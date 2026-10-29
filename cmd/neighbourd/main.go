// Command neighbourd announces a node on the local network, finds others, and
// pairs with them so requests can be authenticated.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/haroon0x/neighbourd/internal/card"
	"github.com/haroon0x/neighbourd/internal/client"
	"github.com/haroon0x/neighbourd/internal/discovery"
	"github.com/haroon0x/neighbourd/internal/identity"
	"github.com/haroon0x/neighbourd/internal/pair"
	"github.com/haroon0x/neighbourd/internal/proto"
	"github.com/haroon0x/neighbourd/internal/server"
	"github.com/haroon0x/neighbourd/internal/trust"
)

const (
	version     = "0.2.0"
	defaultPort = 7717
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "peers":
		err = runPeers(os.Args[2:])
	case "pair":
		err = runPair(os.Args[2:])
	case "status":
		err = runStatus(os.Args[2:])
	case "trust":
		err = runTrust(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("neighbourd", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "neighbourd: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "neighbourd:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `neighbourd — agents on your LAN, meeting without a broker

  neighbourd serve [--pair] [--name NAME] [--port PORT] [--bind ADDR]
      Announce this machine, serve its card, and accept pairing requests
      while a pairing window is open. Send SIGHUP for a new code.

  neighbourd peers [--wait DURATION]
      Browse the local network and print every node that answered.

  neighbourd pair <host:port> --code CODE
      Redeem a pairing code shown by another node.

  neighbourd status <id|name>
      Make a signed request to a paired peer and print its answer.

  neighbourd trust [list|remove <id>]
      Show or revoke paired peers.

  neighbourd version
      Print the version.

Nothing here is reachable from outside your network. Do not port-forward it.
`)
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	name := fs.String("name", "", "label shown to peers (default: stored name, then hostname)")
	port := fs.Int("port", defaultPort, "TCP port to listen on")
	bind := fs.String("bind", "0.0.0.0", "address to bind (IPv4 by default; see DESIGN.md on IPv6)")
	noMDNS := fs.Bool("no-mdns", false, "serve HTTP but do not announce on the network")
	hideToken := fs.Bool("hide-token", false, "do not print the operator token at startup")
	openPairing := fs.Bool("pair", false, "open a pairing window at startup")
	if err := fs.Parse(args); err != nil {
		return err
	}

	id, err := identity.LoadOrCreate(*name)
	if err != nil {
		return err
	}
	storeDir, err := identity.Dir()
	if err != nil {
		return err
	}
	peers, err := trust.Open(storeDir)
	if err != nil {
		return err
	}

	lanIP := discovery.PrimaryIPv4()
	if lanIP == "" {
		fmt.Fprintln(os.Stderr, "neighbourd: warning: no routable IPv4 address found; peers on the network will not reach this node")
	}
	baseURL := fmt.Sprintf("http://%s:%d", hostOr(lanIP, "127.0.0.1"), *port)

	c := card.New(id.ID, id.Name, version, lanIP, *port)

	var adv *discovery.Advertiser
	if !*noMDNS {
		host, _ := os.Hostname()
		adv, err = discovery.Advertise(id.Name, host+".local.", *port, discovery.LocalIPv4s(), discovery.TXT(id.ID, id.Name, version))
		if err != nil {
			return err
		}
		defer adv.Close()
	}

	var window *pair.Window
	if *openPairing {
		window, _, err = pair.NewWindow(pair.DefaultTTL)
		if err != nil {
			return err
		}
	}

	srv := server.New(server.Options{
		Card:  c,
		Self:  id,
		Trust: peers,
		Pair:  window,
		Browse: func(wait time.Duration) []discovery.Peer {
			ctx, cancel := context.WithTimeout(context.Background(), wait+time.Second)
			defer cancel()
			found, err := discovery.Browse(ctx, wait)
			if err != nil {
				return nil
			}
			return found
		},
	})

	addr := net.JoinHostPort(*bind, fmt.Sprint(*port))
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	fmt.Printf("neighbourd %s\n", version)
	fmt.Printf("  name    %s\n", id.Name)
	fmt.Printf("  id      %s\n", id.ID)
	fmt.Printf("  card    %s%s\n", baseURL, proto.PathCard)
	if adv != nil {
		fmt.Printf("  mdns    %s.%s.local\n", id.Name, discovery.ServiceType)
	} else {
		fmt.Printf("  mdns    disabled\n")
	}
	fmt.Printf("  store   %s\n", storeDir)
	fmt.Printf("  paired  %d\n", len(peers.List()))
	if *hideToken {
		fmt.Printf("  token   hidden (see identity.json)\n")
	} else {
		fmt.Printf("  token   %s\n", id.Token)
	}
	printPairing(window, baseURL, "")

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if window == nil {
				fmt.Fprintln(os.Stderr, "\nSIGHUP ignored: this node was started without --pair")
				continue
			}
			code, err := window.Reopen(pair.DefaultTTL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "\ncould not reopen pairing: %v\n", err)
				continue
			}
			printPairing(window, baseURL, code)
		}
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		fmt.Println("\nshutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
	}
	return nil
}

func printPairing(window *pair.Window, baseURL, freshCode string) {
	if window == nil {
		return
	}
	code := freshCode
	if code == "" {
		code = window.Code()
	}
	if code == "" {
		fmt.Printf("\npairing closed (window expired); send SIGHUP for a new code\n\n")
		return
	}
	host := strings.TrimPrefix(strings.TrimPrefix(baseURL, "http://"), "https://")
	fmt.Printf("\npairing open until %s\n  code    %s\n  then    neighbourd pair %s --code %s\n\n",
		window.ExpiresAt().Format("15:04:05"), code, host, code)
}

func runPair(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	code := fs.String("code", "", "pairing code shown on the other machine")
	if err := parseInterspersed(fs, args, "code"); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: neighbourd pair <host:port> --code CODE")
	}
	if *code == "" {
		return errors.New("--code is required; it is printed by `neighbourd serve --pair` on the other machine")
	}

	target, err := normalizeURL(fs.Arg(0))
	if err != nil {
		return err
	}

	id, err := identity.LoadOrCreate("")
	if err != nil {
		return err
	}
	storeDir, err := identity.Dir()
	if err != nil {
		return err
	}
	peers, err := trust.Open(storeDir)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c := client.New(id)
	peer, err := c.Pair(ctx, target, *code)
	if err != nil {
		return err
	}

	// Prove the pairing works before declaring success: a stored token that
	// cannot be used is worse than no pairing at all.
	body, err := c.Get(ctx, peer, peer.BaseURL, proto.PathPing)
	if err != nil {
		return fmt.Errorf("paired, but the first signed request failed: %w", err)
	}
	if err := peers.RememberOutbound(peer); err != nil {
		return err
	}

	fmt.Printf("paired with %s (%s)\n", peer.Name, shortID(peer.ID))
	fmt.Printf("  address %s\n", peer.BaseURL)
	fmt.Printf("  reply   %s\n", strings.TrimSpace(string(body)))
	fmt.Printf("  stored  %s/peers.json\n", storeDir)
	return nil
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: neighbourd status <id|name>")
	}

	id, err := identity.LoadOrCreate("")
	if err != nil {
		return err
	}
	storeDir, err := identity.Dir()
	if err != nil {
		return err
	}
	peers, err := trust.Open(storeDir)
	if err != nil {
		return err
	}
	peer, err := resolvePeer(peers, fs.Arg(0))
	if err != nil {
		return err
	}
	if peer.BaseURL == "" {
		return fmt.Errorf("%s has no recorded address; pair again with a host:port", peer.Name)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	body, err := client.New(id).Get(ctx, peer, peer.BaseURL, proto.PathPing)
	if err != nil {
		return err
	}
	var out any
	if err := json.Unmarshal(body, &out); err != nil {
		fmt.Println(string(body))
		return nil
	}
	pretty, _ := json.MarshalIndent(out, "", "  ")
	fmt.Printf("%s (%s) at %s\n%s\n", peer.Name, shortID(peer.ID), peer.BaseURL, pretty)
	return nil
}

func runTrust(args []string) error {
	storeDir, err := identity.Dir()
	if err != nil {
		return err
	}
	peers, err := trust.Open(storeDir)
	if err != nil {
		return err
	}

	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "list":
		list := peers.List()
		if len(list) == 0 {
			fmt.Println("no paired peers")
			fmt.Println("pair one with: neighbourd serve --pair, then neighbourd pair <host:port> --code CODE")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME	ID	CAN CALL	CALLABLE	PAIRED	LAST SEEN")
		for _, p := range list {
			fmt.Fprintf(w, "%s	%s	%s	%s	%s	%s\n",
				p.Name, shortID(p.ID), yesNo(p.TokenToPeer != ""), yesNo(p.TokenFromPeer != ""),
				p.PairedAt.Local().Format("2006-01-02"), dash(lastSeen(p)))
		}
		return w.Flush()
	case "remove":
		if len(args) < 2 {
			return errors.New("usage: neighbourd trust remove <id|name>")
		}
		peer, err := resolvePeer(peers, args[1])
		if err != nil {
			return err
		}
		if err := peers.Remove(peer.ID); err != nil {
			return err
		}
		fmt.Printf("revoked %s (%s); its token no longer works here\n", peer.Name, shortID(peer.ID))
		return nil
	default:
		return fmt.Errorf("unknown trust subcommand %q (want list or remove)", sub)
	}
}

func runPeers(args []string) error {
	fs := flag.NewFlagSet("peers", flag.ExitOnError)
	wait := fs.Duration("wait", 3*time.Second, "how long to listen for answers")
	if err := parseInterspersed(fs, args, "wait"); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	storeDir, _ := identity.Dir()
	peers, _ := trust.Open(storeDir)
	paired := map[string]bool{}
	if peers != nil {
		for _, p := range peers.List() {
			paired[p.ID] = true
		}
	}

	found, err := discovery.Browse(ctx, *wait)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		fmt.Printf("no peers answered in %s\n", wait)
		fmt.Println("check: same network, client isolation off on the router, node running with mDNS enabled")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tID\tVER\tADDRESS\tPAIRED\tPROTO")
	for _, p := range found {
		addr := "-"
		if p.Addr != "" {
			addr = net.JoinHostPort(p.Addr, fmt.Sprint(p.Port))
		}
		mark := "no"
		if paired[p.ID] {
			mark = "yes"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			p.Name, shortID(p.ID), dash(p.Version), addr, mark, dash(p.Proto))
	}
	return w.Flush()
}

// parseInterspersed parses flags that may appear before or after positional
// arguments. Go's flag package stops at the first non-flag argument, which would
// silently ignore `pair host --code CODE` — the order the usage text prints.
// valueFlags names the flags that consume the following argument.
func parseInterspersed(fs *flag.FlagSet, args []string, valueFlags ...string) error {
	takesValue := make(map[string]bool, len(valueFlags)*2)
	for _, v := range valueFlags {
		takesValue["-"+v] = true
		takesValue["--"+v] = true
	}

	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && takesValue[a] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positional = append(positional, a)
	}
	return fs.Parse(append(flags, positional...))
}

// normalizeURL accepts "host", "host:port" or a full URL and returns a base URL.
func normalizeURL(target string) (string, error) {
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	if strings.Contains(target, " ") {
		return "", fmt.Errorf("%q is not a host or URL", target)
	}
	hostport := strings.TrimPrefix(strings.TrimPrefix(target, "http://"), "https://")
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		if !strings.Contains(err.Error(), "missing port") {
			return "", fmt.Errorf("%q is not a usable address", target)
		}
		target = target + ":" + fmt.Sprint(defaultPort)
	}
	return strings.TrimRight(target, "/"), nil
}

func resolvePeer(peers *trust.Store, ref string) (trust.Peer, error) {
	if p, ok := peers.Get(ref); ok {
		return p, nil
	}
	return peers.ByName(ref)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func lastSeen(p trust.Peer) string {
	if p.LastSeen.IsZero() {
		return ""
	}
	return p.LastSeen.Local().Format("2006-01-02 15:04")
}

func hostOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func shortID(id string) string {
	if id == "" {
		return "-"
	}
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
