// Command neighbourd announces a node on the local network, finds others, and
// pairs with them so requests can be authenticated.
package main

import (
	"bufio"
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
	"github.com/haroon0x/neighbourd/internal/mcp"
	"github.com/haroon0x/neighbourd/internal/pair"
	"github.com/haroon0x/neighbourd/internal/proto"
	"github.com/haroon0x/neighbourd/internal/server"
	"github.com/haroon0x/neighbourd/internal/trust"
)

const (
	version     = "0.3.0"
	defaultPort = 7717
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "up":
		err = runServe(append([]string{"--pair"}, os.Args[2:]...))
	case "serve":
		err = runServe(os.Args[2:])
	case "peers":
		err = runPeers(os.Args[2:])
	case "pair":
		err = runPair(os.Args[2:])
	case "mcp":
		err = runMCP(os.Args[2:])
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

  neighbourd up [--name NAME] [--port PORT]
      Go online and open a pairing window. The one command to run on a machine
      that should be reachable. Send SIGHUP for a new code.

  neighbourd mcp [--print-config] [--allow PATH ...]
      MCP server on stdio, so an agent can call paired peers as tools.
      --print-config writes the client config block pointing at this binary.

  neighbourd pair [<host:port>] [--code CODE]
      With no arguments, list the machines on the network and pair interactively.

  neighbourd peers [--wait DURATION]
      Browse the network and print every node that answered.

  neighbourd status <id|name>
      Make a signed request to a paired peer and print its answer.

  neighbourd trust [list|remove <id>]
      Show or revoke paired peers.

  neighbourd serve [--pair] [--name NAME] [--port PORT] [--bind ADDR] [--no-mdns]
      Same as up, with every option explicit.

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
	codeFlag := fs.String("code", "", "pairing code shown on the other machine")
	if err := parseInterspersed(fs, args, "code"); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return errors.New("usage: neighbourd pair [<host:port>] [--code CODE]")
	}

	me, err := identity.LoadOrCreate("")
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

	// No target given: find the machines and ask. Remembering an address off the
	// other screen is the step where setup stops being convenient.
	code := *codeFlag
	target := fs.Arg(0)
	if target == "" {
		target, code, err = choosePeer(peers, me)
		if err != nil {
			return err
		}
	}
	if code == "" {
		return errors.New("a pairing code is required; it is printed by `neighbourd up` on the other machine")
	}

	baseURL, err := normalizeURL(target)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c := client.New(me)
	peer, err := c.Pair(ctx, baseURL, code)
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
	if peer.ID != "" {
		fmt.Printf("  now     neighbourd status %s\n", shortID(peer.ID))
	}
	return nil
}

// choosePeer lists the nodes on the network that are worth pairing with, then
// reads a choice and the code from stdin. When stdin is a pipe it behaves the
// same way, which is what the tests use.
func choosePeer(peers *trust.Store, me *identity.Identity) (target, code string, err error) {
	fmt.Print("looking for neighbours … ")
	found, browseErr := discovery.Browse(context.Background(), 3*time.Second)
	if browseErr != nil {
		fmt.Printf("failed: %v\n", browseErr)
	} else {
		fmt.Printf("%d found\n\n", len(found))
	}

	candidates := make([]discovery.Peer, 0, len(found))
	for _, p := range found {
		if p.ID == me.ID {
			continue // that is us
		}
		if rec, ok := peers.Get(p.ID); ok && rec.TokenToPeer != "" {
			continue // already paired; nothing to do
		}
		candidates = append(candidates, p)
	}

	if len(candidates) == 0 {
		return "", "", errors.New("nothing to pair with on this network.\n" +
			"check: the other machine is running `neighbourd up`, both are on the same Wi-Fi, and the router is not isolating clients.\n" +
			"or pair by address: neighbourd pair <host:port> --code CODE")
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for i, p := range candidates {
		addr := net.JoinHostPort(p.Addr, fmt.Sprint(p.Port))
		fmt.Fprintf(w, "  %d) %s	%s	%s\n", i+1, p.Name, addr, shortID(p.ID))
	}
	w.Flush()
	fmt.Print("\nwhich one? [1]: ")

	in := bufio.NewReader(os.Stdin)
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return "", "", fmt.Errorf("read choice: %w", err)
	}
	line = strings.TrimSpace(line)

	chosen := candidates[0]
	switch {
	case line == "":
		// keep the default
	case line == strings.TrimSpace(line) && isIndex(line, len(candidates)):
		chosen = candidates[atoi(line)-1]
	default:
		// Treat anything else as an address, so the prompt doubles as a
		// shortcut for a node that mDNS did not surface.
		fmt.Print("pairing code on " + line + ": ")
		code, err = readLine(in)
		return line, code, err
	}

	fmt.Printf("pairing code on %s: ", chosen.Name)
	code, err = readLine(in)
	return net.JoinHostPort(chosen.Addr, fmt.Sprint(chosen.Port)), code, err
}

func readLine(in *bufio.Reader) (string, error) {
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("read input: %w", err)
	}
	return strings.TrimSpace(line), nil
}

func isIndex(s string, hi int) bool {
	n := atoi(s)
	return n >= 1 && n <= hi
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func runMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	printConfig := fs.Bool("print-config", false, "print an MCP client config block and exit")
	var extra multiFlag
	fs.Var(&extra, "allow", "additional path call_peer may request (repeatable)")
	if err := parseInterspersed(fs, args, "allow"); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errors.New("usage: neighbourd mcp [--print-config] [--allow PATH]")
	}

	me, err := identity.LoadOrCreate("")
	if err != nil {
		return err
	}

	if *printConfig {
		return printMCPConfig()
	}

	storeDir, err := identity.Dir()
	if err != nil {
		return err
	}
	peers, err := trust.Open(storeDir)
	if err != nil {
		return err
	}

	srv := mcp.New(mcp.Options{
		ID:      me,
		Trust:   peers,
		Version: version,
		Browse: func(wait time.Duration) []discovery.Peer {
			ctx, cancel := context.WithTimeout(context.Background(), wait+time.Second)
			defer cancel()
			found, err := discovery.Browse(ctx, wait)
			if err != nil {
				return nil
			}
			return found
		},
		Allow: append(append([]string{}, mcp.DefaultAllowlist...), extra...),
		In:    os.Stdin,
		Out:   os.Stdout,
		Log:   os.Stderr,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(peers.List()) == 0 {
		fmt.Fprintln(os.Stderr, "neighbourd: no paired peers yet; the agent can still list the network. Pair with: neighbourd pair")
	}
	return srv.Run(ctx)
}

// printMCPConfig emits the block a client needs, pointing at this exact binary.
// Guessing the path is the difference between "one line to paste" and "read the
// docs to find out what to write".
func printMCPConfig() error {
	exe, err := os.Executable()
	if err != nil {
		exe = "neighbourd"
	}
	storeDir, _ := identity.Dir()
	paired := 0
	if peers, err := trust.Open(storeDir); err == nil {
		for _, p := range peers.List() {
			if p.TokenToPeer != "" {
				paired++
			}
		}
	}

	block := map[string]any{
		"mcpServers": map[string]any{
			"neighbourd": map[string]any{
				"command": exe,
				"args":    []string{"mcp"},
			},
		},
	}
	raw, _ := json.MarshalIndent(block, "", "  ")
	fmt.Println(string(raw))
	fmt.Fprintln(os.Stderr, "\nPaste this into your MCP client config (Hermes: mcp_servers in config.yaml).")
	if paired == 0 {
		fmt.Fprintln(os.Stderr, "No peers paired yet. On the other machine run `neighbourd up`, then run `neighbourd pair` here.")
	} else {
		fmt.Fprintf(os.Stderr, "%d peer(s) ready to call.\n", paired)
	}
	return nil
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
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
