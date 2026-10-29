// Command veranda announces a node on the local network and finds others.
package main

import (
	"context"
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

	"github.com/haroon0x/veranda/internal/card"
	"github.com/haroon0x/veranda/internal/discovery"
	"github.com/haroon0x/veranda/internal/identity"
	"github.com/haroon0x/veranda/internal/server"
)

const (
	version     = "0.1.0"
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
	case "version", "-v", "--version":
		fmt.Println("veranda", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "veranda: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "veranda:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `veranda — agents on your LAN, meeting without a broker

  veranda serve [--name NAME] [--port PORT] [--bind ADDR] [--no-mdns]
      Announce this machine on the local network and start serving its card.

  veranda peers [--wait DURATION]
      Browse the local network and print every node that answered.

  veranda version
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
	hideToken := fs.Bool("hide-token", false, "do not print the device token at startup")
	if err := fs.Parse(args); err != nil {
		return err
	}

	id, err := identity.LoadOrCreate(*name)
	if err != nil {
		return err
	}
	storeDir, _ := identity.Dir()

	lanIP := discovery.PrimaryIPv4()
	if lanIP == "" {
		fmt.Fprintln(os.Stderr, "veranda: warning: no routable IPv4 address found; peers on the network will not reach this node")
	}

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

	srv := server.New(server.Options{
		Card:  c,
		Token: id.Token,
		Browse: func(wait time.Duration) []discovery.Peer {
			ctx, cancel := context.WithTimeout(context.Background(), wait+time.Second)
			defer cancel()
			peers, err := discovery.Browse(ctx, wait)
			if err != nil {
				return nil
			}
			return peers
		},
	})

	addr := net.JoinHostPort(*bind, fmt.Sprint(*port))
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	fmt.Printf("veranda %s\n", version)
	fmt.Printf("  name    %s\n", id.Name)
	fmt.Printf("  id      %s\n", id.ID)
	fmt.Printf("  card    http://%s:%d%s\n", hostOr(lanIP, "127.0.0.1"), *port, c.Endpoints.Card)
	if adv != nil {
		fmt.Printf("  mdns    %s.%s.local\n", id.Name, discovery.ServiceType)
	} else {
		fmt.Printf("  mdns    disabled\n")
	}
	fmt.Printf("  store   %s\n", storeDir)
	if *hideToken {
		fmt.Printf("  token   hidden (see identity.json)\n")
	} else {
		fmt.Printf("  token   %s\n", id.Token)
	}
	fmt.Printf("\npeers authenticate with:  Authorization: Bearer <token>\n\n")

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

func runPeers(args []string) error {
	fs := flag.NewFlagSet("peers", flag.ExitOnError)
	wait := fs.Duration("wait", 3*time.Second, "how long to listen for answers")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	peers, err := discovery.Browse(ctx, *wait)
	if err != nil {
		return err
	}
	if len(peers) == 0 {
		fmt.Printf("no peers answered in %s\n", wait)
		fmt.Println("check: same network, client isolation off on the router, node running with mDNS enabled")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tID\tVER\tADDRESS\tPROTO")
	for _, p := range peers {
		addr := "-"
		if p.Addr != "" {
			addr = net.JoinHostPort(p.Addr, fmt.Sprint(p.Port))
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", p.Name, shortID(p.ID), dash(p.Version), addr, dash(p.Proto))
	}
	return w.Flush()
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
