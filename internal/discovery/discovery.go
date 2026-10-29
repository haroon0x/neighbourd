// Package discovery announces a node on the local network and finds others.
//
// This is mDNS over the multicast group, which means it is bounded by the
// broadcast domain: same subnet, same VLAN, no routing. That boundary is the
// point. Anything that crosses it turns this project into a different thing
// with a different threat model.
package discovery

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/mdns"
)

// ServiceType is the mDNS service a veranda node registers.
const ServiceType = "_veranda._tcp"

// protoID mirrors card.Protocol. Duplicated rather than imported so discovery
// stays independent of the card package's evolution.
const protoID = "veranda/0.1"

// Peer is one discovered node, as far as discovery can honestly describe it.
// Nothing here is authenticated: name and id are claims read off the wire.
type Peer struct {
	Name    string `json:"name"`
	ID      string `json:"id"`
	Version string `json:"version"`
	Proto   string `json:"proto"`
	Host    string `json:"host"` // mDNS target, e.g. g.local.
	Addr    string `json:"addr"` // resolved IPv4
	Port    int    `json:"port"`
}

// Advertiser is a running announcement. Close it to withdraw the service.
type Advertiser struct {
	srv *mdns.Server
	svc *mdns.MDNSService
}

// TXT builds the TXT record fields. Every field is public information: it is
// readable by every device on the network.
func TXT(id, name, version string) []string {
	return []string{
		"v=" + version,
		"id=" + id,
		"name=" + name,
		"proto=" + protoID,
	}
}

// Advertise registers instance under _veranda._tcp and starts answering
// queries. hostName may be empty to let the OS hostname be used; it should be
// the mDNS name, so callers normally want "<hostname>.local.".
//
// ips is the set of addresses to announce. Pass the output of LocalIPv4s, not
// nil: nil makes the library announce every address on the host, including
// container bridges that a peer on the Wi-Fi cannot reach.
//
// Note that a host running avahi or Bonjour can carry several responders on
// port 5353 at once; that is expected and not an error.
func Advertise(instance, hostName string, port int, ips []net.IP, txt []string) (*Advertiser, error) {
	svc, err := mdns.NewMDNSService(instance, ServiceType, "local.", hostName, port, ips, txt)
	if err != nil {
		return nil, fmt.Errorf("build mdns service: %w", err)
	}
	srv, err := mdns.NewServer(&mdns.Config{Zone: svc, Logger: libLogger(os.Stderr)})
	if err != nil {
		return nil, fmt.Errorf("start mdns responder: %w", err)
	}
	return &Advertiser{srv: srv, svc: svc}, nil
}

// Close withdraws the announcement. There is no goodbye packet, so peers keep
// seeing the node in caches for a short while; absence is normal.
func (a *Advertiser) Close() error {
	if a == nil || a.srv == nil {
		return nil
	}
	return a.srv.Shutdown()
}

// Browse waits up to wait and returns everything announced on the network,
// deduplicated by id.
//
// IPv6 is not queried in v0.1: the node binds IPv4 by default (see DESIGN.md
// section 5 on globally routable IPv6 addresses), and returning addresses that
// cannot be dialled would be worse than not returning them.
func Browse(ctx context.Context, wait time.Duration) ([]Peer, error) {
	// QueryParam.Entries is send-only, and the library drops sends when it is
	// full rather than blocking. Keep a buffered local channel so we can drain
	// it concurrently and never lose an answer to a full buffer.
	entries := make(chan *mdns.ServiceEntry, 64)

	params := mdns.DefaultParams(ServiceType)
	params.Entries = entries
	params.Timeout = wait
	params.DisableIPv6 = true
	params.Logger = libLogger(os.Stderr)

	qctx, cancel := context.WithTimeout(ctx, wait+time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- mdns.QueryContext(qctx, params) }()

	var (
		seen = make(map[string]Peer)
		stop = time.After(wait + 250*time.Millisecond)
	)
collect:
	for {
		select {
		case e := <-entries:
			p := peerFromEntry(e)
			// Key on id when present so one node answering over two
			// interfaces does not appear twice. Fall back to name.
			key := p.ID
			if key == "" {
				key = p.Name
			}
			if key != "" {
				seen[key] = p
			}
		case <-stop:
			break collect
		}
	}

	out := make([]Peer, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	// The query goroutine outlives the collection loop by design; a non-nil
	// error there means it failed before producing anything worth keeping.
	select {
	case err := <-errCh:
		if err != nil && len(out) == 0 {
			return nil, fmt.Errorf("mdns query: %w", err)
		}
	default:
	}
	return out, nil
}

func peerFromEntry(e *mdns.ServiceEntry) Peer {
	p := Peer{
		Name: instanceName(e.Name),
		Host: e.Host,
		Port: e.Port,
	}
	if e.AddrV4 != nil {
		p.Addr = e.AddrV4.String()
	}
	for _, f := range e.InfoFields {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "id":
			p.ID = v
		case "name":
			if v != "" {
				p.Name = v
			}
		case "v":
			p.Version = v
		case "proto":
			p.Proto = v
		}
	}
	return p
}

// instanceName trims "laptop._veranda._tcp.local." down to "laptop".
func instanceName(s string) string {
	if i := strings.IndexByte(s, '.'); i > 0 {
		return s[:i]
	}
	return s
}
