package discovery

import (
	"net"
	"testing"

	"github.com/hashicorp/mdns"
)

func TestInstanceNameTrimsServiceSuffix(t *testing.T) {
	cases := map[string]string{
		"laptop._veranda._tcp.local.": "laptop",
		"laptop":                      "laptop",
		"":                            "",
	}
	for in, want := range cases {
		if got := instanceName(in); got != want {
			t.Errorf("instanceName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPeerFromEntryReadsTXT(t *testing.T) {
	e := &mdns.ServiceEntry{
		Name:       "laptop._veranda._tcp.local.",
		Host:       "g.local.",
		Port:       7717,
		AddrV4:     net.IPv4(192, 168, 29, 93),
		InfoFields: []string{"v=0.1.0", "id=abc123", "name=laptop", "proto=veranda/0.1"},
	}

	p := peerFromEntry(e)
	if p.Name != "laptop" {
		t.Errorf("Name = %q, want laptop", p.Name)
	}
	if p.ID != "abc123" {
		t.Errorf("ID = %q, want abc123", p.ID)
	}
	if p.Version != "0.1.0" {
		t.Errorf("Version = %q, want 0.1.0", p.Version)
	}
	if p.Addr != "192.168.29.93" {
		t.Errorf("Addr = %q, want 192.168.29.93", p.Addr)
	}
	if p.Port != 7717 {
		t.Errorf("Port = %d, want 7717", p.Port)
	}
}

func TestPeerFromEntryToleratesMissingTXT(t *testing.T) {
	p := peerFromEntry(&mdns.ServiceEntry{Name: "bare._veranda._tcp.local."})
	if p.Name != "bare" || p.ID != "" {
		t.Errorf("unexpected peer: %+v", p)
	}
}

func TestTXTFieldsAreNamespaced(t *testing.T) {
	fields := TXT("id123", "laptop", "0.1.0")
	want := map[string]string{"v": "0.1.0", "id": "id123", "name": "laptop", "proto": "veranda/0.1"}
	for _, f := range fields {
		var k, v string
		for i := range f {
			if f[i] == '=' {
				k, v = f[:i], f[i+1:]
				break
			}
		}
		if want[k] != v {
			t.Errorf("TXT %q: got %q for %q, want %q", f, v, k, want[k])
		}
	}
}

func TestIsVirtual(t *testing.T) {
	virtual := []string{"docker0", "br-a1303c95ff5c", "veth1a2b", "tailscale0", "wg0", "tun0", "virbr0"}
	for _, n := range virtual {
		if !isVirtual(n) {
			t.Errorf("isVirtual(%q) = false, want true", n)
		}
	}
	physical := []string{"eth0", "wlan0", "wlx9094e4022fc5", "enp3s0"}
	for _, n := range physical {
		if isVirtual(n) {
			t.Errorf("isVirtual(%q) = true, want false", n)
		}
	}
}

func TestLocalIPv4sExcludesLoopback(t *testing.T) {
	for _, ip := range LocalIPv4s() {
		if ip.IsLoopback() {
			t.Errorf("LocalIPv4s returned loopback %s", ip)
		}
		if ip.IsLinkLocalUnicast() {
			t.Errorf("LocalIPv4s returned link-local %s", ip)
		}
	}
}
