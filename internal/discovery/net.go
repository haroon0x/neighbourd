package discovery

import (
	"bytes"
	"io"
	"log"
	"net"
	"strings"
)

// virtualPrefixes are interface names that exist on hosts running containers
// and VPNs. They are up, they have IPv4 addresses, and they are useless to a
// peer on the Wi-Fi: announcing a Docker bridge address means peers dial a
// bridge that only exists on this machine.
var virtualPrefixes = []string{
	"docker", "br-", "veth", "virbr", "vmnet", "tun", "tap",
	"tailscale", "zt", "wg", "utun", "lo",
}

// LocalIPv4s returns the addresses worth announcing: routable IPv4 addresses on
// physical interfaces, best first. Loopback, link-local and known virtual
// prefixes are excluded.
func LocalIPv4s() []net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var out []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isVirtual(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil || ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, ipnet.IP.To4())
		}
	}
	return out
}

// PrimaryIPv4 is the first announced address, for printing URLs. It is display
// only: DHCP moves it, so never persist the result.
func PrimaryIPv4() string {
	ips := LocalIPv4s()
	if len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

func isVirtual(name string) bool {
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// filterWriter drops log lines a dependency emits at INFO level. The mDNS
// library logs a failed IPv6 bind on every query, which is expected here
// because v0.1 is IPv4-only, and drowning the real errors in it helps nobody.
type filterWriter struct{ w io.Writer }

func (f filterWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("[INFO]")) {
		return len(p), nil
	}
	return f.w.Write(p)
}

func libLogger(w io.Writer) *log.Logger {
	return log.New(filterWriter{w: w}, "", log.LstdFlags)
}
