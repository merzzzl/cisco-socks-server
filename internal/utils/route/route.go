package route

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/merzzzl/cisco-socks-server/internal/utils/shell"
)

var ErrNoLANInterface = errors.New("no non-tunnel LAN interface found")

func DetectLAN(ctx context.Context) (string, string, error) {
	out, err := shell.Run(ctx, "netstat", "-rn", "-f", "inet")
	if err == nil {
		if name := parseDefaultNonTunnel(out); name != "" {
			if cidr, cerr := connectedCIDR(name); cerr == nil {
				return cidr, name, nil
			}
		}
	}

	return scanRFC1918()
}

func parseDefaultNonTunnel(netstatOutput string) string {
	for line := range strings.SplitSeq(netstatOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		if fields[0] != "default" {
			continue
		}

		netif := fields[len(fields)-1]
		if strings.HasPrefix(netif, "utun") || strings.HasPrefix(netif, "lo") || netif == "" {
			continue
		}

		return netif
	}

	return ""
}

func connectedCIDR(iface string) (string, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return "", fmt.Errorf("interface %s: %w", iface, err)
	}

	addrs, err := ifi.Addrs()
	if err != nil {
		return "", fmt.Errorf("addrs %s: %w", iface, err)
	}

	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}

		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}

		if ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
			continue
		}

		ones, _ := ipnet.Mask.Size()
		network := ip4.Mask(ipnet.Mask)

		return fmt.Sprintf("%s/%d", network, ones), nil
	}

	return "", fmt.Errorf("no IPv4 address on %s", iface)
}

func scanRFC1918() (string, string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", fmt.Errorf("list interfaces: %w", err)
	}

	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}

		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagPointToPoint != 0 {
			continue
		}

		if strings.HasPrefix(ifi.Name, "utun") {
			continue
		}

		addrs, aerr := ifi.Addrs()
		if aerr != nil {
			continue
		}

		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}

			// IsPrivate on an IPv4 address is exactly the RFC 1918 ranges
			ip4 := ipnet.IP.To4()
			if ip4 == nil || !ip4.IsPrivate() {
				continue
			}

			ones, _ := ipnet.Mask.Size()
			network := ip4.Mask(ipnet.Mask)

			return fmt.Sprintf("%s/%d", network, ones), ifi.Name, nil
		}
	}

	return "", "", ErrNoLANInterface
}

// ArpEntry is a resolved `arp -n <ip>` entry.
type ArpEntry struct {
	MAC   string // normalized, see normalizeMAC
	Iface string
}

// LookupARP reads the kernel's ARP entry for ip. It is read-only: callers
// decide via DecidePin whether a mutating Pin is needed at all.
func LookupARP(ctx context.Context, ip string) (ArpEntry, bool) {
	out, err := shell.Run(ctx, "arp", "-n", ip)
	if err != nil {
		return ArpEntry{}, false
	}

	return parseArpEntry(out)
}

// parseArpEntry parses `arp -n` output ("? (ip) at <mac> on <iface> ...").
// "-- no entry" and "(incomplete)" resolve to false.
func parseArpEntry(out string) (ArpEntry, bool) {
	fields := strings.Fields(out)

	var e ArpEntry

	for i := range len(fields) - 1 {
		switch fields[i] {
		case "at":
			e.MAC = fields[i+1]
		case "on":
			e.Iface = fields[i+1]
		}
	}

	if _, err := net.ParseMAC(padMAC(e.MAC)); err != nil || e.Iface == "" {
		return ArpEntry{}, false
	}

	e.MAC = normalizeMAC(e.MAC)

	return e, true
}

// PinAction is what the pinner must do about one client, see DecidePin.
type PinAction int

const (
	// PinNone: the entry is correct, or there is no MAC to pin yet.
	PinNone PinAction = iota
	// PinAdopt: the client resolves on the LAN interface with another MAC
	// (private Wi-Fi addresses rotate); the kernel entry is the truth, so
	// the caller takes over that MAC and leaves ARP alone.
	PinAdopt
	// PinRepin: the entry is gone or points off the LAN interface (utun*);
	// the caller re-asserts it with Pin.
	PinRepin
)

// DecidePin compares the kernel's ARP entry for a client with the MAC the
// caller knows (empty when not known yet) and the LAN interface.
func DecidePin(entry ArpEntry, found bool, wantMAC, iface string) PinAction {
	switch {
	case found && entry.Iface == iface && entry.MAC == normalizeMAC(wantMAC):
		return PinNone
	case found && entry.Iface == iface:
		return PinAdopt
	case wantMAC == "":
		// nothing to pin with; the client shows up in ARP on its own as
		// soon as it talks to us
		return PinNone
	default:
		return PinRepin
	}
}

// Pin keeps a LAN client reachable while Cisco owns the connected subnet:
// without a per-host pin the kernel has no on-link route to the client, so
// IP_BOUND_IF frames leave with the default gateway's MAC and the client
// never sees them. Host-level route+ARP pins are the only mac-side change
// Cisco tolerates (scoped routes, /24 re-adds, pf route-to all get deleted
// within seconds).
//
// Only call it when DecidePin says PinRepin: `arp -S` replaces the entry
// (delete + re-add), which drops in-flight frames and causes visible stalls
// for active connections. It must be `arp -S` (capital) — lowercase `arp -s`
// fails with "can only proxy" while the subnet is routed into the tunnel.
func Pin(ctx context.Context, ip, mac, iface string) error {
	// route change fails with "not in table" until the ARP entry exists
	// (arp -S creates the host entry itself) — safe to ignore
	_, _ = shell.Run(ctx, "route", "change", ip, "-interface", iface)

	if out, err := shell.Run(ctx, "arp", "-S", ip, mac, "temp"); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(out))
	}

	return nil
}

// normalizeMAC strips leading zeros from each octet — macOS arp prints
// "72:ce:39:12:45:f" for "72:ce:39:12:45:0f".
func normalizeMAC(mac string) string {
	parts := strings.Split(strings.ToLower(mac), ":")
	for i, p := range parts {
		parts[i] = strings.TrimLeft(p, "0")
	}

	return strings.Join(parts, ":")
}

// padMAC restores the leading zeros macOS arp drops, so net.ParseMAC accepts
// "72:ce:39:12:45:f".
func padMAC(mac string) string {
	parts := strings.Split(mac, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}

	return strings.Join(parts, ":")
}
