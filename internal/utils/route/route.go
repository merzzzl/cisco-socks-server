package route

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/merzzzl/cisco-socks-server/internal/utils/shell"
)

var (
	ErrNoLANInterface = errors.New("no non-tunnel LAN interface found")
	errNoIPv4         = errors.New("no IPv4 address")
)

// DetectLAN finds the physical LAN interface and its subnet: the interface of
// the non-tunnel default route, else an up interface with an RFC 1918
// address. In that fallback prefer (the interface in use, may be empty) wins
// while it still qualifies, so a transient loss of the default route does not
// flip the LAN to a bridge or a USB NIC.
func DetectLAN(ctx context.Context, prefer string) (netip.Prefix, string, error) {
	out, err := shell.Run(ctx, "netstat", "-rn", "-f", "inet")
	if err == nil {
		if name := parseDefaultNonTunnel(out); name != "" {
			if subnet, cerr := connectedPrefix(name); cerr == nil {
				return subnet, name, nil
			}
		}
	}

	cands, err := rfc1918Candidates()
	if err != nil {
		return netip.Prefix{}, "", err
	}

	c, ok := pickCandidate(cands, prefer)
	if !ok {
		return netip.Prefix{}, "", ErrNoLANInterface
	}

	return c.subnet, c.iface, nil
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

func connectedPrefix(iface string) (netip.Prefix, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("interface %s: %w", iface, err)
	}

	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("addrs %s: %w", iface, err)
	}

	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}

		subnet, ok := ipv4Prefix(ipnet)
		if !ok || subnet.Addr().IsLoopback() || subnet.Addr().IsLinkLocalUnicast() {
			continue
		}

		return subnet, nil
	}

	return netip.Prefix{}, fmt.Errorf("%w on %s", errNoIPv4, iface)
}

type lanCandidate struct {
	subnet netip.Prefix
	iface  string
}

func rfc1918Candidates() ([]lanCandidate, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	var cands []lanCandidate

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
			subnet, ok := ipv4Prefix(ipnet)
			if !ok || !subnet.Addr().IsPrivate() {
				continue
			}

			cands = append(cands, lanCandidate{subnet: subnet, iface: ifi.Name})

			break
		}
	}

	return cands, nil
}

// pickCandidate returns prefer's candidate when present, else the first one.
func pickCandidate(cands []lanCandidate, prefer string) (lanCandidate, bool) {
	if len(cands) == 0 {
		return lanCandidate{}, false
	}

	for _, c := range cands {
		if prefer != "" && c.iface == prefer {
			return c, true
		}
	}

	return cands[0], true
}

// ipv4Prefix converts an interface address to its masked IPv4 subnet.
func ipv4Prefix(ipnet *net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(ipnet.IP.To4())
	if !ok {
		return netip.Prefix{}, false
	}

	ones, bits := ipnet.Mask.Size()
	if bits == net.IPv6len*8 {
		ones -= 96 // IPv4 address with a 16-byte mask
	}

	if ones < 0 || ones > 32 {
		return netip.Prefix{}, false
	}

	return netip.PrefixFrom(addr, ones).Masked(), true
}

// ArpEntry is a resolved `arp -n <ip>` entry.
type ArpEntry struct {
	MAC   string // canonical, see CanonicalMAC
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

	mac, ok := CanonicalMAC(e.MAC)
	if !ok || e.Iface == "" {
		return ArpEntry{}, false
	}

	e.MAC = mac

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
	case found && entry.Iface == iface && sameMAC(entry.MAC, wantMAC):
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

// CanonicalMAC returns mac as lowercase colon-separated two-digit octets.
// macOS arp drops leading zeros ("72:ce:39:12:45:f" for "72:ce:39:12:45:0f"),
// so those are restored first.
func CanonicalMAC(mac string) (string, bool) {
	parts := strings.Split(mac, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}

	hw, err := net.ParseMAC(strings.Join(parts, ":"))
	if err != nil {
		return "", false
	}

	return hw.String(), true
}

func sameMAC(a, b string) bool {
	ca, okA := CanonicalMAC(a)
	cb, okB := CanonicalMAC(b)

	return okA && okB && ca == cb
}
