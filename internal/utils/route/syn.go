package route

import (
	"context"
	"net/netip"
	"strings"

	"github.com/merzzzl/cisco-socks-server/internal/utils/shell"
)

// WatchSYN calls onSYN with the source IPv4 address and MAC of every TCP SYN
// arriving on iface for port, until ctx is cancelled or tcpdump exits.
//
// It sees the client before the handshake does: while Cisco routes the LAN
// subnet into the tunnel, our SYN-ACK leaves with the default gateway's MAC
// and the handshake never completes until the client is pinned. The SYN's
// Ethernet header is the only place its MAC shows up at that point — the
// client may not ARP for us at all when its cache is warm.
func WatchSYN(ctx context.Context, iface, port string, onSYN func(ip netip.Addr, mac string)) error {
	args := []string{
		"-i", iface,
		"-p", // no promiscuous mode: only frames addressed to us
		"-l", // line-buffered, or lines arrive in 4K chunks
		"-n", // no DNS
		"-t", // no timestamps
		"-e", // the link-level header carries the MAC
		"-s", "128",
		"tcp dst port " + port + " and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn",
	}

	return shell.Stream(ctx, func(line string) {
		if ip, mac, ok := parseSYNLine(line); ok {
			onSYN(ip, mac)
		}
	}, "tcpdump", args...)
}

// parseSYNLine parses a `tcpdump -n -t -e` line:
//
//	76:c9:24:a8:c8:09 > 12:49:61:d3:72:48, ethertype IPv4 (0x0800), length 78: 192.168.0.82.54321 > 192.168.0.105.8080: Flags [S], ...
func parseSYNLine(line string) (netip.Addr, string, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return netip.Addr{}, "", false
	}

	mac, ok := CanonicalMAC(fields[0])
	if !ok {
		return netip.Addr{}, "", false
	}

	_, rest, ok := strings.Cut(line, ", length ")
	if !ok {
		return netip.Addr{}, "", false
	}

	// rest: "78: 192.168.0.82.54321 > ..."
	fields = strings.Fields(rest)
	if len(fields) < 2 {
		return netip.Addr{}, "", false
	}

	i := strings.LastIndexByte(fields[1], '.')
	if i < 0 {
		return netip.Addr{}, "", false
	}

	ip, err := netip.ParseAddr(fields[1][:i])
	if err != nil || !ip.Is4() {
		return netip.Addr{}, "", false
	}

	return ip, mac, true
}
