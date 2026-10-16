package route

import (
	"net"
	"net/netip"
	"testing"
)

func TestParseDefaultNonTunnel(t *testing.T) {
	t.Parallel()

	const netstat = `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            link#22            UCSIg               utun4
default            192.168.0.1        UGScg                 en0
127                127.0.0.1          UCS                   lo0
`

	if got := parseDefaultNonTunnel(netstat); got != "en0" {
		t.Errorf("parseDefaultNonTunnel() = %q, want en0", got)
	}

	if got := parseDefaultNonTunnel("default link#22 UCSIg utun4\n"); got != "" {
		t.Errorf("tunnel-only default must yield empty, got %q", got)
	}
}

func TestParseArpEntry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		want  ArpEntry
		name  string
		out   string
		found bool
	}{
		{
			name:  "regular",
			out:   "? (192.168.0.42) at 12:49:61:d3:72:48 on en0 ifscope [ethernet]\n",
			want:  ArpEntry{MAC: "12:49:61:d3:72:48", Iface: "en0"},
			found: true,
		},
		{
			name:  "permanent",
			out:   "? (192.168.0.42) at 72:ce:39:12:45:f on en0 permanent [ethernet]\n",
			want:  ArpEntry{MAC: "72:ce:39:12:45:0f", Iface: "en0"},
			found: true,
		},
		{
			name:  "leading zeros restored and case folded",
			out:   "? (192.168.0.42) at 2:A:b:C:0:1 on en0 [ethernet]\n",
			want:  ArpEntry{MAC: "02:0a:0b:0c:00:01", Iface: "en0"},
			found: true,
		},
		{
			name:  "tunnel interface",
			out:   "? (192.168.0.42) at 12:49:61:d3:72:48 on utun4 [ethernet]\n",
			want:  ArpEntry{MAC: "12:49:61:d3:72:48", Iface: "utun4"},
			found: true,
		},
		{name: "no entry", out: "192.168.0.42 (192.168.0.42) -- no entry\n"},
		{name: "incomplete", out: "? (192.168.0.42) at (incomplete) on en0 [ethernet]\n"},
		{name: "empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, found := parseArpEntry(tt.out)
			if got != tt.want || found != tt.found {
				t.Errorf("parseArpEntry() = %+v, %v; want %+v, %v", got, found, tt.want, tt.found)
			}
		})
	}
}

func TestDecidePin(t *testing.T) {
	t.Parallel()

	onLAN := ArpEntry{MAC: "12:49:61:d3:72:48", Iface: "en0"}
	onTunnel := ArpEntry{MAC: onLAN.MAC, Iface: "utun4"}

	tests := []struct {
		entry   ArpEntry
		name    string
		wantMAC string
		want    PinAction
		found   bool
	}{
		{onLAN, "matches", "12:49:61:D3:72:48", PinNone, true},
		{ArpEntry{MAC: "72:ce:39:12:45:0f", Iface: "en0"}, "matches without leading zeros", "72:ce:39:12:45:f", PinNone, true},
		{onLAN, "rotated mac on lan iface", "f4:d4:88:85:75:6f", PinAdopt, true},
		{onLAN, "unknown mac learned on lan iface", "", PinAdopt, true},
		{ArpEntry{}, "no entry", "12:49:61:d3:72:48", PinRepin, false},
		{onTunnel, "entry on tunnel", "12:49:61:d3:72:48", PinRepin, true},
		{ArpEntry{}, "no entry and no mac", "", PinNone, false},
		{onTunnel, "tunnel entry and no mac", "", PinNone, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := DecidePin(tt.entry, tt.found, tt.wantMAC, "en0"); got != tt.want {
				t.Errorf("DecidePin() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCanonicalMAC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in, want string
		ok       bool
	}{
		{"72:CE:39:12:45:F", "72:ce:39:12:45:0f", true},
		{"72-ce-39-12-45-0f", "72:ce:39:12:45:0f", true},
		{"0:0:0:0:0:1", "00:00:00:00:00:01", true},
		{"(incomplete)", "", false},
		{"", "", false},
	}

	for _, tt := range tests {
		if got, ok := CanonicalMAC(tt.in); got != tt.want || ok != tt.ok {
			t.Errorf("CanonicalMAC(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestIPv4Prefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ipnet *net.IPNet
		want  string
		ok    bool
	}{
		{&net.IPNet{IP: net.IPv4(192, 168, 0, 42).To4(), Mask: net.CIDRMask(24, 32)}, "192.168.0.0/24", true},
		{&net.IPNet{IP: net.IPv4(10, 1, 2, 3), Mask: net.CIDRMask(112, 128)}, "10.1.0.0/16", true},
		{&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)}, "", false},
	}

	for _, tt := range tests {
		got, ok := ipv4Prefix(tt.ipnet)
		if ok != tt.ok || (ok && got.String() != tt.want) {
			t.Errorf("ipv4Prefix(%v) = %v, %v; want %s, %v", tt.ipnet, got, ok, tt.want, tt.ok)
		}
	}
}

func TestPickCandidate(t *testing.T) {
	t.Parallel()

	cands := []lanCandidate{
		{subnet: netip.MustParsePrefix("192.168.64.0/24"), iface: "bridge100"},
		{subnet: netip.MustParsePrefix("192.168.0.0/24"), iface: "en0"},
	}

	if c, _ := pickCandidate(cands, "en0"); c.iface != "en0" {
		t.Errorf("preferred interface must win, got %s", c.iface)
	}

	if c, _ := pickCandidate(cands, ""); c.iface != "bridge100" {
		t.Errorf("without preference the first candidate wins, got %s", c.iface)
	}

	if c, _ := pickCandidate(cands, "en7"); c.iface != "bridge100" {
		t.Errorf("a vanished preferred interface falls back to the first, got %s", c.iface)
	}

	if _, ok := pickCandidate(nil, "en0"); ok {
		t.Error("no candidates must yield false")
	}
}
