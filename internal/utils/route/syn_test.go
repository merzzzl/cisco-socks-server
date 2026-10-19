package route

import (
	"net/netip"
	"testing"
)

func TestParseSYNLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		line string
		ip   string
		mac  string
		ok   bool
	}{
		{
			// real macOS tcpdump output
			"76:c9:24:a8:c8:09 > 12:49:61:d3:72:48, ethertype IPv4 (0x0800), length 78: 192.168.0.82.50174 > 192.168.0.105.8080: Flags [S], seq 843104139, win 65535, options [mss 1460,nop,wscale 6,nop,nop,TS val 248601949 ecr 0,sackOK,eol], length 0",
			"192.168.0.82", "76:c9:24:a8:c8:09", true,
		},
		{"tcpdump: verbose output suppressed, use -v[v]... for full protocol decode", "", "", false},
		{"listening on en0, link-type EN10MB (Ethernet), snapshot length 128 bytes", "", "", false},
		{"76:c9:24:a8:c8:09 > 12:49:61:d3:72:48, ethertype IPv6 (0x86dd), length 98: fe80::1.54321 > fe80::2.8080: Flags [S]", "", "", false},
		{"", "", "", false},
	}

	for _, tt := range tests {
		ip, mac, ok := parseSYNLine(tt.line)
		if ok != tt.ok || (ok && (ip != netip.MustParseAddr(tt.ip) || mac != tt.mac)) {
			t.Errorf("parseSYNLine(%q) = %v, %q, %v; want %s, %q, %v", tt.line, ip, mac, ok, tt.ip, tt.mac, tt.ok)
		}
	}
}
