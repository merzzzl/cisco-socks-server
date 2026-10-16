package service

import (
	"context"
	"maps"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/merzzzl/cisco-socks-server/internal/utils/route"
)

type fakeARP struct {
	entries map[string]route.ArpEntry
	pinned  []string // "ip mac iface"
}

func (f *fakeARP) ops() pinOps {
	return pinOps{
		lookup: func(_ context.Context, ip string) (route.ArpEntry, bool) {
			e, ok := f.entries[ip]

			return e, ok
		},
		pin: func(_ context.Context, ip, mac, iface string) error {
			f.pinned = append(f.pinned, ip+" "+mac+" "+iface)

			return nil
		},
	}
}

func TestPinClients(t *testing.T) {
	t.Parallel()

	const (
		rotatedMAC = "82:b4:3b:8e:d2:f3"
		otherNetIP = "10.0.0.5"
	)

	s := New("u", "p", "vpn", nil, []LANClient{
		{IP: staticIP, MAC: staticMAC},
		{IP: otherNetIP, MAC: staticMAC},
	})
	s.clients.seen(discoveredIP, learnedMAC, time.Now())
	s.clients.seen("192.168.0.7", "", time.Now())
	s.clients.seen("192.168.0.8", "", time.Now())

	arp := &fakeARP{entries: map[string]route.ArpEntry{
		// rotated private MAC learned by the kernel: adopt, never overwrite
		staticIP: {MAC: rotatedMAC, Iface: "en0"},
		// discoveredIP has no entry (Cisco deleted it): re-pin known MAC
		// unknown MAC learned on the LAN interface: adopt
		"192.168.0.7": {MAC: learnedMAC, Iface: "en0"},
		// unknown MAC, entry on the tunnel: nothing to pin with
		"192.168.0.8": {MAC: learnedMAC, Iface: "utun4"},
	}}

	state := State{LANInterface: "en0", LANSubnet: netip.MustParsePrefix("192.168.0.0/24")}
	s.pinClients(t.Context(), arp.ops(), state)

	if want := []string{discoveredIP + " " + learnedMAC + " en0"}; !slices.Equal(arp.pinned, want) {
		t.Errorf("pinned = %v, want %v", arp.pinned, want)
	}

	want := map[string]string{
		staticIP:      rotatedMAC,
		otherNetIP:    staticMAC, // outside the subnet: untouched
		discoveredIP:  learnedMAC,
		"192.168.0.7": learnedMAC,
		"192.168.0.8": "",
	}
	if got := s.clients.snapshot(); !maps.Equal(got, want) {
		t.Errorf("registry = %v, want %v", got, want)
	}

	// second tick: adopted entries now match, nothing changes
	arp.pinned = nil
	arp.entries[discoveredIP] = route.ArpEntry{MAC: learnedMAC, Iface: "en0"}
	s.pinClients(t.Context(), arp.ops(), state)

	if len(arp.pinned) != 0 {
		t.Errorf("steady state must not re-pin, got %v", arp.pinned)
	}
}

func TestConnTracker(t *testing.T) {
	t.Parallel()

	ct := newConnTracker()

	lanConn := &fakeConn{remote: &net.TCPAddr{IP: net.ParseIP("192.168.0.42"), Port: 50000}}
	loConn := &fakeConn{remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50001}}

	ct.add(lanConn, true)
	ct.add(loConn, false)

	want := map[string]bool{"192.168.0.42": true, "127.0.0.1": true}
	if got := ct.remoteIPs(); !maps.Equal(got, want) {
		t.Errorf("remoteIPs() = %v, want %v", got, want)
	}

	if n := ct.closeLAN(); n != 1 || !lanConn.closed || loConn.closed {
		t.Errorf("closeLAN() = %d, lan closed %v, loopback closed %v; want only the LAN conn", n, lanConn.closed, loConn.closed)
	}

	if n := ct.closeAll(); n != 1 || !loConn.closed {
		t.Errorf("closeAll() = %d, want the remaining loopback conn", n)
	}
}

type fakeConn struct {
	net.Conn

	remote net.Addr
	closed bool
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.remote }

func (c *fakeConn) Close() error {
	c.closed = true

	return nil
}
