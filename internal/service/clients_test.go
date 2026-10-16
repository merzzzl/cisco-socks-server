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

const (
	staticIP     = "192.168.0.42"
	staticMAC    = "72:ce:39:12:45:0f"
	discoveredIP = "192.168.0.214"
	learnedMAC   = "12:49:61:d3:72:48"
)

func TestClientRegistrySeen(t *testing.T) {
	t.Parallel()

	r := newClientRegistry(nil)
	t0 := time.Unix(1000, 0)

	if !r.seen(discoveredIP, learnedMAC, t0) {
		t.Error("first seen must report a new client")
	}

	if r.seen(discoveredIP, "", t0.Add(time.Minute)) {
		t.Error("second seen must not report a new client")
	}

	mac, last, ok := r.lookup(discoveredIP)
	if !ok || mac != learnedMAC || !last.Equal(t0.Add(time.Minute)) {
		t.Errorf("lookup = %q, %v, %v; want known MAC kept and lastSeen bumped", mac, last, ok)
	}

	r.seen(discoveredIP, staticMAC, t0)

	if mac, _, _ := r.lookup(discoveredIP); mac != staticMAC {
		t.Errorf("seen with a MAC must update it, got %q", mac)
	}
}

func TestClientRegistryExpire(t *testing.T) {
	t.Parallel()

	r := newClientRegistry([]LANClient{{IP: staticIP, MAC: staticMAC}})
	t0 := time.Unix(1000, 0)

	r.seen(discoveredIP, learnedMAC, t0)
	r.seen("192.168.0.7", "", t0)
	r.seen("192.168.0.8", "", t0.Add(20*time.Minute))

	now := t0.Add(discoveredClientTTL)
	got := r.expire(now, discoveredClientTTL, map[string]bool{"192.168.0.7": true})

	if !slices.Equal(got, []string{discoveredIP}) {
		t.Errorf("expire() = %v, want only the stale client without live conns", got)
	}

	want := map[string]string{staticIP: staticMAC, "192.168.0.7": "", "192.168.0.8": ""}
	if snap := r.snapshot(); !maps.Equal(snap, want) {
		t.Errorf("snapshot() = %v, want %v", snap, want)
	}
}

func TestClientRegistryResetNetwork(t *testing.T) {
	t.Parallel()

	r := newClientRegistry([]LANClient{{IP: staticIP, MAC: staticMAC}})
	r.seen(discoveredIP, learnedMAC, time.Unix(1000, 0))

	r.resetNetwork()

	want := map[string]string{staticIP: ""}
	if snap := r.snapshot(); !maps.Equal(snap, want) {
		t.Errorf("snapshot() = %v, want %v", snap, want)
	}

	r.setMAC(staticIP, learnedMAC)
	r.setMAC(discoveredIP, learnedMAC) // unknown IP: no-op

	want = map[string]string{staticIP: learnedMAC}
	if snap := r.snapshot(); !maps.Equal(snap, want) {
		t.Errorf("after setMAC snapshot() = %v, want %v", snap, want)
	}
}

func TestClientRegistryCanonicalStaticMAC(t *testing.T) {
	t.Parallel()

	r := newClientRegistry([]LANClient{{IP: staticIP, MAC: "72-CE-39-12-45-0F"}, {IP: discoveredIP}})

	want := map[string]string{staticIP: staticMAC, discoveredIP: ""}
	if snap := r.snapshot(); !maps.Equal(snap, want) {
		t.Errorf("snapshot() = %v, want %v", snap, want)
	}
}

func TestClientRegistrySnapshotIsCopy(t *testing.T) {
	t.Parallel()

	r := newClientRegistry([]LANClient{{IP: staticIP, MAC: staticMAC}})

	snap := r.snapshot()
	snap[staticIP] = "changed"

	if mac, _, _ := r.lookup(staticIP); mac != staticMAC {
		t.Errorf("mutating the snapshot changed the registry: %q", mac)
	}
}

func TestNeedsRefresh(t *testing.T) {
	t.Parallel()

	now := time.Unix(10000, 0)

	tests := []struct {
		lastSeen time.Time
		name     string
		mac      string
		known    bool
		want     bool
	}{
		{name: "unknown client", want: true},
		{name: "fresh", known: true, mac: learnedMAC, lastSeen: now.Add(-10 * time.Second)},
		{name: "fresh without mac", known: true, lastSeen: now.Add(-10 * time.Second), want: true},
		{name: "stale", known: true, mac: learnedMAC, lastSeen: now.Add(-clientRefreshInterval), want: true},
	}

	for _, tt := range tests {
		if got := needsRefresh(tt.known, tt.mac, tt.lastSeen, now); got != tt.want {
			t.Errorf("%s: needsRefresh() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestDiscoverClient(t *testing.T) {
	t.Parallel()

	s := New(Options{LANDiscovery: true})
	s.setStatus(func(st *State) {
		st.LANInterface = "en0"
		st.LANSubnet = netip.MustParsePrefix("192.168.0.0/24")
	})

	lookups := 0
	s.arp.lookup = func(_ context.Context, ip string) (route.ArpEntry, bool) {
		lookups++

		switch ip {
		case discoveredIP:
			return route.ArpEntry{MAC: learnedMAC, Iface: "en0"}, true
		case "192.168.0.8":
			return route.ArpEntry{MAC: learnedMAC, Iface: "utun4"}, true
		}

		return route.ArpEntry{}, false
	}

	conn := func(ip string) net.Conn {
		return &fakeConn{remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 50000}}
	}

	s.discoverClient(t.Context(), conn(discoveredIP))
	s.discoverClient(t.Context(), conn(discoveredIP)) // throttled
	s.discoverClient(t.Context(), conn("192.168.0.8"))
	s.discoverClient(t.Context(), conn("192.168.0.8")) // no MAC yet: looked up again
	s.discoverClient(t.Context(), conn("10.0.0.5"))    // outside the subnet

	if lookups != 3 {
		t.Errorf("lookups = %d, want 3", lookups)
	}

	want := map[string]string{discoveredIP: learnedMAC, "192.168.0.8": ""}
	if got := s.clients.snapshot(); !maps.Equal(got, want) {
		t.Errorf("registry = %v, want %v", got, want)
	}
}

func TestDiscoveryEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		opts Options
		want bool
	}{
		{Options{}, false},
		{Options{LANClients: []LANClient{{IP: staticIP}}}, false},
		{Options{SocksUser: "proxy", SocksPassword: "secret"}, true},
		{Options{LANDiscovery: true}, true},
	}

	for _, tt := range tests {
		if got := New(tt.opts).discoveryEnabled(); got != tt.want {
			t.Errorf("discoveryEnabled(%+v) = %v, want %v", tt.opts, got, tt.want)
		}
	}
}
