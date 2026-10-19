package service

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"testing"
	"time"
)

const (
	selfIP     = "192.168.0.105"
	rotatedMAC = "82:b4:3b:8e:d2:f3"
)

func lanState() State {
	return State{
		LANInterface: "en0",
		LANSubnet:    netip.MustParsePrefix("192.168.0.0/24"),
		LANAddr:      netip.MustParseAddr(selfIP),
	}
}

func TestObserveSYN(t *testing.T) {
	t.Parallel()

	s := New(Options{SocksUser: "u", SocksPassword: "p", LANClients: []LANClient{{IP: staticIP, MAC: staticMAC}}})
	s.setStatus(func(st *State) { *st = lanState() })

	s.observeSYN(netip.MustParseAddr(discoveredIP), learnedMAC)
	s.observeSYN(netip.MustParseAddr(staticIP), rotatedMAC) // the frame wins
	s.observeSYN(netip.MustParseAddr(selfIP), learnedMAC)   // our own outbound SYN
	s.observeSYN(netip.MustParseAddr("10.0.0.5"), learnedMAC)

	want := map[string]string{discoveredIP: learnedMAC, staticIP: rotatedMAC}
	if got := s.clients.snapshot(); !maps.Equal(got, want) {
		t.Errorf("registry = %v, want %v", got, want)
	}
}

func TestPinClientsSkipsSelf(t *testing.T) {
	t.Parallel()

	s := New(Options{LANClients: []LANClient{{IP: selfIP, MAC: staticMAC}}})
	arp := &fakeARP{}
	s.arp = arp.ops()

	s.pinClients(t.Context(), lanState())

	if len(arp.pinned) != 0 {
		t.Errorf("own address must not be pinned, got %v", arp.pinned)
	}
}

func TestSniffLAN(t *testing.T) {
	t.Parallel()

	s := New(Options{SocksUser: "u", SocksPassword: "p"})
	s.setStatus(func(st *State) { *st = lanState() })
	lan := s.lanSnapshot()

	// tcpdump quitting on its own is an error, even with exit status 0
	s.watchSYN = func(context.Context, string, string, func(netip.Addr, string)) error { return nil }
	if err := s.sniffLAN(t.Context(), lan); !errors.Is(err, errSnifferExited) {
		t.Errorf("sniffLAN() = %v, want errSnifferExited", err)
	}

	// a LAN change stops the watch without an error
	s.watchSYN = func(ctx context.Context, _, _ string, onSYN func(netip.Addr, string)) error {
		onSYN(netip.MustParseAddr(discoveredIP), learnedMAC)
		s.setStatus(func(st *State) { st.LANInterface = "en7" })
		<-ctx.Done()

		return ctx.Err()
	}

	done := make(chan error, 1)
	go func() { done <- s.sniffLAN(t.Context(), lan) }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("sniffLAN() after a LAN change = %v, want nil", err)
		}
	case <-time.After(3 * snifferLANPoll):
		t.Fatal("sniffLAN did not stop on a LAN change")
	}

	if mac, _, ok := s.clients.lookup(discoveredIP); !ok || mac != learnedMAC {
		t.Errorf("client from SYN = %q, %v; want %q", mac, ok, learnedMAC)
	}
}
