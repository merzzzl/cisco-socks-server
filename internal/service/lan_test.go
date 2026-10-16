package service

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

var (
	errAddrInUse = errors.New("address in use")

	homeLAN = lanSnapshot{Subnet: netip.MustParsePrefix("192.168.0.0/24"), Iface: "en0"}
	cafeLAN = lanSnapshot{Subnet: netip.MustParsePrefix("10.0.0.0/24"), Iface: "en0"}
	usbLAN  = lanSnapshot{Subnet: netip.MustParsePrefix("192.168.0.0/24"), Iface: "en7"}
)

func TestLANChanged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cur, next lanSnapshot
		want      bool
	}{
		{"same", homeLAN, homeLAN, false},
		{"other subnet", homeLAN, cafeLAN, true},
		{"other interface", homeLAN, usbLAN, true},
		{"first detection", lanSnapshot{}, homeLAN, true},
		{"lost", homeLAN, lanSnapshot{}, false},
	}

	for _, tt := range tests {
		if got := lanChanged(tt.cur, tt.next); got != tt.want {
			t.Errorf("%s: lanChanged() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestConfirmLAN(t *testing.T) {
	t.Parallel()

	sv := &ciscoSupervisor{}

	if !sv.confirmLAN(lanSnapshot{}, homeLAN) {
		t.Error("first detection must apply at once")
	}

	if sv.confirmLAN(homeLAN, usbLAN) {
		t.Error("a change must not apply on its first sighting")
	}

	if sv.confirmLAN(homeLAN, homeLAN) {
		t.Error("an unchanged LAN must not apply")
	}

	if sv.confirmLAN(homeLAN, cafeLAN) {
		t.Error("a blip must reset the pending change")
	}

	if !sv.confirmLAN(homeLAN, cafeLAN) {
		t.Error("a change seen twice in a row must apply")
	}
}

// fakeLANBinder hands out loopback listeners in place of IP_BOUND_IF ones.
type fakeLANBinder struct {
	fail      error
	listeners []net.Listener
	ifaces    []string
	mu        sync.Mutex
}

func (b *fakeLANBinder) listen(ctx context.Context, iface string) (net.Listener, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.ifaces = append(b.ifaces, iface)
	if b.fail != nil {
		return nil, b.fail
	}

	var lc net.ListenConfig

	l, err := lc.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err == nil {
		b.listeners = append(b.listeners, l)
	}

	return l, err
}

func (b *fakeLANBinder) calls() []string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return append([]string(nil), b.ifaces...)
}

func (b *fakeLANBinder) last() net.Listener {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.listeners[len(b.listeners)-1]
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}

		time.Sleep(5 * time.Millisecond)
	}
}

func setLAN(s *Service, lan lanSnapshot) {
	s.setStatus(func(st *State) {
		st.LANInterface = lan.Iface
		st.LANSubnet = lan.Subnet
	})
	s.notifyLANCheck()
}

func TestServeLANRebindsOnChange(t *testing.T) {
	t.Parallel()

	s := New(Options{})
	binder := &fakeLANBinder{}
	s.listenLAN = binder.listen

	setLAN(s, homeLAN) // leaves a pending check, as the first detection does

	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)

	go func() { errc <- s.serveLAN(ctx, s.newSocksServer(true)) }()

	waitFor(t, "first bind", func() bool { return len(binder.calls()) == 1 })

	// the pending check of the first detection must not re-bind
	time.Sleep(50 * time.Millisecond)

	if got := binder.calls(); len(got) != 1 {
		t.Fatalf("binds = %v, want one", got)
	}

	// a LAN connection on the old network is dropped on change
	conn, err := net.Dial("tcp4", binder.last().Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	waitFor(t, "tracked LAN conn", func() bool { return len(s.conns.remoteIPs()) == 1 })

	setLAN(s, usbLAN)
	waitFor(t, "re-bind", func() bool { return len(binder.calls()) == 2 })

	if got := binder.calls(); got[1] != "en7" {
		t.Errorf("re-bound to %s, want en7", got[1])
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("connection from the old LAN must be closed")
	}

	cancel()

	if err := <-errc; err != nil {
		t.Errorf("serveLAN() = %v on shutdown, want nil", err)
	}
}

func TestServeLANUnexpectedClose(t *testing.T) {
	t.Parallel()

	s := New(Options{})
	binder := &fakeLANBinder{}
	s.listenLAN = binder.listen
	setLAN(s, homeLAN)

	errc := make(chan error, 1)

	go func() { errc <- s.serveLAN(t.Context(), s.newSocksServer(true)) }()

	waitFor(t, "bind", func() bool { return len(binder.calls()) == 1 })

	_ = binder.last().Close()

	select {
	case err := <-errc:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("serveLAN() = %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveLAN did not fail on an unexpectedly closed listener")
	}
}

func TestServeLANBindFailure(t *testing.T) {
	t.Parallel()

	s := New(Options{})
	binder := &fakeLANBinder{fail: errAddrInUse}
	s.listenLAN = binder.listen

	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)

	go func() { errc <- s.serveLAN(ctx, s.newSocksServer(true)) }()

	// no LAN yet: nothing to bind
	time.Sleep(50 * time.Millisecond)

	if got := binder.calls(); len(got) != 0 {
		t.Fatalf("binds without a LAN = %v", got)
	}

	setLAN(s, homeLAN)
	waitFor(t, "failed bind", func() bool { return len(binder.calls()) == 1 })

	// a failed bind is retried on the next check (and on lanRetryInterval)
	s.notifyLANCheck()
	waitFor(t, "retry", func() bool { return len(binder.calls()) == 2 })

	cancel()

	if err := <-errc; err != nil {
		t.Errorf("serveLAN() = %v, want nil", err)
	}
}
