package service

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	socks5 "github.com/things-go/go-socks5"
)

// lanRetryInterval is how often a failed LAN bind is retried.
const lanRetryInterval = 10 * time.Second

// lanSnapshot is the LAN the proxy serves: interface and its subnet.
type lanSnapshot struct {
	Subnet netip.Prefix
	Iface  string
}

func (l lanSnapshot) String() string {
	if l.Iface == "" {
		return "none"
	}

	return l.Iface + "/" + l.Subnet.String()
}

func (s *Service) lanSnapshot() lanSnapshot {
	st := s.GetState()

	return lanSnapshot{Subnet: st.LANSubnet, Iface: st.LANInterface}
}

// lanChanged reports whether next replaces cur. Losing the LAN (next empty)
// is not a change: the last known LAN stays until another one is found.
func lanChanged(cur, next lanSnapshot) bool {
	return next.Iface != "" && next != cur
}

// notifyLANCheck asks the LAN listener owner to compare its listener with
// State. Non-blocking: one pending check is enough.
func (s *Service) notifyLANCheck() {
	select {
	case s.lanCheck <- struct{}{}:
	default:
	}
}

type lanListener struct {
	l      net.Listener
	cancel context.CancelFunc
	done   chan error // result of the accept loop
	bound  lanSnapshot
}

// close stops the accept loop on purpose: the loop sees its context
// cancelled and returns without error.
func (ll *lanListener) close() {
	ll.cancel()
	_ = ll.l.Close()
	<-ll.done
}

// serveLAN owns the LAN listener: it binds it to the LAN interface in State
// (IP_BOUND_IF), re-binds when the LAN changes and retries a failed bind.
// The listener is best-effort: without it the proxy serves localhost only.
// An unexpectedly closed listener is fatal, as for loopback.
func (s *Service) serveLAN(ctx context.Context, server *socks5.Server) error {
	var cur *lanListener

	defer func() {
		if cur != nil {
			cur.close()
		}
	}()

	warnedNoLAN := false

	for {
		want := s.lanSnapshot()

		if cur != nil && cur.bound != want {
			cur.close()
			cur = nil

			if n := s.conns.closeLAN(); n > 0 {
				slog.Info(fmt.Sprintf("LAN changed, dropped %d LAN connections", n))
			}
		}

		switch {
		case cur != nil:
		case want.Iface != "":
			cur = s.openLAN(ctx, server, want)
		case !warnedNoLAN:
			slog.Warn("no LAN interface detected, proxy serves localhost only")

			warnedNoLAN = true
		}

		var retry <-chan time.Time
		if cur == nil && want.Iface != "" {
			retry = time.After(lanRetryInterval)
		}

		var done <-chan error
		if cur != nil {
			done = cur.done
		}

		select {
		case <-ctx.Done():
			return nil
		case <-s.lanCheck:
		case <-retry:
		case err := <-done:
			cur.cancel()
			cur = nil

			return err
		}
	}
}

// openLAN binds the LAN listener and starts its accept loop; nil when the
// bind failed.
func (s *Service) openLAN(ctx context.Context, server *socks5.Server, lan lanSnapshot) *lanListener {
	l, err := s.listenLAN(ctx, lan.Iface)
	if err != nil {
		slog.Warn("failed to listen on LAN interface", "interface", lan.Iface, "error", err)

		return nil
	}

	slog.Info("proxy bound to LAN interface", "interface", lan.Iface, "subnet", lan.Subnet)

	lctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)

	go func() {
		done <- s.acceptConns(lctx, l, server, true)
	}()

	return &lanListener{l: l, cancel: cancel, done: done, bound: lan}
}
