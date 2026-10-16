package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	socks5 "github.com/things-go/go-socks5"
	"golang.org/x/sync/errgroup"
)

const (
	proxyPort          = "8080"
	acceptErrorBackoff = 500 * time.Millisecond
	vpnWatchInterval   = 2 * time.Second
)

type proxyLogger struct{}

func (*proxyLogger) Errorf(format string, args ...any) {
	slog.Error(fmt.Sprintf(format, args...))
}

// connTracker remembers live client connections so they can be dropped at
// once when the tunnel goes away: their upstream legs are dead by then, and
// without an explicit close clients hang until TCP gives up.
type connTracker struct {
	conns map[net.Conn]bool // value: accepted on the LAN listener
	mu    sync.Mutex
}

func newConnTracker() *connTracker {
	return &connTracker{conns: make(map[net.Conn]bool)}
}

func (ct *connTracker) add(c net.Conn, lan bool) {
	ct.mu.Lock()
	ct.conns[c] = lan
	ct.mu.Unlock()
}

func (ct *connTracker) remove(c net.Conn) {
	ct.mu.Lock()
	delete(ct.conns, c)
	ct.mu.Unlock()
}

func (ct *connTracker) closeAll() int {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	n := len(ct.conns)
	for c := range ct.conns {
		_ = c.Close()
	}

	clear(ct.conns)

	return n
}

// closeLAN drops the connections accepted on the LAN listener: after a
// network change their peers are on a network we are no longer part of.
func (ct *connTracker) closeLAN() int {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	n := 0

	for c, lan := range ct.conns {
		if !lan {
			continue
		}

		_ = c.Close()

		delete(ct.conns, c)

		n++
	}

	return n
}

// remoteIPs is the set of peer IPs with live connections.
func (ct *connTracker) remoteIPs() map[string]bool {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	ips := make(map[string]bool, len(ct.conns))

	for c := range ct.conns {
		if ap, ok := remoteAddrPort(c); ok {
			ips[ap.Addr().String()] = true
		}
	}

	return ips
}

func remoteAddrPort(c net.Conn) (netip.AddrPort, bool) {
	tcp, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}

	ap := tcp.AddrPort()

	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

func (s *Service) startProxy(ctx context.Context) error {
	defer s.setStatus(func(st *State) {
		st.ProxyStarted = false
	})

	select {
	case <-s.ciscoReady:
	case <-ctx.Done():
		return nil
	}

	var lc net.ListenConfig

	loopback, err := lc.Listen(ctx, "tcp4", net.JoinHostPort("127.0.0.1", proxyPort))
	if err != nil {
		return fmt.Errorf("failed to listen on loopback: %w", err)
	}

	defer s.conns.closeAll()

	s.setStatus(func(st *State) {
		st.ProxyStarted = true
	})

	slog.Info("starting SOCKS5 server on " + proxyPort)

	if s.opts.SocksUser == "" && s.opts.LANDiscovery {
		slog.Warn("lan_discovery without socks_user: the LAN proxy is open to anyone on the network")
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return s.acceptConns(gctx, loopback, s.newSocksServer(false), false)
	})

	g.Go(func() error {
		return s.serveLAN(gctx, s.newSocksServer(true))
	})

	g.Go(func() error {
		s.dropConnsOnVPNLoss(gctx)

		return nil
	})

	// unblocks Accept; gctx is also cancelled when Wait returns, so this
	// goroutine never outlives startProxy
	go func() {
		<-gctx.Done()

		_ = loopback.Close()
	}()

	if err := g.Wait(); err != nil {
		return fmt.Errorf("proxy: %w", err)
	}

	slog.Info("proxy server stopped")

	return nil
}

// acceptConns serves l until ctx is done; lan marks the LAN listener.
func (s *Service) acceptConns(ctx context.Context, l net.Listener, server *socks5.Server, lan bool) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("listener %s closed unexpectedly: %w", l.Addr(), err)
			}

			// transient (EMFILE, ECONNABORTED, ...): back off and keep serving
			slog.Warn("accept error", "error", err)

			select {
			case <-ctx.Done():
				return nil
			case <-time.After(acceptErrorBackoff):
			}

			continue
		}

		s.conns.add(conn, lan)

		go func() {
			defer s.conns.remove(conn)

			if lan && s.discoveryEnabled() {
				s.discoverClient(ctx, conn)
			}

			_ = server.ServeConn(conn)
		}()
	}
}

func (s *Service) dropConnsOnVPNLoss(ctx context.Context) {
	ticker := time.NewTicker(vpnWatchInterval)
	defer ticker.Stop()

	wasConnected := s.GetState().CiscoConnected

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		connected := s.GetState().CiscoConnected
		if wasConnected && !connected {
			if n := s.conns.closeAll(); n > 0 {
				slog.Info(fmt.Sprintf("VPN lost, dropped %d active connections", n))
			}
		}

		wasConnected = connected
	}
}
