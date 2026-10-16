package service

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/merzzzl/cisco-socks-server/internal/utils/route"
)

const (
	pinInterval          = time.Second
	clientExpireInterval = time.Minute
)

// LANClient is a LAN host pinned to the LAN interface while the VPN is up
// (see route.Pin). MAC is optional: when empty it is learned from ARP.
type LANClient struct {
	IP  string `yaml:"ip"`
	MAC string `yaml:"mac"`
}

// Options configures a Service.
type Options struct {
	CiscoUser     string
	CiscoPassword string
	CiscoProfile  string
	// SocksUser/SocksPassword, when set, require SOCKS5 username/password
	// auth on the LAN listener (loopback stays open).
	SocksUser     string
	SocksPassword string
	DNSServers    []string
	LANClients    []LANClient
	// LANDiscovery enables client autodiscovery without auth, i.e. an open
	// proxy for everyone on the network. Auth enables it on its own.
	LANDiscovery bool
}

type Service struct {
	clients    *clientRegistry
	conns      *connTracker
	ciscoReady chan struct{}
	status     State
	opts       Options
	mu         sync.RWMutex
}

type State struct {
	LANSubnet      netip.Prefix
	LANInterface   string
	CiscoConnected bool
	PFDisabled     bool
	ProxyStarted   bool
	DNSStarted     bool
}

func New(opts Options) *Service {
	return &Service{
		opts:       opts,
		clients:    newClientRegistry(opts.LANClients),
		conns:      newConnTracker(),
		ciscoReady: make(chan struct{}),
	}
}

func (s *Service) GetState() State {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.status
}

func (s *Service) setStatus(fn func(*State)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fn(&s.status)
}

func (s *Service) Start(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return s.startCisco(ctx)
	})

	g.Go(func() error {
		return s.startProxy(ctx)
	})

	g.Go(func() error {
		return s.startDNS(ctx)
	})

	g.Go(func() error {
		return s.startPinner(ctx)
	})

	return g.Wait()
}

// pinOps are the shell operations of a pinner tick, swapped out in tests.
type pinOps struct {
	lookup func(ctx context.Context, ip string) (route.ArpEntry, bool)
	pin    func(ctx context.Context, ip, mac, iface string) error
}

var shellPinOps = pinOps{lookup: route.LookupARP, pin: route.Pin}

func (s *Service) startPinner(ctx context.Context) error {
	select {
	case <-s.ciscoReady:
	case <-ctx.Done():
		return nil
	}

	var lastExpire time.Time

	for sleepCtx(ctx, pinInterval) {
		if now := time.Now(); now.Sub(lastExpire) >= clientExpireInterval {
			lastExpire = now

			for _, ip := range s.clients.expire(now, discoveredClientTTL, s.conns.remoteIPs()) {
				slog.Info("LAN client expired", "ip", ip)
			}
		}

		state := s.GetState()
		if !state.CiscoConnected || state.LANInterface == "" {
			continue
		}

		s.pinClients(ctx, shellPinOps, state)
	}

	return nil
}

// pinClients keeps every registered client in the current LAN subnet
// reachable. The check is read-only; ARP is mutated only on drift (see
// route.DecidePin), because a re-pin drops in-flight frames.
func (s *Service) pinClients(ctx context.Context, ops pinOps, state State) {
	for ip, mac := range s.clients.snapshot() {
		// a static client of another network must not be pinned here: the
		// IP belongs to someone else (or no one) in this one
		if addr, err := netip.ParseAddr(ip); err != nil || !state.LANSubnet.Contains(addr) {
			continue
		}

		entry, found := ops.lookup(ctx, ip)

		switch route.DecidePin(entry, found, mac, state.LANInterface) {
		case route.PinAdopt:
			s.clients.setMAC(ip, entry.MAC)

			if mac == "" {
				slog.Info("LAN client MAC learned", "ip", ip, "mac", entry.MAC)
			} else {
				slog.Warn("LAN client MAC changed", "ip", ip, "old", mac, "new", entry.MAC)
			}
		case route.PinRepin:
			if err := ops.pin(ctx, ip, mac, state.LANInterface); err != nil {
				slog.Debug("arp pin failed", "ip", ip, "error", err)
			} else {
				slog.Info("LAN client pinned", "ip", ip, "mac", mac)
			}
		case route.PinNone:
		}
	}
}

// sleepCtx waits for d and reports whether ctx is still alive afterwards.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
