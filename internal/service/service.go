package service

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/merzzzl/cisco-socks-server/internal/utils/route"
)

const pinInterval = time.Second

// LANClient is a LAN host pinned to the LAN interface while the VPN is up
// (see route.Pin).
type LANClient struct {
	IP  string `yaml:"ip"`
	MAC string `yaml:"mac"`
}

type Service struct {
	mu            sync.RWMutex
	status        State
	ciscoUser     string
	ciscoPassword string
	ciscoProfile  string
	dnsServers    []string
	lanClients    []LANClient
	ciscoReady    chan struct{}
}

type State struct {
	CiscoConnected bool
	PFDisabled     bool
	LANSubnet      string
	LANInterface   string
	ProxyStarted   bool
	DNSStarted     bool
}

func New(ciscoUser, ciscoPassword, ciscoProfile string, dnsServers []string, lanClients []LANClient) *Service {
	return &Service{
		ciscoUser:     ciscoUser,
		ciscoPassword: ciscoPassword,
		ciscoProfile:  ciscoProfile,
		dnsServers:    dnsServers,
		lanClients:    lanClients,
		ciscoReady:    make(chan struct{}),
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

	if len(s.lanClients) > 0 {
		g.Go(func() error {
			return s.startPinner(ctx)
		})
	}

	return g.Wait()
}

func (s *Service) startPinner(ctx context.Context) error {
	select {
	case <-s.ciscoReady:
	case <-ctx.Done():
		return nil
	}

	for sleepCtx(ctx, pinInterval) {
		state := s.GetState()
		if !state.CiscoConnected || state.LANInterface == "" {
			continue
		}

		for _, lc := range s.lanClients {
			entry, found := route.LookupARP(ctx, lc.IP)
			if route.DecidePin(entry, found, lc.MAC, state.LANInterface) != route.PinRepin {
				continue
			}

			if err := route.Pin(ctx, lc.IP, lc.MAC, state.LANInterface); err != nil {
				slog.Debug("arp pin failed", "ip", lc.IP, "error", err)
			} else {
				slog.Info("LAN client pinned: " + lc.IP + " -> " + lc.MAC)
			}
		}
	}

	return nil
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
