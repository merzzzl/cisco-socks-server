package service

import (
	"context"
	"log/slog"
	"sync"

	"golang.org/x/sync/errgroup"
)

type Service struct {
	mu            sync.RWMutex
	status        State
	ciscoUser     string
	ciscoPassword string
	ciscoProfile  string
	ciscoReady    chan struct{}
}

type State struct {
	CiscoConnected bool
	PFDisabled     bool
	ProxyStarted   bool
}

func New(ciscoUser, ciscoPassword, ciscoProfile string) *Service {
	return &Service{
		ciscoUser:     ciscoUser,
		ciscoPassword: ciscoPassword,
		ciscoProfile:  ciscoProfile,
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

	if err := g.Wait(); err != nil {
		slog.Error("service stopped", "error", err)

		return err
	}

	return nil
}
