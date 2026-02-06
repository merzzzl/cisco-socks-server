package service

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	socks5 "github.com/things-go/go-socks5"
	"golang.org/x/sync/errgroup"

	"github.com/merzzzl/cisco-socks5/internal/utils/cisco"
	"github.com/merzzzl/cisco-socks5/internal/utils/log"
)

type Service struct {
	status        *State
	ciscoUser     string
	ciscoPassword string
	ciscoProfile  string
}

type State struct {
	CiscoConnected bool
	PFDisabled     bool
	ProxyStarted   bool
}

func New(ciscoUser, ciscoPassword, ciscoProfile string) *Service {
	return &Service{
		status:        &State{},
		ciscoUser:     ciscoUser,
		ciscoPassword: ciscoPassword,
		ciscoProfile:  ciscoProfile,
	}
}

func (s *Service) GetState() State {
	return *s.status
}

func (s *Service) Start(ctx context.Context) error {
	ctx, closer := context.WithCancel(ctx)
	defer closer()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if err := s.StartCisco(ctx); err != nil {
			return fmt.Errorf("failed to start cisco: %w", err)
		}

		return nil
	})

	g.Go(func() error {
		if err := s.ProxyServer(ctx); err != nil {
			return fmt.Errorf("failed to start proxy: %w", err)
		}

		return nil
	})

	if err := g.Wait(); err != nil {
		log.Error().Msgf("SYS", "failed to start service: %v", err)

		return err
	}

	return nil
}

func (s *Service) StartCisco(ctx context.Context) error {
	ctx, closer := context.WithCancel(ctx)
	maxRetries := 3

	defer func() {
		closer()

		s.status.CiscoConnected = false
		s.status.PFDisabled = false
	}()

	for ctx.Err() == nil {
		connected, err := cisco.IsConected()
		if err != nil {
			log.Error().Err(err).Msgf("CIS", "failed to get cisco state: %v", err)
		}

		if !connected && err == nil {
			if err := cisco.Connect(s.ciscoProfile, s.ciscoUser, s.ciscoPassword); err != nil {
				if maxRetries == 0 {
					return fmt.Errorf("failed to connect to cisco: %w", err)
				}

				log.Error().Err(err).Msgf("CIS", "failed to connect to cisco: %v", err)

				maxRetries--
			} else {
				s.status.CiscoConnected = true
				s.status.PFDisabled = false
			}
		}

		if s.status.CiscoConnected && !s.status.PFDisabled {
			if err := cisco.DisablePF(); err != nil {
				log.Error().Err(err).Msgf("NPF", "failed to disable network pf: %v", err)
			} else {
				s.status.PFDisabled = true
			}
		}

		time.Sleep(5 * time.Second)
	}

	if err := cisco.Disconnect(); err != nil {
		return fmt.Errorf("failed to disconnect cisco: %w", err)
	}

	return nil
}

type proxyLogger struct{}

func (p *proxyLogger) Errorf(format string, args ...interface{}) {
	log.Error().Msgf("SOC", format, args...)
}

func (s *Service) ProxyServer(ctx context.Context) error {
	ctx, closer := context.WithCancel(ctx)

	defer func() {
		closer()

		s.status.ProxyStarted = false
	}()

	server := socks5.NewServer(socks5.WithConnectMiddleware(func(_ context.Context, _ io.Writer, request *socks5.Request) error {
		log.Info().Msgf("SOC", "connection to %s", request.DestAddr.Address())

		return nil
	}), socks5.WithLogger(&proxyLogger{}))

	lc := net.ListenConfig{}

	list, err := lc.Listen(ctx, "tcp", "0.0.0.0:8080")
	if err != nil {
		return fmt.Errorf("failed to listen on port 8080: %w", err)
	}

	go func() {
		<-ctx.Done()

		_ = list.Close()
	}()

	s.status.ProxyStarted = true

	if err := server.Serve(list); err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	return nil
}
