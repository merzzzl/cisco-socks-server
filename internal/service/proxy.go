package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"

	socks5 "github.com/things-go/go-socks5"
)

type proxyLogger struct{}

func (p *proxyLogger) Errorf(format string, args ...any) {
	slog.Error(fmt.Sprintf(format, args...))
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

	server := socks5.NewServer(socks5.WithConnectMiddleware(func(_ context.Context, _ io.Writer, request *socks5.Request) error {
		slog.Info("connection to " + request.DestAddr.Address())

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

	s.setStatus(func(st *State) {
		st.ProxyStarted = true
	})

	if err := server.Serve(list); err != nil {
		if ctx.Err() != nil && errors.Is(err, net.ErrClosed) {
			return nil
		}

		return fmt.Errorf("proxy server error: %w", err)
	}

	return nil
}
