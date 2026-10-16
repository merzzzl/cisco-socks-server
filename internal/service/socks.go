package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"

	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

var errVPNDown = errors.New("VPN is not connected")

// newSocksServer builds the server for one listener. The LAN one requires
// username/password when configured; loopback stays open. Both refuse
// requests while the VPN is down: the dial would follow the routing table
// as it is without the tunnel and leak corporate traffic past it.
func (s *Service) newSocksServer(lan bool) *socks5.Server {
	opts := []socks5.Option{
		socks5.WithLogger(&proxyLogger{}),
		socks5.WithResolver(vpnGatedResolver{s: s}),
		socks5.WithConnectMiddleware(s.vpnGate),
	}

	if lan && s.opts.SocksUser != "" {
		opts = append(opts, socks5.WithCredential(socks5.StaticCredentials{s.opts.SocksUser: s.opts.SocksPassword}))
	}

	return socks5.NewServer(opts...)
}

// vpnGate rejects CONNECT while the VPN is down. go-socks5 sends no reply
// for a middleware error, so the reply is written here: the client fails
// at once instead of on a timeout.
func (s *Service) vpnGate(_ context.Context, w io.Writer, request *socks5.Request) error {
	dest := request.DestAddr.Address()

	if !s.GetState().CiscoConnected {
		slog.Debug("connection refused, VPN is down", "dest", dest)

		if err := socks5.SendReply(w, statute.RepNetworkUnreachable, nil); err != nil {
			return fmt.Errorf("send reply: %w", err)
		}

		return errVPNDown
	}

	slog.Info("connection to " + dest)

	return nil
}

// vpnGatedResolver fails name resolution while the VPN is down. go-socks5
// resolves FQDN destinations before any middleware runs, through the system
// resolver, i.e. our DNS forwarder and dns_servers outside the tunnel.
type vpnGatedResolver struct {
	s *Service
}

func (r vpnGatedResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if !r.s.GetState().CiscoConnected {
		return ctx, nil, errVPNDown
	}

	return socks5.DNSResolver{}.Resolve(ctx, name)
}
