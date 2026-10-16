package service

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"time"

	"github.com/miekg/dns"
)

const (
	dnsListenAddr      = "127.0.0.1:53"
	dnsUpstreamTimeout = 5 * time.Second
	dnsUpstreamUDPSize = 4096
)

func (s *Service) startDNS(ctx context.Context) error {
	defer s.setStatus(func(st *State) {
		st.DNSStarted = false
	})

	select {
	case <-s.ciscoReady:
	case <-ctx.Done():
		return nil
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) > 0 {
			q := r.Question[0]
			slog.Info("dns query", "name", q.Name, "type", dns.TypeToString[q.Qtype])
		}

		resp, err := s.forwardDNS(r)
		if err != nil {
			slog.Error("dns forward failed", "error", err)

			msg := new(dns.Msg)
			msg.SetRcode(r, dns.RcodeServerFailure)
			_ = w.WriteMsg(msg)

			return
		}

		_ = w.WriteMsg(resp)
	})

	// listen before reporting DNSStarted so a busy :53 fails loudly, and own
	// the listener so shutdown works even if ctx is cancelled before the
	// server starts (miekg's Shutdown refuses a not-yet-started server, which
	// would leave ActivateAndServe blocked forever)
	var lc net.ListenConfig

	l, err := lc.Listen(ctx, "tcp", dnsListenAddr)
	if err != nil {
		return fmt.Errorf("dns listen: %w", err)
	}

	server := &dns.Server{
		Listener: l,
		Net:      "tcp",
		Handler:  handler,
	}

	go func() {
		<-ctx.Done()

		_ = server.Shutdown()
		_ = l.Close()
	}()

	s.setStatus(func(st *State) {
		st.DNSStarted = true
	})

	slog.Info("starting DNS server on " + dnsListenAddr)

	if err := server.ActivateAndServe(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("dns server error: %w", err)
	}

	slog.Info("DNS server stopped")

	return nil
}

// forwardDNS relays a TCP-received query over UDP. Without EDNS0 the upstream
// caps UDP answers at 512 bytes and sets TC; relaying a truncated answer back
// over TCP is useless (the client would retry over TCP — to us again), so a
// larger UDP buffer is advertised upstream and stripped from the reply when
// the client did not ask for EDNS0 itself.
func (s *Service) forwardDNS(r *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{
		Net:     "udp",
		Timeout: dnsUpstreamTimeout,
	}

	req := r
	clientEDNS := r.IsEdns0() != nil

	if !clientEDNS {
		req = r.Copy()
		req.SetEdns0(dnsUpstreamUDPSize, false)
	}

	var lastErr error

	for _, server := range s.opts.DNSServers {
		resp, _, err := client.Exchange(req, net.JoinHostPort(server, "53"))
		if err != nil {
			lastErr = err
			slog.Debug("dns upstream failed", "server", server, "error", err)

			continue
		}

		if !clientEDNS {
			resp.Extra = slices.DeleteFunc(resp.Extra, func(rr dns.RR) bool {
				return rr.Header().Rrtype == dns.TypeOPT
			})
		}

		if resp.Truncated {
			slog.Warn("dns answer truncated by upstream " + server)
		}

		return resp, nil
	}

	return nil, fmt.Errorf("all dns servers failed: %w", lastErr)
}
