package service

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"time"
)

const (
	// snifferRetry is the pause before tcpdump is restarted after it failed.
	snifferRetry = 10 * time.Second
	// snifferLANPoll is how often the sniffer checks State for a LAN change.
	snifferLANPoll = 2 * time.Second
)

var errSnifferExited = errors.New("tcpdump exited")

// startSniffer discovers LAN clients from their SYN to the proxy port, before
// the handshake: discoverClient on Accept alone cannot bootstrap a client
// that is not pinned yet, because its handshake never completes while the
// subnet is routed into the tunnel (see route.WatchSYN). Gated like
// discoverClient: discovery without auth is an open proxy.
func (s *Service) startSniffer(ctx context.Context) error {
	if !s.discoveryEnabled() {
		return nil
	}

	for {
		lan := s.lanSnapshot()
		if lan.Iface == "" {
			if !sleepCtx(ctx, snifferLANPoll) {
				return nil
			}

			continue
		}

		if err := s.sniffLAN(ctx, lan); err != nil {
			slog.Warn("SYN sniffer failed", "interface", lan.Iface, "error", err)

			if !sleepCtx(ctx, snifferRetry) {
				return nil
			}
		}

		if ctx.Err() != nil {
			return nil
		}
	}
}

// sniffLAN watches lan until ctx ends, tcpdump fails or the LAN changes; the
// last two are reported as nil.
func (s *Service) sniffLAN(ctx context.Context, lan lanSnapshot) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		for sleepCtx(ctx, snifferLANPoll) {
			if s.lanSnapshot() != lan {
				cancel()

				return
			}
		}
	}()

	err := s.watchSYN(ctx, lan.Iface, proxyPort, func(ip netip.Addr, mac string) {
		s.observeSYN(ctx, ip, mac)
	})
	if ctx.Err() != nil {
		return nil
	}

	if err == nil {
		err = errSnifferExited
	}

	return err
}

// observeSYN registers the sender of a SYN with the MAC from its frame,
// which is the freshest one there is (private Wi-Fi MACs rotate).
func (s *Service) observeSYN(ctx context.Context, ip netip.Addr, mac string) {
	state := s.GetState()
	if state.LANInterface == "" || !state.LANSubnet.Contains(ip) || ip == state.LANAddr {
		return
	}

	key := ip.String()
	old, _, known := s.clients.lookup(key)

	if mac != old {
		s.repinStale(ctx, state, key, mac)
	}

	s.clients.seen(key, mac, time.Now())

	switch {
	case !known:
		slog.Info("LAN client discovered", "ip", key, "mac", mac)
	case old != "" && old != mac:
		slog.Warn("LAN client MAC changed", "ip", key, "old", old, "new", mac)
	}
}

// repinStale replaces a kernel entry on the LAN interface that disagrees with
// the frame, typically our own earlier pin with a MAC the client has rotated
// away from. The pinner would adopt that entry back (DecidePin trusts the
// kernel), so the frame has to win here. A missing entry is left to the
// pinner, which re-pins it with the registry MAC anyway.
func (s *Service) repinStale(ctx context.Context, state State, ip, mac string) {
	if !state.CiscoConnected {
		return
	}

	entry, found := s.arp.lookup(ctx, ip)
	if !found || entry.Iface != state.LANInterface || entry.MAC == mac {
		return
	}

	if err := s.arp.pin(ctx, ip, mac, state.LANInterface); err != nil {
		slog.Debug("arp pin failed", "ip", ip, "error", err)
	} else {
		slog.Info("LAN client pinned", "ip", ip, "mac", mac)
	}
}
