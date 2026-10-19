package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/merzzzl/cisco-socks-server/internal/utils/cisco"
	"github.com/merzzzl/cisco-socks-server/internal/utils/route"
)

const (
	ciscoPollInterval    = 5 * time.Second
	ciscoMaxConnectDelay = time.Minute
	// how long to trust agent-driven reconnection before forcing a disconnect:
	// the agent can stay in "Reconnecting" indefinitely (observed 6+ min), and
	// only an explicit "vpn -s disconnect" kicks it out of that state.
	ciscoReconnectGrace = 2 * time.Minute
	// disconnect must not hang on a wedged agent, neither at shutdown nor
	// when kicking it out of a stuck reconnect
	ciscoDisconnectTimeout = 30 * time.Second
)

// ciscoSupervisor is the per-run state of startCisco's polling loop.
type ciscoSupervisor struct {
	s                 *Service
	reconnectingSince time.Time
	pendingLAN        lanSnapshot // LAN change awaiting confirmation
	connectDelay      time.Duration
	readyNotified     bool
	connectedByUs     bool
}

func (s *Service) startCisco(ctx context.Context) error {
	sv := &ciscoSupervisor{s: s, connectDelay: ciscoPollInterval}

	defer sv.shutdown(ctx)

	var delay time.Duration // first tick runs immediately

	for sleepCtx(ctx, delay) {
		delay = sv.tick(ctx)
	}

	return nil
}

// tick runs one supervisor iteration and returns the delay before the next.
func (sv *ciscoSupervisor) tick(ctx context.Context) time.Duration {
	sv.detectLAN(ctx)

	delay := ciscoPollInterval

	state, err := cisco.Status(ctx)

	switch {
	case err != nil:
		// transient CLI failure (the vpn binary occasionally aborts);
		// keep the last known status and poll again
		slog.Error("failed to get cisco state", "error", err)
	case state == cisco.StateConnected:
		sv.connectDelay = ciscoPollInterval
		sv.reconnectingSince = time.Time{}
		sv.setConnected(true)
	case state == cisco.StateReconnecting:
		sv.setConnected(false)
		sv.awaitReconnect(ctx)
	default:
		sv.reconnectingSince = time.Time{}
		sv.setConnected(false)
		delay = sv.connect(ctx)
	}

	if sv.s.GetState().CiscoConnected {
		sv.disablePF(ctx)

		if !sv.readyNotified {
			close(sv.s.ciscoReady)
			sv.readyNotified = true
		}
	}

	return delay
}

// detectLAN tracks the LAN interface and subnet. The first detection runs
// before Cisco hijacks the default route (the non-tunnel default stays in the
// table afterwards, so later ticks still see it); the proxy binds its LAN
// listener to the interface via IP_BOUND_IF so replies egress via the
// physical NIC regardless of the routing table. A change (another Wi-Fi, an
// Ethernet switch) re-binds the listener and resets the client registry.
func (sv *ciscoSupervisor) detectLAN(ctx context.Context) {
	cur := sv.s.lanSnapshot()

	ifaddr, iface, err := route.DetectLAN(ctx, cur.Iface)
	if err != nil {
		if !errors.Is(err, route.ErrNoLANInterface) {
			slog.Warn("failed to detect LAN", "error", err)
		}

		sv.pendingLAN = lanSnapshot{}

		return
	}

	subnet, addr := ifaddr.Masked(), ifaddr.Addr()

	next := lanSnapshot{Subnet: subnet, Iface: iface}
	if !sv.confirmLAN(cur, next) {
		// DHCP can hand out another address within the same subnet
		if next == cur {
			sv.s.setStatus(func(st *State) {
				st.LANAddr = addr
			})
		}

		return
	}

	if cur.Iface == "" {
		slog.Info("LAN detected", "subnet", subnet, "interface", iface)
	} else {
		slog.Info("LAN changed", "old", cur.String(), "new", next.String())

		// clients of the old network; the first detection keeps the
		// static MACs from the config
		sv.s.clients.resetNetwork()
	}

	sv.s.setStatus(func(st *State) {
		st.LANSubnet = subnet
		st.LANAddr = addr
		st.LANInterface = iface
	})

	sv.s.warnSelfClients(addr)

	sv.s.notifyLANCheck()
}

// confirmLAN debounces LAN changes: the first detection applies at once, a
// change only once the same snapshot was seen on two ticks in a row, so a
// transient routing-table state does not re-bind the listener and drop LAN
// connections.
func (sv *ciscoSupervisor) confirmLAN(cur, next lanSnapshot) bool {
	if !lanChanged(cur, next) {
		sv.pendingLAN = lanSnapshot{}

		return false
	}

	if cur.Iface != "" && sv.pendingLAN != next {
		sv.pendingLAN = next

		return false
	}

	sv.pendingLAN = lanSnapshot{}

	return true
}

// setConnected records the VPN status. Losing the connection also resets
// PFDisabled: Cisco re-enables pf on every reconnect, so pfctl -d must run
// again.
func (sv *ciscoSupervisor) setConnected(connected bool) {
	sv.s.setStatus(func(st *State) {
		st.CiscoConnected = connected
		if !connected {
			st.PFDisabled = false
		}
	})
}

// awaitReconnect leaves agent-driven reconnection alone (issuing "connect"
// now would only interfere), unless it has been stuck past the grace period.
func (sv *ciscoSupervisor) awaitReconnect(ctx context.Context) {
	if sv.reconnectingSince.IsZero() {
		sv.reconnectingSince = time.Now()
	}

	elapsed := time.Since(sv.reconnectingSince)
	if elapsed <= ciscoReconnectGrace {
		slog.Info("cisco agent is reconnecting, waiting")

		return
	}

	slog.Warn("cisco agent stuck in reconnecting, forcing disconnect", "elapsed", elapsed.Round(time.Second))

	dctx, cancel := context.WithTimeout(ctx, ciscoDisconnectTimeout)
	defer cancel()

	if err := cisco.Disconnect(dctx); err != nil {
		slog.Error("failed to force disconnect", "error", err)

		return
	}

	sv.reconnectingSince = time.Time{}
}

// connect issues "vpn -s connect" and returns the delay before the next tick:
// the regular poll interval, or an exponential backoff after a failure.
func (sv *ciscoSupervisor) connect(ctx context.Context) time.Duration {
	err := cisco.Connect(ctx, sv.s.opts.CiscoProfile, sv.s.opts.CiscoUser, sv.s.opts.CiscoPassword)

	switch {
	case errors.Is(err, cisco.ErrAcquired):
		slog.Warn("another Cisco client has connection capability, will retry")
	case err != nil:
		if ctx.Err() != nil {
			return ciscoPollInterval
		}

		delay := sv.connectDelay
		sv.connectDelay = min(sv.connectDelay*2, ciscoMaxConnectDelay)

		slog.Error("failed to connect to cisco", "error", err, "retry_in", delay)

		return delay
	default:
		sv.connectDelay = ciscoPollInterval
		sv.connectedByUs = true
		sv.setConnected(true)
	}

	return ciscoPollInterval
}

func (sv *ciscoSupervisor) disablePF(ctx context.Context) {
	if sv.s.GetState().PFDisabled {
		return
	}

	slog.Info("disabling network packet filter")

	if err := cisco.DisablePF(ctx); err != nil {
		slog.Error("failed to disable network pf", "error", err)

		return
	}

	slog.Info("network packet filter disabled successfully")

	sv.s.setStatus(func(st *State) {
		st.PFDisabled = true
	})
}

// shutdown disconnects the VPN only if this process connected it, bounded by
// ciscoDisconnectTimeout so a wedged agent cannot block exit.
func (sv *ciscoSupervisor) shutdown(ctx context.Context) {
	sv.setConnected(false)

	if !sv.connectedByUs {
		return
	}

	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ciscoDisconnectTimeout)
	defer cancel()

	if err := cisco.Disconnect(dctx); err != nil {
		slog.Error("failed to disconnect cisco", "error", err)
	}
}
