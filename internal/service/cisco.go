package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/merzzzl/cisco-socks-server/internal/utils/cisco"
)

func (s *Service) startCisco(ctx context.Context) error {
	maxRetries := 3
	ciscoReadyNotified := false

	defer func() {
		s.setStatus(func(st *State) {
			st.CiscoConnected = false
			st.PFDisabled = false
		})

		if err := cisco.Disconnect(context.Background()); err != nil {
			slog.Error("failed to disconnect cisco", "error", err)
		}
	}()

	for ctx.Err() == nil {
		connected, err := cisco.IsConnected(ctx)
		if err != nil {
			slog.Error("failed to get cisco state", "error", err)
		}

		if !connected && err == nil {
			s.setStatus(func(st *State) {
				st.CiscoConnected = false
				st.PFDisabled = false
			})

			if err := cisco.Connect(ctx, s.ciscoProfile, s.ciscoUser, s.ciscoPassword); errors.Is(err, cisco.ErrAcquired) {
				slog.Warn("another Cisco client is running, killing it")

				if killErr := cisco.KillUI(ctx); killErr != nil {
					slog.Error("failed to kill Cisco UI", "error", killErr)
				}
			} else if err != nil {
				if maxRetries == 0 {
					return fmt.Errorf("failed to connect to cisco: %w", err)
				}

				slog.Error("failed to connect to cisco", "error", err)

				maxRetries--
			} else {
				maxRetries = 3

				s.setStatus(func(st *State) {
					st.CiscoConnected = true
					st.PFDisabled = false
				})
			}
		}

		if connected && err == nil {
			s.setStatus(func(st *State) {
				st.CiscoConnected = true
			})
		}

		state := s.GetState()
		if state.CiscoConnected && !state.PFDisabled {
			if err := cisco.DisablePF(ctx); err != nil {
				slog.Error("failed to disable network pf", "error", err)
			} else {
				s.setStatus(func(st *State) {
					st.PFDisabled = true
				})
			}
		}

		if state.CiscoConnected && !ciscoReadyNotified {
			close(s.ciscoReady)
			ciscoReadyNotified = true
		}

		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}

	return nil
}
