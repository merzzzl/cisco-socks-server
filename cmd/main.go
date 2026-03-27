package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/merzzzl/cisco-socks-server/internal/service"
	"github.com/merzzzl/cisco-socks-server/internal/utils/log"
	"github.com/merzzzl/cisco-socks-server/internal/utils/tui"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	level := slog.LevelInfo
	if cfg.debug {
		level = slog.LevelDebug
	}

	log.Setup(os.Stdout, level)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	srv := service.New(cfg.CiscoUser, cfg.CiscoPassword, cfg.CiscoProfile)

	if !cfg.noTUI {
		go func() {
			defer cancel()

			if err := tui.CreateTUI(srv, level); err != nil {
				slog.Error("failed to create tui", "error", err)
			}
		}()
	}

	if err := srv.Start(ctx); err != nil {
		slog.Error("service stopped", "error", err)
	}
}
