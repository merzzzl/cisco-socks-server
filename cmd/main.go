package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/merzzzl/cisco-socks-server/internal/service"
	"github.com/merzzzl/cisco-socks-server/internal/utils/log"
	"github.com/merzzzl/cisco-socks-server/internal/utils/tui"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	level := slog.LevelInfo
	if cfg.debug {
		level = slog.LevelDebug
	}

	log.Setup(os.Stdout, level)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	srv := service.New(cfg.serviceOptions())

	// buffered: the TUI goroutine must not block if run returns early
	tuiErr := make(chan error, 1)

	if cfg.noTUI {
		tuiErr <- nil
	} else {
		go func() {
			defer cancel()

			tuiErr <- tui.CreateTUI(ctx, srv, level)
		}()
	}

	err = srv.Start(ctx)

	// the TUI must restore the terminal before anything is printed or the
	// process exits; afterwards route logs back to stdout so the final
	// error is visible. A TUI failure is reported here rather than logged
	// from the goroutine: at that point slog still feeds the dead TUI.
	cancel()

	if terr := <-tuiErr; terr != nil && err == nil {
		err = fmt.Errorf("tui: %w", terr)
	}

	log.Setup(os.Stdout, level)

	return err
}
