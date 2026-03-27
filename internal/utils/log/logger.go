package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
)

func Setup(out io.Writer, level slog.Level) {
	slog.SetDefault(slog.New(&colorHandler{out: out, level: level}))
}

func colorize(s string, c int) string {
	return fmt.Sprintf("\033[38;5;%dm%s\033[0m", c, s)
}

type colorHandler struct {
	out   io.Writer
	level slog.Level
	attrs []slog.Attr
	group string
}

func (h *colorHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level
}

func (h *colorHandler) Handle(_ context.Context, r slog.Record) error {
	ts := colorize(r.Time.Format("15:04:05"), 7)
	lvl := formatLevel(r.Level)
	msg := r.Message

	var errStr string

	for _, a := range h.attrs {
		if a.Key == "error" {
			errStr = colorize(a.Value.String(), 1)
		}
	}

	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "error" {
			errStr = colorize(a.Value.String(), 1)
		}

		return true
	})

	if errStr != "" {
		_, err := fmt.Fprintf(h.out, "%s %s %s %s\n", ts, lvl, msg, errStr)
		return err
	}

	_, err := fmt.Fprintf(h.out, "%s %s %s\n", ts, lvl, msg)

	return err
}

func (h *colorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &colorHandler{
		out:   h.out,
		level: h.level,
		attrs: append(h.attrs, attrs...),
		group: h.group,
	}
}

func (h *colorHandler) WithGroup(name string) slog.Handler {
	return &colorHandler{
		out:   h.out,
		level: h.level,
		attrs: h.attrs,
		group: name,
	}
}

func formatLevel(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return colorize("ERR", 9)
	case l >= slog.LevelWarn:
		return colorize("WRN", 11)
	case l >= slog.LevelInfo:
		return colorize("INF", 10)
	default:
		return colorize("DBG", 10)
	}
}
