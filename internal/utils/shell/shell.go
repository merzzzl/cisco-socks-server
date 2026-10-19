// Package shell is the single entry point for spawning external commands, so
// every shell-out is bound to a context and cancellation propagates.
package shell

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// Run executes name with args and returns its combined output. The output is
// returned even on failure: callers parse it or attach it to the error.
func Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}

	return string(out), nil
}

// Stream executes name with args and calls onLine for every stdout line until
// the command exits or ctx is cancelled. The tail of stderr is attached to the
// error, since long-running tools report why they quit only there.
func Stream(ctx context.Context, onLine func(string), name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)

	var stderr tailBuffer

	cmd.Stderr = &stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}

	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		onLine(sc.Text())
	}

	// a line too long for the scanner stops it; keep draining, or the
	// command blocks on a full pipe and Wait never returns
	_, _ = io.Copy(io.Discard, stdout)

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}

	return nil
}

const tailSize = 1024

// tailBuffer keeps the last tailSize bytes written to it.
type tailBuffer struct {
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - tailSize; over > 0 {
		t.buf = t.buf[over:]
	}

	return len(p), nil
}

func (t *tailBuffer) String() string {
	return string(t.buf)
}
