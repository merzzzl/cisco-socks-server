package cisco

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const ciscoPath = "/opt/cisco/secureclient/bin/vpn"

const (
	stateConnected    = "Connected"
	stateDisconnected = "Disconnected"
	stateUnknown      = "Unknown"
)

var (
	ErrNotConnected = errors.New("vpn connection not established")
	ErrAcquired     = errors.New("connect capability is unavailable, another Cisco application acquired it")
)

func Connect(ctx context.Context, profile, user, password string) error {
	cmd := exec.CommandContext(ctx, ciscoPath, "-s", "connect", profile)
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s\n%s\ny\n", user, password))

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("vpn connection error: %w", err)
	}

	output := string(out)

	if hasAcquiredError(output) {
		return ErrAcquired
	}

	if parseState(output) != stateConnected {
		return fmt.Errorf("%w: %s", ErrNotConnected, output)
	}

	return nil
}

func IsConnected(ctx context.Context) (bool, error) {
	out, err := run(ctx, ciscoPath, "-s", "state")
	if err != nil {
		return false, fmt.Errorf("vpn state check error: %w", err)
	}

	return parseState(out) == stateConnected, nil
}

func Disconnect(ctx context.Context) error {
	_, err := run(ctx, ciscoPath, "-s", "disconnect")
	if err != nil {
		return fmt.Errorf("vpn disconnection error: %w", err)
	}

	return nil
}

func DisablePF(ctx context.Context) error {
	_, err := run(ctx, "pfctl", "-d")

	return err
}

func KillUI(ctx context.Context) error {
	_, err := run(ctx, "killall", "Cisco Secure Client")

	return err
}

func parseState(output string) string {
	var last string

	for _, line := range strings.Split(output, "\n") {
		if state, ok := strings.CutPrefix(strings.TrimSpace(line), ">> state: "); ok {
			last = strings.SplitN(state, " ", 2)[0]
		}
	}

	switch last {
	case "Подключено", "Connected":
		return stateConnected
	case "Отключено", "Disconnected":
		return stateDisconnected
	default:
		return stateUnknown
	}
}

func hasAcquiredError(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ">> error:") && strings.Contains(line, "Connect capability is unavailable") {
			return true
		}
	}

	return false
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}

	return string(out), nil
}
