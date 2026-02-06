package cisco

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const (
	ciscoPath = "/opt/cisco/secureclient/bin/vpn"
)

const (
	ciscoStateConnected    = "Connected"
	ciscoStateDisconnected = "Disconnected"
	ciscoUnknown           = "Unknown"
)

var ErrNotConnected = errors.New("vpn connection not established")

func Connect(profile, user, password string) error {
	cmd := exec.Command(
		ciscoPath,
		"-s",
		"connect",
		profile,
	)

	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s\n%s\ny\n", user, password))

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("vpn connection error: %w", err)
	}

	currentState := getState(string(out))
	if currentState != ciscoStateConnected {
		return fmt.Errorf("%w: %s", ErrNotConnected, string(out))
	}

	return nil
}

func IsConected() (bool, error) {
	output, err := Command("%s -s state", ciscoPath)
	if err != nil {
		return false, fmt.Errorf("vpn connection error: %w", err)
	}

	currentState := getState(output)

	return currentState == ciscoStateConnected, nil
}

func Disconnect() error {
	output, err := Command("%s -s disconnect", ciscoPath)
	if err != nil {
		return fmt.Errorf("vpn disconnection error: %w\n %s", err, output)
	}

	return nil
}

func getState(output string) string {
	var states []string

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, ">> state: ") {
			state := strings.TrimPrefix(line, ">> state: ")
			states = append(states, state)
		}
	}

	if len(states) > 0 {
		last := states[len(states)-1]
		last = strings.Split(last, " ")[0]

		switch last {
		case "Подключено", "Connected":
			return ciscoStateConnected
		case "Отключено", "Disconnected":
			return ciscoStateDisconnected
		default:
			return ciscoUnknown
		}
	}

	return ciscoUnknown
}

func DisablePF() error {
	_, _ = Command("pfctl -d")

	return nil
}

func Command(command string, agrs ...any) (string, error) {
	str := fmt.Sprintf(command, agrs...)
	cmd := exec.Command("sh", "-c", str)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w", str, err)
	}

	return string(out), nil
}
