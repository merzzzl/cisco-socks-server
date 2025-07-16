package cisco

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

const (
	ciscoPath = "/opt/cisco/secureclient/bin/vpn"
)

const (
	ciscoStateConnected        = "Connected"
	ciscoStateDisconnected     = "Disconnected"
	ciscoNoticeReadyForConnect = "ReadyForConnect"
	ciscoUnknown               = "Unknown"
)

func CiscoConnect(profile, user, password string) error {
	var outBuf bytes.Buffer

	cmd := exec.Command(
		ciscoPath,
		"-s",
		"connect",
		profile,
	)

	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf

	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s\n%s\ny\n", user, password))

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("vpn connection error: %v\n", err)
	}

	output := outBuf.String()

	currentState := getLastCiscoState(string(output))
	if currentState != ciscoStateConnected {
		return fmt.Errorf("vpn connection not established: %s", string(output))
	}

	return nil
}

func IsCiscoConected() (bool, error) {
	output, err := Command("%s -s state", ciscoPath)
	if err != nil {
		return false, fmt.Errorf("vpn connection error: %v\n", err)
	}

	currentState := getLastCiscoState(string(output))

	return currentState == ciscoStateConnected, nil
}

func CiscoDisconnect() error {
	output, err := Command("%s -s disconnect", ciscoPath)
	if err != nil {
		return fmt.Errorf("vpn disconnection error: %v\n %s", err, output)
	}

	return nil
}

func getLastCiscoState(output string) string {
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
		switch states[len(states)-1] {
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

func Command(cmd string, agrs ...any) (string, error) {
	str := fmt.Sprintf(cmd, agrs...)

	out, err := exec.Command("sh", "-c", str).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w", str, err)
	}

	return string(out), nil
}
