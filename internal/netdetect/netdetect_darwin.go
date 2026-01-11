//go:build darwin

package netdetect

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// DetectInterfaceForTarget returns the interface that routes to the target IP on macOS.
// Uses `route -n get <ip>` to query the routing table.
func DetectInterfaceForTarget(targetIP string) (string, error) {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", targetIP)
	}

	// For loopback addresses, return loopback interface
	if ip.IsLoopback() {
		return findLoopbackInterface()
	}

	// Run route command to get interface for target
	cmd := exec.Command("route", "-n", "get", targetIP)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("route command failed: %w", err)
	}

	// Parse output looking for "interface:" line
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "interface:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ifaceName := strings.TrimSpace(parts[1])
				if ifaceName != "" {
					return ifaceName, nil
				}
			}
		}
	}

	return "", fmt.Errorf("could not determine interface for target %s", targetIP)
}
