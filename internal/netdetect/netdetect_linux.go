//go:build linux

package netdetect

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// DetectInterfaceForTarget returns the interface that routes to the target IP on Linux.
// Uses `ip route get <ip>` to query the routing table.
func DetectInterfaceForTarget(targetIP string) (string, error) {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", targetIP)
	}

	// For loopback addresses, return loopback interface
	if ip.IsLoopback() {
		return findLoopbackInterface()
	}

	// Run ip route command to get interface for target
	// Output format: "10.0.0.50 via 192.168.1.1 dev eth0 src 192.168.1.100 uid 1000"
	cmd := exec.Command("ip", "route", "get", targetIP)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ip route command failed: %w", err)
	}

	// Parse output looking for "dev" field
	fields := strings.Fields(string(output))
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}

	return "", fmt.Errorf("could not determine interface for target %s", targetIP)
}
