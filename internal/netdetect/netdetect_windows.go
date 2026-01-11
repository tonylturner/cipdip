//go:build windows

package netdetect

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/gopacket/pcap"
)

// DetectInterfaceForTarget returns the interface that routes to the target IP on Windows.
// Uses PowerShell's Find-NetRoute to query the routing table.
func DetectInterfaceForTarget(targetIP string) (string, error) {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", targetIP)
	}

	// For loopback addresses, return loopback interface
	if ip.IsLoopback() {
		return findLoopbackInterface()
	}

	// Try PowerShell first (more reliable)
	ifaceName, err := detectViaPowerShell(targetIP)
	if err == nil && ifaceName != "" {
		return ifaceName, nil
	}

	// Fallback to route print parsing
	return detectViaRoute(targetIP)
}

// detectViaPowerShell uses PowerShell's Find-NetRoute cmdlet.
func detectViaPowerShell(targetIP string) (string, error) {
	// PowerShell command to get interface index for route
	psCmd := fmt.Sprintf(`(Find-NetRoute -RemoteIPAddress '%s' | Select-Object -First 1).InterfaceIndex`, targetIP)
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("powershell command failed: %w", err)
	}

	// Parse interface index
	indexStr := strings.TrimSpace(string(output))
	ifaceIndex, err := strconv.Atoi(indexStr)
	if err != nil {
		return "", fmt.Errorf("invalid interface index: %s", indexStr)
	}

	// Map interface index to pcap interface name
	return mapIndexToPcapName(ifaceIndex)
}

// detectViaRoute uses the route print command as fallback.
func detectViaRoute(targetIP string) (string, error) {
	// Parse target IP to determine network
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return "", fmt.Errorf("invalid IP: %s", targetIP)
	}

	cmd := exec.Command("route", "print")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("route print failed: %w", err)
	}

	// Look for the default gateway line and extract interface index
	// Format varies but typically includes interface column
	lines := strings.Split(string(output), "\n")

	// Try to find a matching route or default route
	var defaultIfaceIdx int
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and headers
		if line == "" || strings.HasPrefix(line, "=") || strings.HasPrefix(line, "Interface") {
			continue
		}

		// Look for 0.0.0.0 default route
		if strings.Contains(line, "0.0.0.0") && !strings.HasPrefix(line, "0.0.0.0") {
			// This is likely a route entry
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				// Last field is often the interface
				for _, field := range fields {
					if idx, err := strconv.Atoi(field); err == nil && idx > 0 && idx < 100 {
						defaultIfaceIdx = idx
					}
				}
			}
		}
	}

	if defaultIfaceIdx > 0 {
		return mapIndexToPcapName(defaultIfaceIdx)
	}

	return "", fmt.Errorf("could not determine interface for target %s", targetIP)
}

// mapIndexToPcapName maps a Windows interface index to the pcap interface name.
func mapIndexToPcapName(ifaceIndex int) (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("find pcap devices: %w", err)
	}

	// On Windows, pcap interface names are GUIDs like:
	// \Device\NPF_{GUID}
	// We need to match by the interface index

	// First, get interface info from Go's net package
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("list interfaces: %w", err)
	}

	// Find the interface with matching index
	var targetIface *net.Interface
	for i := range ifaces {
		if ifaces[i].Index == ifaceIndex {
			targetIface = &ifaces[i]
			break
		}
	}

	if targetIface == nil {
		return "", fmt.Errorf("no interface found with index %d", ifaceIndex)
	}

	// Now find the matching pcap device
	// pcap device names on Windows contain the GUID which we can match
	// against the interface name or description
	for _, device := range devices {
		// Check if description matches
		if strings.Contains(strings.ToLower(device.Description), strings.ToLower(targetIface.Name)) {
			return device.Name, nil
		}

		// Check addresses match
		addrs, _ := targetIface.Addrs()
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			for _, devAddr := range device.Addresses {
				if devAddr.IP != nil && devAddr.IP.Equal(ipNet.IP) {
					return device.Name, nil
				}
			}
		}
	}

	// Try matching by GUID extraction from interface name
	// Windows interface names sometimes contain the same GUID as pcap device names
	guidPattern := regexp.MustCompile(`\{[0-9A-Fa-f-]+\}`)
	targetGUID := guidPattern.FindString(targetIface.Name)
	if targetGUID != "" {
		for _, device := range devices {
			if strings.Contains(device.Name, targetGUID) {
				return device.Name, nil
			}
		}
	}

	// Last resort: return the first non-loopback device
	for _, device := range devices {
		isLoopback := false
		for _, addr := range device.Addresses {
			if addr.IP != nil && addr.IP.IsLoopback() {
				isLoopback = true
				break
			}
		}
		if !isLoopback && len(device.Addresses) > 0 {
			return device.Name, nil
		}
	}

	return "", fmt.Errorf("could not map interface index %d to pcap device", ifaceIndex)
}
