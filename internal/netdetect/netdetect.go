package netdetect

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket/pcap"
)

// InterfaceInfo represents a network interface with its properties.
type InterfaceInfo struct {
	Name        string   // System interface name (e.g., "en0", "eth0", "\Device\NPF_{GUID}")
	DisplayName string   // Human-readable name for UI display (e.g., "en0", "eth0", "Ethernet")
	Description string   // Human-readable description
	Addresses   []string // IP addresses assigned to this interface
	IsUp        bool     // Whether the interface is up
	IsLoopback  bool     // Whether this is a loopback interface
}

// ListInterfaces returns all available network interfaces suitable for packet capture.
func ListInterfaces() ([]InterfaceInfo, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("find network devices: %w", err)
	}

	var interfaces []InterfaceInfo
	for _, device := range devices {
		info := InterfaceInfo{
			Name:        device.Name,
			DisplayName: device.Name, // Default to system name
			Description: device.Description,
		}

		// Collect addresses and check for loopback
		for _, addr := range device.Addresses {
			if addr.IP != nil {
				info.Addresses = append(info.Addresses, addr.IP.String())
				if addr.IP.IsLoopback() {
					info.IsLoopback = true
				}
			}
		}

		// Check if interface is up using net package
		iface, err := net.InterfaceByName(device.Name)
		if err == nil {
			info.IsUp = (iface.Flags & net.FlagUp) != 0
			// On some systems, net.Interface has a better name
			if iface.Name != "" && iface.Name != device.Name {
				info.DisplayName = iface.Name
			}
		}

		// Use Description as DisplayName if it's more human-readable
		// This is especially useful on Windows where Name is a GUID
		if info.Description != "" && isGUIDName(info.Name) {
			info.DisplayName = info.Description
		}

		interfaces = append(interfaces, info)
	}

	return interfaces, nil
}

// isGUIDName checks if a name looks like a Windows GUID-style interface name.
func isGUIDName(name string) bool {
	// Windows pcap names look like: \Device\NPF_{GUID}
	return len(name) > 20 && (strings.Contains(name, "{") || strings.HasPrefix(name, "\\Device\\"))
}

// DetectInterfaceForListen returns the interface bound to the given listen IP.
// For 0.0.0.0, returns the first non-loopback interface.
// For 127.0.0.1, returns the loopback interface.
func DetectInterfaceForListen(listenIP string) (string, error) {
	ip := net.ParseIP(listenIP)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", listenIP)
	}

	// If listening on all interfaces, pick first non-loopback
	if ip.IsUnspecified() {
		interfaces, err := ListInterfaces()
		if err != nil {
			return "", err
		}
		for _, iface := range interfaces {
			if !iface.IsLoopback && len(iface.Addresses) > 0 {
				return iface.Name, nil
			}
		}
		return "", fmt.Errorf("no non-loopback interfaces found")
	}

	// If listening on loopback, return loopback interface
	if ip.IsLoopback() {
		return findLoopbackInterface()
	}

	// Find interface with the specific IP
	interfaces, err := ListInterfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		for _, addr := range iface.Addresses {
			if addr == listenIP {
				return iface.Name, nil
			}
		}
	}

	return "", fmt.Errorf("no interface found with IP %s", listenIP)
}

// findLoopbackInterface returns the name of the loopback interface.
func findLoopbackInterface() (string, error) {
	interfaces, err := ListInterfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if iface.IsLoopback {
			return iface.Name, nil
		}
	}

	// Fallback to common loopback names
	commonNames := []string{"lo0", "lo", "Loopback Pseudo-Interface 1"}
	for _, name := range commonNames {
		for _, iface := range interfaces {
			if iface.Name == name {
				return name, nil
			}
		}
	}

	return "", fmt.Errorf("no loopback interface found")
}

// GetInterfaceDisplayName returns a display-friendly name for an interface.
func GetInterfaceDisplayName(info InterfaceInfo) string {
	if info.DisplayName != "" && info.DisplayName != info.Name {
		return info.DisplayName
	}
	if info.Description != "" && info.Description != info.Name {
		return info.Description
	}
	return info.Name
}

// GetDisplayNameForInterface looks up the display name for an interface by its system name.
func GetDisplayNameForInterface(name string) string {
	interfaces, err := ListInterfaces()
	if err != nil {
		return name
	}
	for _, iface := range interfaces {
		if iface.Name == name {
			if iface.DisplayName != "" {
				return iface.DisplayName
			}
			return iface.Name
		}
	}
	return name
}

// GetInterfaceAddressString returns a comma-separated list of interface addresses.
func GetInterfaceAddressString(info InterfaceInfo) string {
	if len(info.Addresses) == 0 {
		return "no addresses"
	}
	result := info.Addresses[0]
	for i := 1; i < len(info.Addresses) && i < 3; i++ {
		result += ", " + info.Addresses[i]
	}
	if len(info.Addresses) > 3 {
		result += fmt.Sprintf(" (+%d more)", len(info.Addresses)-3)
	}
	return result
}
