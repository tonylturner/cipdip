package netdetect

import (
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"
)

// InterfaceInfo represents a network interface with its properties.
type InterfaceInfo struct {
	Name        string   // System interface name (e.g., "en0", "eth0", "Ethernet")
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
		}

		interfaces = append(interfaces, info)
	}

	return interfaces, nil
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
	if info.Description != "" && info.Description != info.Name {
		return fmt.Sprintf("%s (%s)", info.Name, info.Description)
	}
	return info.Name
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
