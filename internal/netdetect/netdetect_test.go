package netdetect

import (
	"strings"
	"testing"
)

func TestIsGUIDName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Windows GUID name",
			input:    `\Device\NPF_{12345678-1234-1234-1234-123456789ABC}`,
			expected: true,
		},
		{
			name:     "Standalone GUID - long enough with brace",
			input:    `{12345678-1234-1234-1234-123456789ABC}`,
			expected: true, // Length 38 > 20 and contains "{"
		},
		{
			name:     "Unix interface name",
			input:    "eth0",
			expected: false,
		},
		{
			name:     "macOS interface name",
			input:    "en0",
			expected: false,
		},
		{
			name:     "loopback",
			input:    "lo0",
			expected: false,
		},
		{
			name:     "Device prefix but too short",
			input:    `\Device\NPF_Eth`,
			expected: false, // Length 15, not > 20
		},
		{
			name:     "Device prefix exactly 20 chars",
			input:    `\Device\NPF_Etherne`,
			expected: false, // Length 19, not > 20
		},
		{
			name:     "Long Device prefix",
			input:    `\Device\NPF_EthernetAdapter`,
			expected: true, // Has Device prefix and length > 20
		},
		{
			name:     "Empty string",
			input:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isGUIDName(tt.input)
			if result != tt.expected {
				t.Errorf("isGUIDName(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetInterfaceDisplayName(t *testing.T) {
	tests := []struct {
		name     string
		info     InterfaceInfo
		expected string
	}{
		{
			name: "DisplayName different from Name",
			info: InterfaceInfo{
				Name:        "eth0",
				DisplayName: "Ethernet",
			},
			expected: "Ethernet",
		},
		{
			name: "DisplayName same as Name",
			info: InterfaceInfo{
				Name:        "eth0",
				DisplayName: "eth0",
			},
			expected: "eth0",
		},
		{
			name: "No DisplayName but has Description",
			info: InterfaceInfo{
				Name:        "eth0",
				DisplayName: "",
				Description: "Ethernet Adapter",
			},
			expected: "Ethernet Adapter",
		},
		{
			name: "Only Name available",
			info: InterfaceInfo{
				Name: "eth0",
			},
			expected: "eth0",
		},
		{
			name: "Description same as Name",
			info: InterfaceInfo{
				Name:        "eth0",
				Description: "eth0",
			},
			expected: "eth0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetInterfaceDisplayName(tt.info)
			if result != tt.expected {
				t.Errorf("GetInterfaceDisplayName() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestGetInterfaceAddressString(t *testing.T) {
	tests := []struct {
		name     string
		info     InterfaceInfo
		expected string
	}{
		{
			name:     "No addresses",
			info:     InterfaceInfo{Addresses: nil},
			expected: "no addresses",
		},
		{
			name:     "Empty addresses",
			info:     InterfaceInfo{Addresses: []string{}},
			expected: "no addresses",
		},
		{
			name:     "Single address",
			info:     InterfaceInfo{Addresses: []string{"192.168.1.100"}},
			expected: "192.168.1.100",
		},
		{
			name:     "Two addresses",
			info:     InterfaceInfo{Addresses: []string{"192.168.1.100", "fe80::1"}},
			expected: "192.168.1.100, fe80::1",
		},
		{
			name:     "Three addresses",
			info:     InterfaceInfo{Addresses: []string{"192.168.1.100", "fe80::1", "10.0.0.1"}},
			expected: "192.168.1.100, fe80::1, 10.0.0.1",
		},
		{
			name: "More than three addresses",
			info: InterfaceInfo{Addresses: []string{
				"192.168.1.100", "fe80::1", "10.0.0.1", "172.16.0.1", "8.8.8.8",
			}},
			expected: "192.168.1.100, fe80::1, 10.0.0.1 (+2 more)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetInterfaceAddressString(tt.info)
			if result != tt.expected {
				t.Errorf("GetInterfaceAddressString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestInterfaceInfo(t *testing.T) {
	info := InterfaceInfo{
		Name:        "eth0",
		DisplayName: "Ethernet",
		Description: "Primary network adapter",
		Addresses:   []string{"192.168.1.100", "fe80::1"},
		IsUp:        true,
		IsLoopback:  false,
	}

	if info.Name != "eth0" {
		t.Errorf("Name = %q, want %q", info.Name, "eth0")
	}
	if info.DisplayName != "Ethernet" {
		t.Errorf("DisplayName = %q, want %q", info.DisplayName, "Ethernet")
	}
	if !info.IsUp {
		t.Error("IsUp should be true")
	}
	if info.IsLoopback {
		t.Error("IsLoopback should be false")
	}
	if len(info.Addresses) != 2 {
		t.Errorf("Addresses count = %d, want 2", len(info.Addresses))
	}
}

func TestListInterfacesReturnsResults(t *testing.T) {
	// This test requires pcap access which may not be available in all environments
	// Skip if we can't access network interfaces
	interfaces, err := ListInterfaces()
	if err != nil {
		if strings.Contains(err.Error(), "permission") ||
			strings.Contains(err.Error(), "access") ||
			strings.Contains(err.Error(), "no devices") {
			t.Skip("Skipping: insufficient permissions or no pcap devices available")
		}
		t.Fatalf("ListInterfaces() error: %v", err)
	}

	// Should have at least loopback in most environments
	if len(interfaces) == 0 {
		t.Log("Warning: no interfaces returned, but no error")
	}

	// Verify interface fields are populated
	for _, iface := range interfaces {
		if iface.Name == "" {
			t.Error("Interface has empty Name")
		}
		// DisplayName should at least equal Name
		if iface.DisplayName == "" {
			t.Errorf("Interface %q has empty DisplayName", iface.Name)
		}
	}
}
