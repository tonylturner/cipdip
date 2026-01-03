package cipclient

import (
	"net"
	"testing"
)

var enipOrderDiscovery = currentENIPByteOrder()

// TestBuildListIdentityODVACompliance validates ListIdentity request against ODVA spec
// ODVA EtherNet/IP Encapsulation Protocol Specification:
// - Command: 0x0063 (ListIdentity)
// - Length: 0 (no data field)
// - Session ID: 0 (no session required for discovery)
// - Status: 0 (request)
// - Sender Context: 8 bytes (client identifier)
func TestBuildListIdentityODVACompliance(t *testing.T) {
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	packet := BuildListIdentity(senderContext)

	encap, err := DecodeENIP(packet)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	// Validate command code per ODVA spec
	if encap.Command != 0x0063 {
		t.Errorf("Command: got 0x%04X, want 0x0063 (ListIdentity per ODVA spec)", encap.Command)
	}

	// Validate length per ODVA spec (must be 0)
	if encap.Length != 0 {
		t.Errorf("Length: got %d, want 0 (no data per ODVA spec)", encap.Length)
	}

	// Validate session ID per ODVA spec (must be 0)
	if encap.SessionID != 0 {
		t.Errorf("Session ID: got 0x%08X, want 0x00000000 (no session required per ODVA spec)", encap.SessionID)
	}

	// Validate status per ODVA spec (must be 0 for request)
	if encap.Status != 0 {
		t.Errorf("Status: got 0x%08X, want 0x00000000 (request per ODVA spec)", encap.Status)
	}

	// Validate sender context per ODVA spec (must be echoed)
	if encap.SenderContext != senderContext {
		t.Error("Sender context must match per ODVA spec")
	}

	// Validate no data field per ODVA spec
	if len(encap.Data) != 0 {
		t.Errorf("Data length: got %d, want 0 (no data per ODVA spec)", len(encap.Data))
	}
}

// TestParseListIdentityResponseODVACompliance validates ListIdentity response parsing against ODVA spec
// ODVA EtherNet/IP Encapsulation Protocol Specification:
// ListIdentity response structure:
// - ENIP Header (24 bytes)
// - Socket Address (16 bytes)
// - Vendor ID (2 bytes, big-endian)
// - Product Type (2 bytes)
// - Product Code (2 bytes, big-endian)
// - Revision (2 bytes, major.minor)
// - Status (2 bytes)
// - Serial Number (4 bytes, big-endian)
// - Product Name Length (1 byte)
// - Product Name (variable, 0-255 bytes)
// - State (1 byte)
func TestParseListIdentityResponseODVACompliance(t *testing.T) {
	// Build a valid ListIdentity response per ODVA spec
	response := make([]byte, 24+34+10) // ENIP header + minimum data + product name

	// ENIP Header (24 bytes)
	enipOrderDiscovery.PutUint16(response[0:2], ENIPCommandListIdentity) // Command
	enipOrderDiscovery.PutUint16(response[2:4], 34+10)                   // Length (data only)
	enipOrderDiscovery.PutUint32(response[4:8], 0)                       // Session ID (0 for ListIdentity)
	enipOrderDiscovery.PutUint32(response[8:12], ENIPStatusSuccess)      // Status
	// Sender Context (8 bytes) - skip, not critical for parsing
	enipOrderDiscovery.PutUint32(response[20:24], 0) // Options

	// ListIdentity Data (starting at offset 24)
	offset := 24

	// Socket Address (16 bytes) - IPv4 address + port + zero padding
	// IPv4: 192.168.1.100, Port: 44818
	response[offset] = 0x02   // Address family: IPv4 = 2
	response[offset+2] = 0xAF // Port high byte (44818 = 0xAF12)
	response[offset+3] = 0x12 // Port low byte
	response[offset+4] = 192  // IP: 192.168.1.100
	response[offset+5] = 168
	response[offset+6] = 1
	response[offset+7] = 100
	offset += 16

	// Vendor ID (2 bytes, big-endian) - e.g., 1 (Rockwell)
	enipOrderDiscovery.PutUint16(response[offset:offset+2], 1)
	vendorID := uint16(1)
	offset += 2

	// Product Type (2 bytes) - skip
	offset += 2

	// Product Code (2 bytes, big-endian) - e.g., 100
	enipOrderDiscovery.PutUint16(response[offset:offset+2], 100)
	productID := uint16(100)
	offset += 2

	// Revision (2 bytes) - skip
	offset += 2

	// Status (2 bytes) - skip
	offset += 2

	// Serial Number (4 bytes, big-endian) - e.g., 12345
	enipOrderDiscovery.PutUint32(response[offset:offset+4], 12345)
	serialNumber := uint32(12345)
	offset += 4

	// Product Name Length (1 byte)
	productName := "Test Device"
	nameLen := len(productName)
	response[offset] = byte(nameLen)
	offset++

	// Product Name (variable)
	copy(response[offset:offset+nameLen], productName)
	offset += nameLen

	// State (1 byte) - e.g., 0 (configured)
	response[offset] = 0
	state := uint8(0)

	// Parse response
	device, err := parseListIdentityResponse(response)
	if err != nil {
		t.Fatalf("parseListIdentityResponse failed: %v", err)
	}

	// Validate parsed fields per ODVA spec
	if device.VendorID != vendorID {
		t.Errorf("Vendor ID: got %d, want %d (per ODVA spec)", device.VendorID, vendorID)
	}

	if device.ProductID != productID {
		t.Errorf("Product ID: got %d, want %d (per ODVA spec)", device.ProductID, productID)
	}

	if device.SerialNumber != serialNumber {
		t.Errorf("Serial Number: got %d, want %d (per ODVA spec)", device.SerialNumber, serialNumber)
	}

	if device.ProductName != productName {
		t.Errorf("Product Name: got '%s', want '%s' (per ODVA spec)", device.ProductName, productName)
	}

	if device.State != state {
		t.Errorf("State: got 0x%02X, want 0x%02X (per ODVA spec)", device.State, state)
	}
}

// TestParseListIdentityResponseMinimalODVA validates minimal valid response per ODVA spec
// ODVA spec minimum: 24 (ENIP header) + 34 (minimum ListIdentity data) = 58 bytes
func TestParseListIdentityResponseMinimalODVA(t *testing.T) {
	// Build minimal valid response (58 bytes total)
	response := make([]byte, 58)

	// ENIP Header
	enipOrderDiscovery.PutUint16(response[0:2], ENIPCommandListIdentity)
	enipOrderDiscovery.PutUint16(response[2:4], 34) // Minimum data length
	enipOrderDiscovery.PutUint32(response[4:8], 0)
	enipOrderDiscovery.PutUint32(response[8:12], ENIPStatusSuccess)

	// ListIdentity Data (34 bytes minimum)
	offset := 24
	offset += 16                                               // Socket Address
	enipOrderDiscovery.PutUint16(response[offset:offset+2], 1) // Vendor ID
	offset += 2
	offset += 2                                                  // Product Type
	enipOrderDiscovery.PutUint16(response[offset:offset+2], 100) // Product Code
	offset += 2
	offset += 2                                                    // Revision
	offset += 2                                                    // Status
	enipOrderDiscovery.PutUint32(response[offset:offset+4], 12345) // Serial Number
	offset += 4
	response[offset] = 0 // Product Name Length (0 = no name)
	offset++
	response[offset] = 0 // State

	// Should parse successfully
	device, err := parseListIdentityResponse(response)
	if err != nil {
		t.Fatalf("parseListIdentityResponse failed for minimal response: %v", err)
	}

	// Validate minimum fields
	if device.VendorID == 0 {
		t.Error("Vendor ID should be parsed")
	}

	if device.ProductName != "" {
		t.Error("Product name should be empty for length 0 per ODVA spec")
	}
}

// TestParseListIdentityResponseTooShort validates error handling for short responses per ODVA spec
func TestParseListIdentityResponseTooShortODVA(t *testing.T) {
	// Test with various short lengths
	tests := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"too short for ENIP header", 23},
		{"exactly ENIP header", 24},
		{"ENIP header + partial data", 50},
		{"ENIP header + minimum data - 1", 57},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.size)
			_, err := parseListIdentityResponse(data)
			if err == nil {
				t.Errorf("parseListIdentityResponse should fail for %d bytes (minimum 58 per ODVA spec)", tt.size)
			}
		})
	}
}

// TestParseListIdentityResponseInvalidCommand validates error handling for wrong command per ODVA spec
func TestParseListIdentityResponseInvalidCommandODVA(t *testing.T) {
	response := make([]byte, 58)

	// Set wrong command code
	enipOrderDiscovery.PutUint16(response[0:2], ENIPCommandRegisterSession) // Wrong command
	enipOrderDiscovery.PutUint16(response[2:4], 34)
	enipOrderDiscovery.PutUint32(response[4:8], 0)
	enipOrderDiscovery.PutUint32(response[8:12], ENIPStatusSuccess)

	// Fill minimum data
	offset := 24
	offset += 16 // Socket Address
	enipOrderDiscovery.PutUint16(response[offset:offset+2], 1)
	offset += 2
	offset += 2
	enipOrderDiscovery.PutUint32(response[offset:offset+4], 12345)
	offset += 4
	response[offset] = 0
	offset++
	response[offset] = 0

	_, err := parseListIdentityResponse(response)
	if err == nil {
		t.Error("parseListIdentityResponse should fail for wrong command per ODVA spec")
	}
}

// TestParseListIdentityResponseErrorStatus validates error status handling per ODVA spec
func TestParseListIdentityResponseErrorStatusODVA(t *testing.T) {
	response := make([]byte, 58)

	// Set error status
	enipOrderDiscovery.PutUint16(response[0:2], ENIPCommandListIdentity)
	enipOrderDiscovery.PutUint16(response[2:4], 34)
	enipOrderDiscovery.PutUint32(response[4:8], 0)
	enipOrderDiscovery.PutUint32(response[8:12], ENIPStatusInvalidCommand) // Error status

	// Fill minimum data
	offset := 24
	offset += 16
	enipOrderDiscovery.PutUint16(response[offset:offset+2], 1)
	offset += 2
	offset += 2
	enipOrderDiscovery.PutUint32(response[offset:offset+4], 12345)
	offset += 4
	response[offset] = 0
	offset++
	response[offset] = 0

	_, err := parseListIdentityResponse(response)
	if err == nil {
		t.Error("parseListIdentityResponse should fail for error status per ODVA spec")
	}
}

// TestParseListIdentityResponseProductNameLength validates product name length handling per ODVA spec
// ODVA spec: Product Name Length is 1 byte (0-255), name is variable length
func TestParseListIdentityResponseProductNameLengthODVA(t *testing.T) {
	tests := []struct {
		name     string
		nameLen  int
		expected string
	}{
		{"zero length", 0, ""},
		{"short name", 5, "Test"},
		{"medium name", 20, "Test Device Name"},
		{"max length", 255, string(make([]byte, 255))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build response with specified name length
			totalLen := 24 + 34 + tt.nameLen
			response := make([]byte, totalLen)

			// ENIP Header
			enipOrderDiscovery.PutUint16(response[0:2], ENIPCommandListIdentity)
			enipOrderDiscovery.PutUint16(response[2:4], uint16(34+tt.nameLen))
			enipOrderDiscovery.PutUint32(response[4:8], 0)
			enipOrderDiscovery.PutUint32(response[8:12], ENIPStatusSuccess)

			// ListIdentity Data
			offset := 24
			offset += 16 // Socket Address
			enipOrderDiscovery.PutUint16(response[offset:offset+2], 1)
			offset += 2
			offset += 2
			enipOrderDiscovery.PutUint16(response[offset:offset+2], 100)
			offset += 2
			offset += 2
			offset += 2
			enipOrderDiscovery.PutUint32(response[offset:offset+4], 12345)
			offset += 4
			response[offset] = byte(tt.nameLen)
			offset++
			if tt.nameLen > 0 {
				copy(response[offset:offset+tt.nameLen], tt.expected)
				offset += tt.nameLen
			}
			response[offset] = 0

			device, err := parseListIdentityResponse(response)
			if err != nil {
				t.Fatalf("parseListIdentityResponse failed: %v", err)
			}

			if len(device.ProductName) != tt.nameLen {
				t.Errorf("Product name length: got %d, want %d (per ODVA spec)", len(device.ProductName), tt.nameLen)
			}
		})
	}
}

// TestBroadcastAddressCalculation validates broadcast address calculation per network standards
func TestBroadcastAddressCalculation(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		mask      string
		broadcast string
	}{
		{"Class C", "192.168.1.100", "255.255.255.0", "192.168.1.255"},
		{"Class B", "172.16.0.1", "255.255.0.0", "172.16.255.255"},
		{"Class A", "10.0.0.1", "255.0.0.0", "10.255.255.255"},
		{"Subnet", "192.168.1.100", "255.255.255.192", "192.168.1.127"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip).To4()
			mask := net.IPMask(net.ParseIP(tt.mask).To4())
			expected := net.ParseIP(tt.broadcast).To4()

			// Calculate broadcast
			broadcast := make(net.IP, 4)
			for i := range ip {
				broadcast[i] = ip[i] | ^mask[i]
			}

			if !broadcast.Equal(expected) {
				t.Errorf("Broadcast: got %s, want %s", broadcast, expected)
			}
		})
	}
}
