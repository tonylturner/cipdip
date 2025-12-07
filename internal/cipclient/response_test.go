package cipclient

// Response structure validation tests

import (
	"testing"
)

// TestCIPResponseStructure validates CIP response structure
func TestCIPResponseStructure(t *testing.T) {
	// Test response with success status
	// CIP response structure: [service_code, status, ...payload]
	responseData := []byte{
		0x0E, // Service code: Get_Attribute_Single (echoed from request)
		0x00, // General status (success)
		0x01, 0x02, 0x03, 0x04, // Payload data
	}

	path := CIPPath{
		Class:     0x04,
		Instance:  0x65,
		Attribute: 0x03,
	}

	resp, err := DecodeCIPResponse(responseData, path)
	if err != nil {
		t.Fatalf("DecodeCIPResponse failed: %v", err)
	}

	// Verify response structure
	if resp.Status != 0x00 {
		t.Errorf("Status: got 0x%02X, want 0x00", resp.Status)
	}

	if len(resp.Payload) != 4 {
		t.Errorf("Payload length: got %d, want 4", len(resp.Payload))
	}

	// Verify payload content
	expectedPayload := []byte{0x01, 0x02, 0x03, 0x04}
	for i, b := range resp.Payload {
		if b != expectedPayload[i] {
			t.Errorf("Payload[%d]: got 0x%02X, want 0x%02X", i, b, expectedPayload[i])
		}
	}
}

// TestCIPResponseWithError validates CIP error response structure
func TestCIPResponseWithError(t *testing.T) {
	// Test response with error status
	// CIP response structure: [service_code, status, extended_status_size, ...extended_status]
	responseData := []byte{
		0x0E, // Service code: Get_Attribute_Single (echoed from request)
		0x01, // General status (error)
		0x05, // Extended status size
		0x01, 0x02, 0x03, 0x04, 0x05, // Extended status bytes
	}

	path := CIPPath{
		Class:     0x04,
		Instance:  0x65,
		Attribute: 0x03,
	}

	resp, err := DecodeCIPResponse(responseData, path)
	if err != nil {
		t.Fatalf("DecodeCIPResponse failed: %v", err)
	}

	// Verify error status
	if resp.Status != 0x01 {
		t.Errorf("Status: got 0x%02X, want 0x01", resp.Status)
	}

	// Extended status should be present (implementation takes remaining bytes as ext status)
	if len(resp.ExtStatus) == 0 {
		t.Error("Extended status should be present for error responses")
	}
}

// TestForwardOpenResponseStructure validates ForwardOpen response structure
func TestForwardOpenResponseStructure(t *testing.T) {
	// ForwardOpen response structure:
	// - General status (1 byte)
	// - Additional status size (1 byte, if status != 0)
	// - Additional status (variable)
	// - O->T connection ID (4 bytes)
	// - T->O connection ID (4 bytes)
	// - Connection serial number (2 bytes)
	// - Originator vendor ID (2 bytes)
	// - Originator serial number (4 bytes)
	// - Connection timeout multiplier (1 byte)

	responseData := []byte{
		0x00, // General status (success)
		0x00, // Additional status size (0 for success)
		0x12, 0x34, 0x56, 0x78, // O->T connection ID
		0x9A, 0xBC, 0xDE, 0xF0, // T->O connection ID
		0x00, 0x01, // Connection serial number
		0x00, 0x01, // Originator vendor ID
		0x00, 0x00, 0x00, 0x01, // Originator serial number
		0x01, // Connection timeout multiplier
	}

	connID, oToTID, tToOID, err := ParseForwardOpenResponse(responseData)
	if err != nil {
		t.Fatalf("ParseForwardOpenResponse failed: %v", err)
	}

	// Verify connection IDs
	expectedOToTID := uint32(0x12345678)
	expectedTToOID := uint32(0x9ABCDEF0)

	if oToTID != expectedOToTID {
		t.Errorf("O->T connection ID: got 0x%08X, want 0x%08X", oToTID, expectedOToTID)
	}

	if tToOID != expectedTToOID {
		t.Errorf("T->O connection ID: got 0x%08X, want 0x%08X", tToOID, expectedTToOID)
	}

	// Connection ID should be O->T ID
	if connID != oToTID {
		t.Errorf("Connection ID: got 0x%08X, want 0x%08X (O->T ID)", connID, oToTID)
	}
}

// TestForwardOpenResponseWithError validates ForwardOpen error response
func TestForwardOpenResponseWithError(t *testing.T) {
	// Error response with additional status
	responseData := []byte{
		0x01, // General status (error)
		0x02, // Additional status size
		0x05, 0x06, // Additional status
	}

	_, _, _, err := ParseForwardOpenResponse(responseData)
	if err == nil {
		t.Error("ParseForwardOpenResponse should return error for error status")
	}
}

// TestForwardCloseResponseStructure validates ForwardClose response structure
func TestForwardCloseResponseStructure(t *testing.T) {
	// ForwardClose response is simple: just status
	responseData := []byte{
		0x00, // General status (success)
	}

	err := ParseForwardCloseResponse(responseData)
	if err != nil {
		t.Errorf("ParseForwardCloseResponse failed: %v", err)
	}
}

// TestForwardCloseResponseWithError validates ForwardClose error response
func TestForwardCloseResponseWithError(t *testing.T) {
	responseData := []byte{
		0x01, // General status (error)
	}

	err := ParseForwardCloseResponse(responseData)
	if err == nil {
		t.Error("ParseForwardCloseResponse should return error for error status")
	}
}

// TestCIPStatusCodes validates CIP status code values
func TestCIPStatusCodes(t *testing.T) {
	// Common CIP status codes per ODVA spec:
	statusCodes := map[uint8]string{
		0x00: "Success",
		0x01: "General error",
		0x02: "Resource unavailable",
		0x03: "Invalid parameter value",
		0x04: "Path segment error",
		0x05: "Path destination unknown",
		0x06: "Partial transfer",
		0x07: "Connection lost",
		0x08: "Service not supported",
		0x09: "Invalid attribute value",
		0x0A: "Attribute list error",
		0x0B: "Already in requested mode/state",
		0x0C: "Object state conflict",
		0x0D: "Object already exists",
		0x0E: "Attribute not settable",
		0x0F: "Privilege violation",
	}

	// Verify status codes are recognized (basic validation)
	for code, name := range statusCodes {
		// Just verify the codes are in expected range
		if code > 0xFF {
			t.Errorf("Status code %d (%s) exceeds 8-bit range", code, name)
		}
	}

	// Test that we handle success status correctly
	// CIP response structure: [service_code, status, ...payload]
	successData := []byte{
		0x0E, // Service code: Get_Attribute_Single
		0x00, // Status: success
		0x01, 0x02, // Payload
	}
	path := CIPPath{Class: 0x04, Instance: 0x65, Attribute: 0x03}
	resp, err := DecodeCIPResponse(successData, path)
	if err != nil {
		t.Fatalf("DecodeCIPResponse failed: %v", err)
	}
	if resp.Status != 0x00 {
		t.Errorf("Success status: got 0x%02X, want 0x00", resp.Status)
	}
	if resp.Service != CIPServiceGetAttributeSingle {
		t.Errorf("Service code: got 0x%02X, want 0x%02X", resp.Service, CIPServiceGetAttributeSingle)
	}
}

