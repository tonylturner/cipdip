package validation

import (
	"testing"

	"github.com/tturner/cipdip/internal/cipclient"
)

// TestWiresharkValidationRegisterSession tests Wireshark validation on RegisterSession packet
func TestWiresharkValidationRegisterSession(t *testing.T) {
	// Skip if tshark is not available
	validator := NewWiresharkValidator("")
	if _, err := validator.ValidatePacket([]byte{}); err != nil {
		if err.Error() == "tshark not found in PATH" {
			t.Skip("tshark not available, skipping Wireshark validation test")
		}
	}

	// Build a RegisterSession packet
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	packet := cipclient.BuildRegisterSession(senderContext)

	// Validate with Wireshark
	result, err := validator.ValidatePacket(packet)
	if err != nil {
		t.Fatalf("Wireshark validation failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("RegisterSession packet failed Wireshark validation")
		if len(result.Errors) > 0 {
			t.Errorf("Errors: %v", result.Errors)
		}
		if len(result.Warnings) > 0 {
			t.Logf("Warnings: %v", result.Warnings)
		}
	}

	// Check that validation message is present
	if result.Message == "" {
		t.Error("Validation message not set")
	}

	// Check that packet is on correct port
	if port, ok := result.Fields["tcp.port"]; ok {
		if port != "44818" && port != "2222" {
			t.Errorf("Packet not on ENIP port, got %s", port)
		}
	} else {
		t.Error("TCP port not extracted from packet")
	}
}

// TestWiresharkValidationSendRRData tests Wireshark validation on SendRRData packet
func TestWiresharkValidationSendRRData(t *testing.T) {
	// Skip if tshark is not available
	validator := NewWiresharkValidator("")
	if _, err := validator.ValidatePacket([]byte{}); err != nil {
		if err.Error() == "tshark not found in PATH" {
			t.Skip("tshark not available, skipping Wireshark validation test")
		}
	}

	// Build a SendRRData packet with GetAttributeSingle
	sessionID := uint32(0x12345678)
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	cipData := []byte{0x0E, 0x20, 0x04, 0x24, 0x65, 0x30, 0x03} // GetAttributeSingle
	packet := cipclient.BuildSendRRData(sessionID, senderContext, cipData)

	// Validate with Wireshark
	result, err := validator.ValidatePacket(packet)
	if err != nil {
		t.Fatalf("Wireshark validation failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("SendRRData packet failed Wireshark validation")
		if len(result.Errors) > 0 {
			t.Errorf("Errors: %v", result.Errors)
		}
	}

	// Check that packet is on correct port
	if port, ok := result.Fields["tcp.port"]; ok {
		if port != "44818" && port != "2222" {
			t.Errorf("Packet not on ENIP port, got %s", port)
		}
	} else {
		t.Error("TCP port not extracted from packet")
	}
}

// TestWiresharkValidationConvenienceFunction tests the convenience function
func TestWiresharkValidationConvenienceFunction(t *testing.T) {
	// Skip if tshark is not available
	if _, err := ValidateENIPPacket([]byte{}); err != nil {
		if err.Error() == "tshark not found in PATH" {
			t.Skip("tshark not available, skipping Wireshark validation test")
		}
	}

	// Build a RegisterSession packet
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	packet := cipclient.BuildRegisterSession(senderContext)

	// Validate with convenience function
	valid, err := ValidateENIPPacket(packet)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if !valid {
		t.Error("RegisterSession packet should be valid according to Wireshark")
	}
}

