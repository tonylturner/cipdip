package cipclient

import (
	"testing"

	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
)

func TestEncodeEPATH(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	tests := []struct {
		name     string
		path     protocol.CIPPath
		expected []byte
	}{
		{
			name: "8-bit class and instance",
			path: protocol.CIPPath{
				Class:     0x04,
				Instance:  0x65,
				Attribute: 0x03,
			},
			expected: []byte{
				0x20, 0x04, // Class (8-bit)
				0x24, 0x65, // Instance (8-bit)
				0x30, 0x03, // Attribute (8-bit)
			},
		},
		{
			name: "16-bit class",
			path: protocol.CIPPath{
				Class:     0x0100,
				Instance:  0x65,
				Attribute: 0x03,
			},
			expected: []byte{
				0x21, 0x00, 0x01, // Class (16-bit, little-endian)
				0x24, 0x65, // Instance (8-bit)
				0x30, 0x03, // Attribute (8-bit)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := protocol.EncodeEPATH(tt.path)
			if len(result) != len(tt.expected) {
				t.Errorf("length mismatch: got %d, want %d", len(result), len(tt.expected))
				return
			}
			for i, b := range result {
				if b != tt.expected[i] {
					t.Errorf("byte %d: got 0x%02X, want 0x%02X", i, b, tt.expected[i])
				}
			}
		})
	}
}

func TestEncodeCIPRequest(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	req := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     0x04,
			Instance:  0x65,
			Attribute: 0x03,
		},
		Payload: nil,
	}

	data, err := protocol.EncodeCIPRequest(req)
	if err != nil {
		t.Fatalf("protocol.EncodeCIPRequest failed: %v", err)
	}

	minLen := 7
	if CurrentProtocolProfile().IncludeCIPPathSize {
		minLen = 8
	}
	if len(data) < minLen {
		t.Errorf("encoded data too short: %d bytes", len(data))
	}

	// Check service code
	if data[0] != uint8(spec.CIPServiceGetAttributeSingle) {
		t.Errorf("service code: got 0x%02X, want 0x%02X", data[0], uint8(spec.CIPServiceGetAttributeSingle))
	}
}
