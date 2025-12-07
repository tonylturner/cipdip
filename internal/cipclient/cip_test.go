package cipclient

import (
	"testing"
)

func TestEncodeEPATH(t *testing.T) {
	tests := []struct {
		name     string
		path     CIPPath
		expected []byte
	}{
		{
			name: "8-bit class and instance",
			path: CIPPath{
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
			path: CIPPath{
				Class:     0x0100,
				Instance:  0x65,
				Attribute: 0x03,
			},
			expected: []byte{
				0x21, 0x01, 0x00, // Class (16-bit, big-endian)
				0x24, 0x65,       // Instance (8-bit)
				0x30, 0x03,       // Attribute (8-bit)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EncodeEPATH(tt.path)
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
	req := CIPRequest{
		Service: CIPServiceGetAttributeSingle,
		Path: CIPPath{
			Class:     0x04,
			Instance:  0x65,
			Attribute: 0x03,
		},
		Payload: nil,
	}

	data, err := EncodeCIPRequest(req)
	if err != nil {
		t.Fatalf("EncodeCIPRequest failed: %v", err)
	}

	// Should have: service code (1) + EPATH (6 bytes for 8-bit class/instance)
	if len(data) < 7 {
		t.Errorf("encoded data too short: %d bytes", len(data))
	}

	// Check service code
	if data[0] != uint8(CIPServiceGetAttributeSingle) {
		t.Errorf("service code: got 0x%02X, want 0x%02X", data[0], uint8(CIPServiceGetAttributeSingle))
	}
}

func TestCIPServiceCodeString(t *testing.T) {
	tests := []struct {
		code     CIPServiceCode
		expected string
	}{
		{CIPServiceGetAttributeSingle, "Get_Attribute_Single"},
		{CIPServiceSetAttributeSingle, "Set_Attribute_Single"},
		{CIPServiceForwardOpen, "Forward_Open"},
		{CIPServiceCode(0xFF), "Unknown(0xFF)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.code.String()
			if result != tt.expected {
				t.Errorf("got %q, want %q", result, tt.expected)
			}
		})
	}
}

