package spec

import (
	"testing"

	"github.com/tturner/cipdip/internal/cip/protocol"
)

func TestServiceName(t *testing.T) {
	tests := []struct {
		code     protocol.CIPServiceCode
		expected string
	}{
		{CIPServiceGetAttributeSingle, "Get_Attribute_Single"},
		{CIPServiceSetAttributeSingle, "Set_Attribute_Single"},
		{CIPServiceForwardOpen, "Forward_Open"},
		{protocol.CIPServiceCode(0xFF), "Unknown(0xFF)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := ServiceName(tt.code)
			if result != tt.expected {
				t.Errorf("got %q, want %q", result, tt.expected)
			}
		})
	}
}
