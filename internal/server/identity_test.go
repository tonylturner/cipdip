package server

import (
	"github.com/tturner/cipdip/internal/cip/spec"
	"testing"

	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/config"
)

func TestIdentityGetAttributeSingle(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerConfigSection{
			IdentityVendorID:    0x1234,
			IdentityDeviceType:  0x000C,
			IdentityProductCode: 0x0042,
			IdentityRevMajor:    2,
			IdentityRevMinor:    1,
			IdentityStatus:      0x00A0,
			IdentitySerial:      0x01020304,
			IdentityProductName: "CIPDIP",
		},
	}
	s := &Server{config: cfg}

	resp, ok := s.handleIdentityRequest(protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     0x0001,
			Instance:  0x0001,
			Attribute: 1,
		},
	})
	if !ok {
		t.Fatalf("expected identity handler")
	}
	if resp.Status != 0x00 {
		t.Fatalf("expected status 0, got 0x%02X", resp.Status)
	}
	if len(resp.Payload) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(resp.Payload))
	}
	if resp.Payload[0] != 0x34 || resp.Payload[1] != 0x12 {
		t.Fatalf("unexpected vendor ID bytes: %02X %02X", resp.Payload[0], resp.Payload[1])
	}
}

func TestIdentityGetAttributeAllIncludesName(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerConfigSection{
			IdentityVendorID:    0x0001,
			IdentityDeviceType:  0x000C,
			IdentityProductCode: 0x0001,
			IdentityRevMajor:    1,
			IdentityRevMinor:    0,
			IdentityStatus:      0x0000,
			IdentitySerial:      0x00000001,
			IdentityProductName: "TestProduct",
		},
	}
	s := &Server{config: cfg}

	resp, ok := s.handleIdentityRequest(protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeAll,
		Path: protocol.CIPPath{
			Class:     0x0001,
			Instance:  0x0001,
			Attribute: 0,
		},
	})
	if !ok {
		t.Fatalf("expected identity handler")
	}
	if resp.Status != 0x00 {
		t.Fatalf("expected status 0, got 0x%02X", resp.Status)
	}
	if len(resp.Payload) < 16 {
		t.Fatalf("expected payload length >= 16, got %d", len(resp.Payload))
	}
	nameLen := int(resp.Payload[len(resp.Payload)-len("TestProduct")-1])
	if nameLen != len("TestProduct") {
		t.Fatalf("expected name length %d, got %d", len("TestProduct"), nameLen)
	}
}
