package rockwell

import (
	"context"
	"github.com/tturner/cipdip/internal/cip/spec"
	"testing"

	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
)

func TestLogixReadTag(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerConfigSection{},
		LogixTags: []config.LogixTagConfig{
			{Name: "Tag1", Type: "DINT", ArrayLength: 1, UpdatePattern: "static"},
		},
	}
	logger, err := logging.NewLogger(logging.LogLevelSilent, "")
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}

	lp, err := NewLogixPersonality(cfg, logger)
	if err != nil {
		t.Fatalf("NewLogixPersonality failed: %v", err)
	}

	tag := lp.tags["Tag1"]
	tag.Data[0] = 0x11
	tag.Data[1] = 0x22
	tag.Data[2] = 0x33
	tag.Data[3] = 0x44

	req := protocol.CIPRequest{
		Service: spec.CIPServiceReadTag,
		Path:    protocol.CIPPath{Class: 0x0067, Instance: 0x0001, Attribute: 0x0000},
		Payload: []byte{0x01, 0x00},
	}

	resp, err := lp.HandleCIPRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleCIPRequest failed: %v", err)
	}
	if resp.Status != 0x00 {
		t.Fatalf("Expected status 0, got 0x%02X", resp.Status)
	}
	if len(resp.Payload) < 8 {
		t.Fatalf("Expected payload length >= 8, got %d", len(resp.Payload))
	}
	if resp.Payload[0] != 0xC4 || resp.Payload[1] != 0x00 {
		t.Fatalf("Expected type code 0x00C4, got %02X%02X", resp.Payload[1], resp.Payload[0])
	}
	if resp.Payload[2] != 0x01 || resp.Payload[3] != 0x00 {
		t.Fatalf("Expected element count 1, got %02X%02X", resp.Payload[3], resp.Payload[2])
	}
	if resp.Payload[4] != 0x11 || resp.Payload[5] != 0x22 || resp.Payload[6] != 0x33 || resp.Payload[7] != 0x44 {
		t.Fatalf("Unexpected data bytes: %02X %02X %02X %02X", resp.Payload[4], resp.Payload[5], resp.Payload[6], resp.Payload[7])
	}
}

func TestLogixWriteTag(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerConfigSection{},
		LogixTags: []config.LogixTagConfig{
			{Name: "Tag1", Type: "DINT", ArrayLength: 1, UpdatePattern: "static"},
		},
	}
	logger, err := logging.NewLogger(logging.LogLevelSilent, "")
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}

	lp, err := NewLogixPersonality(cfg, logger)
	if err != nil {
		t.Fatalf("NewLogixPersonality failed: %v", err)
	}

	req := protocol.CIPRequest{
		Service: spec.CIPServiceWriteTag,
		Path:    protocol.CIPPath{Class: 0x0067, Instance: 0x0001, Attribute: 0x0000},
		Payload: []byte{0xC4, 0x00, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF},
	}

	resp, err := lp.HandleCIPRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleCIPRequest failed: %v", err)
	}
	if resp.Status != 0x00 {
		t.Fatalf("Expected status 0, got 0x%02X", resp.Status)
	}

	tag := lp.tags["Tag1"]
	if tag.Data[0] != 0xDE || tag.Data[1] != 0xAD || tag.Data[2] != 0xBE || tag.Data[3] != 0xEF {
		t.Fatalf("Unexpected tag data: %02X %02X %02X %02X", tag.Data[0], tag.Data[1], tag.Data[2], tag.Data[3])
	}
}

func TestLogixReadTagByName(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerConfigSection{},
		LogixTags: []config.LogixTagConfig{
			{Name: "Pressure.PV", Type: "DINT", ArrayLength: 1, UpdatePattern: "static"},
		},
	}
	logger, err := logging.NewLogger(logging.LogLevelSilent, "")
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}

	lp, err := NewLogixPersonality(cfg, logger)
	if err != nil {
		t.Fatalf("NewLogixPersonality failed: %v", err)
	}

	tag := lp.tags["Pressure.PV"]
	tag.Data[0] = 0x10
	tag.Data[1] = 0x20
	tag.Data[2] = 0x30
	tag.Data[3] = 0x40

	req := protocol.CIPRequest{
		Service: spec.CIPServiceReadTag,
		Path:    protocol.CIPPath{Name: "Pressure.PV"},
		Payload: []byte{0x01, 0x00},
	}

	resp, err := lp.HandleCIPRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleCIPRequest failed: %v", err)
	}
	if resp.Status != 0x00 {
		t.Fatalf("Expected status 0, got 0x%02X", resp.Status)
	}
	if len(resp.Payload) < 8 {
		t.Fatalf("Expected payload length >= 8, got %d", len(resp.Payload))
	}
	if resp.Payload[4] != 0x10 || resp.Payload[5] != 0x20 || resp.Payload[6] != 0x30 || resp.Payload[7] != 0x40 {
		t.Fatalf("Unexpected data bytes: %02X %02X %02X %02X", resp.Payload[4], resp.Payload[5], resp.Payload[6], resp.Payload[7])
	}
}
