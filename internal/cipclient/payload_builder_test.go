package cipclient

import (
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
	"testing"
)

func TestBuildServicePayloadRockwellTag(t *testing.T) {
	req := protocol.CIPRequest{
		Service: spec.CIPServiceReadTag,
		Path:    protocol.CIPPath{Class: spec.CIPClassSymbolObject, Instance: 1},
	}
	result, err := BuildServicePayload(req, PayloadSpec{
		Type: "rockwell_tag",
		Params: map[string]any{
			"tag":      "TestTag",
			"elements": "1",
		},
	})
	if err != nil {
		t.Fatalf("BuildServicePayload error: %v", err)
	}
	if len(result.RawPath) == 0 {
		t.Fatalf("expected symbolic RawPath")
	}
	if len(result.Payload) != 2 {
		t.Fatalf("expected payload length 2, got %d", len(result.Payload))
	}
}

func TestBuildServicePayloadUnconnectedSend(t *testing.T) {
	req := protocol.CIPRequest{
		Service: spec.CIPServiceUnconnectedSend,
		Path:    protocol.CIPPath{Class: spec.CIPClassConnectionManager, Instance: 1},
	}
	result, err := BuildServicePayload(req, PayloadSpec{
		Type: "unconnected_send",
		Params: map[string]any{
			"embedded_request_hex": "0E0200010001",
			"route_slot":           "1",
		},
	})
	if err != nil {
		t.Fatalf("BuildServicePayload error: %v", err)
	}
	if len(result.Payload) == 0 {
		t.Fatalf("expected payload bytes")
	}
	if len(result.RawPath) == 0 {
		t.Fatalf("expected raw path for Connection Manager")
	}
}

func TestBuildServicePayloadForwardOpen(t *testing.T) {
	req := protocol.CIPRequest{
		Service: spec.CIPServiceForwardOpen,
		Path:    protocol.CIPPath{Class: spec.CIPClassConnectionManager, Instance: 1},
	}
	result, err := BuildServicePayload(req, PayloadSpec{
		Type: "forward_open",
		Params: map[string]any{
			"o_to_t_rpi_ms": "20",
			"t_to_o_rpi_ms": "20",
		},
	})
	if err != nil {
		t.Fatalf("BuildServicePayload error: %v", err)
	}
	if len(result.Payload) == 0 {
		t.Fatalf("expected payload bytes")
	}
}

func TestBuildServicePayloadTemplate(t *testing.T) {
	req := protocol.CIPRequest{
		Service: spec.CIPServiceReadTag,
		Path:    protocol.CIPPath{Class: spec.CIPClassTemplateObject, Instance: 1},
	}
	result, err := BuildServicePayload(req, PayloadSpec{
		Type: "rockwell_template",
		Params: map[string]any{
			"offset": "0",
			"length": "64",
		},
	})
	if err != nil {
		t.Fatalf("BuildServicePayload error: %v", err)
	}
	if len(result.Payload) != 6 {
		t.Fatalf("expected template payload length 6, got %d", len(result.Payload))
	}
}

func TestBuildServicePayloadFileObject(t *testing.T) {
	req := protocol.CIPRequest{
		Service: spec.CIPServiceInitiateUpload,
		Path:    protocol.CIPPath{Class: spec.CIPClassFileObject, Instance: 1},
	}
	result, err := BuildServicePayload(req, PayloadSpec{
		Type:   "file_object",
		Params: map[string]any{"file_size": "1024"},
	})
	if err != nil {
		t.Fatalf("BuildServicePayload error: %v", err)
	}
	if len(result.Payload) != 4 {
		t.Fatalf("expected file payload length 4, got %d", len(result.Payload))
	}
}

func TestBuildServicePayloadModbus(t *testing.T) {
	req := protocol.CIPRequest{
		Service: 0x4B,
		Path:    protocol.CIPPath{Class: spec.CIPClassModbus, Instance: 1},
	}
	result, err := BuildServicePayload(req, PayloadSpec{
		Type: "modbus_object",
		Params: map[string]any{
			"modbus_addr": "1",
			"modbus_qty":  "2",
		},
	})
	if err != nil {
		t.Fatalf("BuildServicePayload error: %v", err)
	}
	if len(result.Payload) != 4 {
		t.Fatalf("expected modbus payload length 4, got %d", len(result.Payload))
	}
}

func TestBuildServicePayloadPCCC(t *testing.T) {
	req := protocol.CIPRequest{
		Service: spec.CIPServiceExecutePCCC,
		Path:    protocol.CIPPath{Class: spec.CIPClassPCCCObject, Instance: 1},
	}
	result, err := BuildServicePayload(req, PayloadSpec{
		Type:   "rockwell_pccc",
		Params: map[string]any{"pccc_hex": "0F00"},
	})
	if err != nil {
		t.Fatalf("BuildServicePayload error: %v", err)
	}
	if len(result.Payload) == 0 {
		t.Fatalf("expected pccc payload bytes")
	}
}
