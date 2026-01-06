package cipclient

import (
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
	"testing"
)

func TestValidateCIPRequestConnectionManagerServices(t *testing.T) {
	validator := NewPacketValidator(true)
	services := []protocol.CIPServiceCode{
		spec.CIPServiceForwardOpen,
		spec.CIPServiceForwardClose,
		spec.CIPServiceGetConnectionData,
		spec.CIPServiceSearchConnectionData,
		spec.CIPServiceGetConnectionOwner,
		spec.CIPServiceLargeForwardOpen,
	}

	for _, svc := range services {
		req := protocol.CIPRequest{
			Service: svc,
			Path: protocol.CIPPath{
				Class:    spec.CIPClassConnectionManager,
				Instance: 0x0001,
			},
		}
		switch svc {
		case spec.CIPServiceForwardOpen, spec.CIPServiceLargeForwardOpen:
			payload, err := BuildForwardOpenPayload(ConnectionParams{
				Priority:              "scheduled",
				OToTRPIMs:             20,
				TToORPIMs:             20,
				OToTSizeBytes:         32,
				TToOSizeBytes:         32,
				TransportClassTrigger: 3,
				Class:                 spec.CIPClassAssembly,
				Instance:              0x65,
			})
			if err != nil {
				t.Fatalf("BuildForwardOpenPayload error: %v", err)
			}
			req.Payload = payload
		case spec.CIPServiceForwardClose:
			payload, err := BuildForwardClosePayload(0x11223344)
			if err != nil {
				t.Fatalf("BuildForwardClosePayload error: %v", err)
			}
			req.Payload = payload
		default:
			req.Payload = []byte{0x01, 0x02}
		}
		if err := validator.ValidateCIPRequest(req); err != nil {
			t.Fatalf("ValidateCIPRequest(%s) error: %v", spec.ServiceName(svc), err)
		}
	}
}

func TestValidateCIPRequestFragmentedPayloads(t *testing.T) {
	validator := NewPacketValidator(true)

	readReq := protocol.CIPRequest{
		Service: spec.CIPServiceReadTagFragmented,
		Path:    protocol.CIPPath{Class: 0x006B, Instance: 0x0001},
		Payload: nil,
	}
	if err := validator.ValidateCIPRequest(readReq); err == nil {
		t.Fatalf("expected error for missing Read_Tag_Fragmented payload")
	}

	readReq.Payload = []byte{0x01, 0x00, 0x00, 0x00}
	if err := validator.ValidateCIPRequest(readReq); err == nil {
		t.Fatalf("expected error for short Read_Tag_Fragmented payload")
	}

	readReq.Payload = BuildReadTagFragmentedPayload(1, 0)
	if err := validator.ValidateCIPRequest(readReq); err != nil {
		t.Fatalf("unexpected error for Read_Tag_Fragmented payload: %v", err)
	}

	writeReq := protocol.CIPRequest{
		Service: spec.CIPServiceWriteTagFragmented,
		Path:    protocol.CIPPath{Class: 0x006B, Instance: 0x0001},
		Payload: []byte{0x00},
	}
	if err := validator.ValidateCIPRequest(writeReq); err == nil {
		t.Fatalf("expected error for short Write_Tag_Fragmented payload")
	}

	writeReq.Payload = BuildWriteTagFragmentedPayload(uint16(protocol.CIPTypeDINT), 1, 0, []byte{0x01, 0x02, 0x03, 0x04})
	if err := validator.ValidateCIPRequest(writeReq); err != nil {
		t.Fatalf("unexpected error for Write_Tag_Fragmented payload: %v", err)
	}
}

func TestValidateCIPRequestUnconnectedSendEmbedded(t *testing.T) {
	validator := NewPacketValidator(true)
	embedded := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path: protocol.CIPPath{
			Class:    spec.CIPClassIdentityObject,
			Instance: 0x01,
		},
	}
	embeddedBytes, err := protocol.EncodeCIPRequest(embedded)
	if err != nil {
		t.Fatalf("protocol.EncodeCIPRequest error: %v", err)
	}
	payload, err := BuildUnconnectedSendPayload(embeddedBytes, UnconnectedSendOptions{})
	if err != nil {
		t.Fatalf("BuildUnconnectedSendPayload error: %v", err)
	}
	req := protocol.CIPRequest{
		Service: spec.CIPServiceUnconnectedSend,
		Path: protocol.CIPPath{
			Class:    spec.CIPClassConnectionManager,
			Instance: 0x0001,
		},
		Payload: payload,
	}
	if err := validator.ValidateCIPRequest(req); err != nil {
		t.Fatalf("ValidateCIPRequest(Unconnected_Send) error: %v", err)
	}
}

func TestValidateCIPResponseForwardOpenPayload(t *testing.T) {
	validator := NewPacketValidator(true)
	resp := protocol.CIPResponse{
		Service: spec.CIPServiceForwardOpen,
		Path: protocol.CIPPath{
			Class:    spec.CIPClassConnectionManager,
			Instance: 0x0001,
		},
		Status:  0x00,
		Payload: make([]byte, 16),
	}
	if err := validator.ValidateCIPResponse(resp, spec.CIPServiceForwardOpen); err == nil {
		t.Fatalf("expected error for short Forward_Open response payload")
	}

	resp.Payload = make([]byte, 17)
	if err := validator.ValidateCIPResponse(resp, spec.CIPServiceForwardOpen); err != nil {
		t.Fatalf("unexpected error for Forward_Open response payload: %v", err)
	}
}

func TestValidateCIPResponseUnconnectedSendPayload(t *testing.T) {
	validator := NewPacketValidator(true)
	resp := protocol.CIPResponse{
		Service: spec.CIPServiceUnconnectedSend,
		Path: protocol.CIPPath{
			Class:    spec.CIPClassConnectionManager,
			Instance: 0x0001,
		},
		Status:  0x00,
		Payload: []byte{0x00},
	}
	if err := validator.ValidateCIPResponse(resp, spec.CIPServiceUnconnectedSend); err == nil {
		t.Fatalf("expected error for missing Unconnected_Send embedded payload")
	}

	embeddedResp, err := protocol.EncodeCIPResponse(protocol.CIPResponse{
		Service: spec.CIPServiceGetAttributeSingle,
		Status:  0x00,
		Payload: []byte{0x01},
	})
	if err != nil {
		t.Fatalf("protocol.EncodeCIPResponse error: %v", err)
	}
	resp.Payload = BuildUnconnectedSendResponsePayload(embeddedResp)
	if err := validator.ValidateCIPResponse(resp, spec.CIPServiceUnconnectedSend); err != nil {
		t.Fatalf("unexpected error for Unconnected_Send response payload: %v", err)
	}
}
