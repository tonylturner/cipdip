package core

import (
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
	"testing"

	cipclient "github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/enip"
	"github.com/tturner/cipdip/internal/logging"
)

func TestHandleUnconnectedSendSuccess(t *testing.T) {
	cfg := createTestServerConfig()
	cfg.Server.IdentityVendorID = 0x1234
	cfg.Server.IdentityDeviceType = 0x000C
	cfg.Server.IdentityProductCode = 0x0042
	cfg.Server.IdentityRevMajor = 2
	cfg.Server.IdentityRevMinor = 1
	cfg.Server.IdentityStatus = 0x00A0
	cfg.Server.IdentitySerial = 0x01020304
	cfg.Server.IdentityProductName = "CIPDIP"
	logger, _ := logging.NewLogger(logging.LogLevelError, "")
	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	embeddedReq := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     spec.CIPClassIdentityObject,
			Instance:  0x0001,
			Attribute: 0x0001,
		},
	}
	embeddedData, err := protocol.EncodeCIPRequest(embeddedReq)
	if err != nil {
		t.Fatalf("EncodeCIPRequest failed: %v", err)
	}
	payload, err := cipclient.BuildUnconnectedSendPayload(embeddedData, cipclient.UnconnectedSendOptions{})
	if err != nil {
		t.Fatalf("BuildUnconnectedSendPayload failed: %v", err)
	}

	req := protocol.CIPRequest{
		Service: spec.CIPServiceUnconnectedSend,
		Path: protocol.CIPPath{
			Class:    spec.CIPClassConnectionManager,
			Instance: 0x0001,
		},
		Payload: payload,
	}

	encap := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandSendRRData,
		SessionID:     0x1234,
		Status:        0,
		SenderContext: [8]byte{0x01},
		Options:       0,
		Data:          nil,
	}

	resp := srv.handleUnconnectedSend(encap, req)
	respEncap, err := enip.DecodeENIP(resp)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}
	cipPayload, err := enip.ParseSendRRDataResponse(respEncap.Data)
	if err != nil {
		t.Fatalf("ParseSendRRDataResponse failed: %v", err)
	}
	cipResp, err := protocol.DecodeCIPResponse(cipPayload, req.Path)
	if err != nil {
		t.Fatalf("DecodeCIPResponse failed: %v", err)
	}
	if cipResp.Status != 0x00 {
		t.Fatalf("expected status 0, got 0x%02X", cipResp.Status)
	}

	embeddedRespData, ok := protocol.ParseUnconnectedSendResponsePayload(cipResp.Payload)
	if !ok {
		t.Fatalf("ParseUnconnectedSendResponsePayload failed")
	}
	embeddedResp, err := protocol.DecodeCIPResponse(embeddedRespData, embeddedReq.Path)
	if err != nil {
		t.Fatalf("DecodeCIPResponse (embedded) failed: %v", err)
	}
	if embeddedResp.Status != 0x00 {
		t.Fatalf("expected embedded status 0, got 0x%02X", embeddedResp.Status)
	}
	if len(embeddedResp.Payload) != 2 {
		t.Fatalf("expected vendor ID payload length 2, got %d", len(embeddedResp.Payload))
	}
}

func TestHandleUnconnectedSendInvalidPayload(t *testing.T) {
	cfg := createTestServerConfig()
	logger, _ := logging.NewLogger(logging.LogLevelError, "")
	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	req := protocol.CIPRequest{
		Service: spec.CIPServiceUnconnectedSend,
		Path: protocol.CIPPath{
			Class:    spec.CIPClassConnectionManager,
			Instance: 0x0001,
		},
		Payload: []byte{0x01},
	}

	encap := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandSendRRData,
		SessionID:     0x1234,
		Status:        0,
		SenderContext: [8]byte{0x01},
		Options:       0,
		Data:          nil,
	}

	resp := srv.handleUnconnectedSend(encap, req)
	respEncap, err := enip.DecodeENIP(resp)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}
	cipPayload, err := enip.ParseSendRRDataResponse(respEncap.Data)
	if err != nil {
		t.Fatalf("ParseSendRRDataResponse failed: %v", err)
	}
	cipResp, err := protocol.DecodeCIPResponse(cipPayload, req.Path)
	if err != nil {
		t.Fatalf("DecodeCIPResponse failed: %v", err)
	}
	if cipResp.Status != 0x13 {
		t.Fatalf("expected status 0x13, got 0x%02X", cipResp.Status)
	}
}

func TestHandleMultipleService(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()
	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	reqs := []protocol.CIPRequest{
		{
			Service: spec.CIPServiceGetAttributeSingle,
			Path: protocol.CIPPath{
				Class:     spec.CIPClassIdentityObject,
				Instance:  0x0001,
				Attribute: 0x0001,
			},
		},
		{
			Service: spec.CIPServiceGetAttributeSingle,
			Path: protocol.CIPPath{
				Class:     spec.CIPClassIdentityObject,
				Instance:  0x0001,
				Attribute: 0x0002,
			},
		},
	}

	payload, err := cipclient.BuildMultipleServiceRequestPayload(reqs)
	if err != nil {
		t.Fatalf("BuildMultipleServiceRequestPayload failed: %v", err)
	}

	req := protocol.CIPRequest{
		Service: spec.CIPServiceMultipleService,
		Path: protocol.CIPPath{
			Class:    spec.CIPClassMessageRouter,
			Instance: 0x0001,
		},
		Payload: payload,
	}

	encap := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandSendRRData,
		SessionID:     0x1234,
		Status:        0,
		SenderContext: [8]byte{0x01},
		Options:       0,
		Data:          nil,
	}

	resp := srv.handleMultipleService(encap, req)
	respEncap, err := enip.DecodeENIP(resp)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}
	cipPayload, err := enip.ParseSendRRDataResponse(respEncap.Data)
	if err != nil {
		t.Fatalf("ParseSendRRDataResponse failed: %v", err)
	}
	cipResp, err := protocol.DecodeCIPResponse(cipPayload, req.Path)
	if err != nil {
		t.Fatalf("DecodeCIPResponse failed: %v", err)
	}
	if cipResp.Status != 0x00 {
		t.Fatalf("expected status 0, got 0x%02X", cipResp.Status)
	}

	embedded, err := cipclient.ParseMultipleServiceResponsePayload(cipResp.Payload, req.Path)
	if err != nil {
		t.Fatalf("ParseMultipleServiceResponsePayload failed: %v", err)
	}
	if len(embedded) != len(reqs) {
		t.Fatalf("expected %d embedded responses, got %d", len(reqs), len(embedded))
	}
}
