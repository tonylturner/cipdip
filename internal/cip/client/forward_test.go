package client

import (
	"testing"

	"github.com/tonylturner/cipdip/internal/cip/spec"
)

func TestBuildForwardOpenRequestIncludesPathSize(t *testing.T) {
	prev := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prev)

	params := ConnectionParams{
		Class:                 0x04,
		Instance:              0x65,
		OToTRPIMs:             10,
		TToORPIMs:             10,
		OToTSizeBytes:         16,
		TToOSizeBytes:         16,
		TransportClassTrigger: 0x03,
		Priority:              "scheduled",
	}

	req, err := BuildForwardOpenRequest(params)
	if err != nil {
		t.Fatalf("BuildForwardOpenRequest error: %v", err)
	}
	if len(req) < 10 {
		t.Fatalf("unexpected request length: %d", len(req))
	}
	if req[0] != byte(spec.CIPServiceForwardOpen) {
		t.Fatalf("expected ForwardOpen service, got 0x%02X", req[0])
	}
	if req[1] != 0x02 {
		t.Fatalf("expected connection manager path size 2, got %d", req[1])
	}
}

func TestBuildForwardCloseRequestPadding(t *testing.T) {
	prev := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prev)

	req, err := BuildForwardCloseRequest(0x11223344)
	if err != nil {
		t.Fatalf("BuildForwardCloseRequest error: %v", err)
	}
	if len(req) < 10 {
		t.Fatalf("unexpected request length: %d", len(req))
	}
	if req[0] != byte(spec.CIPServiceForwardClose) {
		t.Fatalf("expected ForwardClose service, got 0x%02X", req[0])
	}
	// path size byte at index 5 when strict mode enabled.
	if req[5] == 0 {
		t.Fatalf("expected non-zero path size")
	}
}

