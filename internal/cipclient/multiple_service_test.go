package cipclient

import (
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
	"testing"
)

func TestMultipleServicePayloadRoundTrip(t *testing.T) {
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
				Class:     spec.CIPClassAssembly,
				Instance:  0x0065,
				Attribute: 0x0003,
			},
		},
	}

	payload, err := BuildMultipleServiceRequestPayload(reqs)
	if err != nil {
		t.Fatalf("BuildMultipleServiceRequestPayload failed: %v", err)
	}

	decoded, err := ParseMultipleServiceRequestPayload(payload)
	if err != nil {
		t.Fatalf("ParseMultipleServiceRequestPayload failed: %v", err)
	}
	if len(decoded) != len(reqs) {
		t.Fatalf("Expected %d embedded requests, got %d", len(reqs), len(decoded))
	}
	for i, req := range decoded {
		if req.Service != reqs[i].Service {
			t.Fatalf("Request %d service mismatch: got 0x%02X want 0x%02X", i, req.Service, reqs[i].Service)
		}
		if req.Path.Class != reqs[i].Path.Class || req.Path.Instance != reqs[i].Path.Instance || req.Path.Attribute != reqs[i].Path.Attribute {
			t.Fatalf("Request %d path mismatch: got %04X/%04X/%04X want %04X/%04X/%04X", i, req.Path.Class, req.Path.Instance, req.Path.Attribute, reqs[i].Path.Class, reqs[i].Path.Instance, reqs[i].Path.Attribute)
		}
	}
}
