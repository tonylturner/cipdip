package client

import (
	"bytes"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"testing"
)

func TestUnconnectedSendPayloadRoundTrip(t *testing.T) {
	embedded := []byte{0x4C, 0x02, 0x20, 0x6B, 0x24, 0x01}
	payload, err := BuildUnconnectedSendPayload(embedded, UnconnectedSendOptions{})
	if err != nil {
		t.Fatalf("BuildUnconnectedSendPayload failed: %v", err)
	}
	decoded, route, ok := protocol.ParseUnconnectedSendRequestPayload(payload)
	if !ok {
		t.Fatalf("protocol.ParseUnconnectedSendRequestPayload failed")
	}
	if len(route) != 0 {
		t.Fatalf("Expected empty route path")
	}
	if !bytes.Equal(decoded, embedded) {
		t.Fatalf("Embedded mismatch: got %x want %x", decoded, embedded)
	}

	respPayload := BuildUnconnectedSendResponsePayload(embedded)
	respDecoded, ok := protocol.ParseUnconnectedSendResponsePayload(respPayload)
	if !ok {
		t.Fatalf("protocol.ParseUnconnectedSendResponsePayload failed")
	}
	if !bytes.Equal(respDecoded, embedded) {
		t.Fatalf("Response embedded mismatch: got %x want %x", respDecoded, embedded)
	}
}

