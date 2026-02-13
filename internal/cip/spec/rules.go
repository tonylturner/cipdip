package spec

import (
	"fmt"

	"github.com/tonylturner/cipdip/internal/cip/protocol"
)

// UnconnectedSendRule enforces embedded request/response presence.
type UnconnectedSendRule struct{}

func (UnconnectedSendRule) Name() string {
	return "unconnected_send_embedded"
}

func (UnconnectedSendRule) CheckRequest(payload []byte) error {
	embedded, _, ok := protocol.ParseUnconnectedSendRequestPayload(payload)
	if !ok || len(embedded) == 0 {
		return fmt.Errorf("missing embedded request")
	}
	return nil
}

func (UnconnectedSendRule) CheckResponse(payload []byte) error {
	embedded, ok := protocol.ParseUnconnectedSendResponsePayload(payload)
	if !ok || len(embedded) == 0 {
		return fmt.Errorf("missing embedded response")
	}
	return nil
}
