package client

import (
	"encoding/binary"

	"github.com/tonylturner/cipdip/internal/cip/codec"
)

// UnconnectedSendOptions defines UCMM unconnected send payload settings.
type UnconnectedSendOptions struct {
	PriorityTick uint8
	TimeoutTicks uint8
	RoutePath    []byte
}

// BuildUnconnectedSendPayload builds the payload for an Unconnected Send (0x52) request.
func BuildUnconnectedSendPayload(messageRequest []byte, opts UnconnectedSendOptions) ([]byte, error) {
	priority := opts.PriorityTick
	if priority == 0 {
		priority = 0x0A
	}
	timeout := opts.TimeoutTicks
	if timeout == 0 {
		timeout = 0x0E
	}

	routePath := opts.RoutePath
	if len(routePath)%2 != 0 {
		routePath = append(routePath, 0x00)
	}
	routeWords := uint8(len(routePath) / 2)

	payload := make([]byte, 0, 4+len(messageRequest)+2+len(routePath))
	payload = append(payload, priority, timeout)
	payload = codec.AppendUint16(binary.LittleEndian, payload, uint16(len(messageRequest)))
	payload = append(payload, messageRequest...)
	payload = append(payload, routeWords, 0x00)
	payload = append(payload, routePath...)
	return payload, nil
}

// BuildUnconnectedSendResponsePayload builds the payload for an Unconnected Send response.
func BuildUnconnectedSendResponsePayload(messageResponse []byte) []byte {
	payload := make([]byte, 0, 2+len(messageResponse))
	payload = codec.AppendUint16(binary.LittleEndian, payload, uint16(len(messageResponse)))
	payload = append(payload, messageResponse...)
	return payload
}

