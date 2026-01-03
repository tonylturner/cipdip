package cipclient

import "encoding/binary"

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
	payload = appendUint16(binary.LittleEndian, payload, uint16(len(messageRequest)))
	payload = append(payload, messageRequest...)
	payload = append(payload, routeWords, 0x00)
	payload = append(payload, routePath...)
	return payload, nil
}

// ParseUnconnectedSendRequestPayload extracts embedded message request and route path.
func ParseUnconnectedSendRequestPayload(payload []byte) ([]byte, []byte, bool) {
	if len(payload) < 4 {
		return nil, nil, false
	}
	msgSize := binary.LittleEndian.Uint16(payload[2:4])
	offset := 4
	msgBytes := sizeToBytes(msgSize, len(payload)-offset)
	if msgBytes == 0 || offset+msgBytes > len(payload) {
		return nil, nil, false
	}
	msg := payload[offset : offset+msgBytes]
	offset += msgBytes
	if len(payload) < offset+2 {
		return msg, nil, true
	}
	routeWords := int(payload[offset])
	offset += 2
	routeBytes := routeWords * 2
	if routeBytes == 0 || len(payload) < offset+routeBytes {
		return msg, nil, true
	}
	route := payload[offset : offset+routeBytes]
	return msg, route, true
}

// BuildUnconnectedSendResponsePayload builds the payload for an Unconnected Send response.
func BuildUnconnectedSendResponsePayload(messageResponse []byte) []byte {
	payload := make([]byte, 0, 2+len(messageResponse))
	payload = appendUint16(binary.LittleEndian, payload, uint16(len(messageResponse)))
	payload = append(payload, messageResponse...)
	return payload
}

// ParseUnconnectedSendResponsePayload extracts the embedded response from payload.
func ParseUnconnectedSendResponsePayload(payload []byte) ([]byte, bool) {
	if len(payload) < 2 {
		return nil, false
	}
	msgSize := binary.LittleEndian.Uint16(payload[0:2])
	offset := 2
	msgBytes := sizeToBytes(msgSize, len(payload)-offset)
	if msgBytes == 0 || offset+msgBytes > len(payload) {
		return nil, false
	}
	return payload[offset : offset+msgBytes], true
}

func sizeToBytes(size uint16, remaining int) int {
	if int(size) <= remaining {
		return int(size)
	}
	if int(size)*2 <= remaining {
		return int(size) * 2
	}
	return 0
}
