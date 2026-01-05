package protocol

import "encoding/binary"

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
