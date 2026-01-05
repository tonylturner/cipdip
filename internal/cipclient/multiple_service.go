package cipclient

import (
	"fmt"

	"github.com/tturner/cipdip/internal/cip/codec"
	"github.com/tturner/cipdip/internal/cip/protocol"
)

// BuildMultipleServiceRequest builds a Multiple Service Packet request for UCMM.
func BuildMultipleServiceRequest(requests []protocol.CIPRequest) (protocol.CIPRequest, error) {
	if len(requests) == 0 {
		return protocol.CIPRequest{}, fmt.Errorf("multiple service request requires at least one embedded request")
	}
	payload, err := BuildMultipleServiceRequestPayload(requests)
	if err != nil {
		return protocol.CIPRequest{}, err
	}
	return protocol.CIPRequest{
		Service: protocol.CIPServiceMultipleService,
		Path: protocol.CIPPath{
			Class:    CIPClassMessageRouter,
			Instance: 0x0001,
		},
		Payload: payload,
	}, nil
}

// BuildMultipleServiceRequestPayload encodes embedded CIP requests for service 0x0A.
func BuildMultipleServiceRequestPayload(requests []protocol.CIPRequest) ([]byte, error) {
	if len(requests) == 0 {
		return nil, fmt.Errorf("multiple service payload requires at least one request")
	}
	order := CurrentProtocolProfile().CIPByteOrder
	count := len(requests)
	headerLen := 2 + 2*count
	payload := make([]byte, headerLen)
	codec.PutUint16(order, payload[0:2], uint16(count))

	offset := headerLen
	offsets := make([]uint16, count)
	for i, req := range requests {
		encoded, err := protocol.EncodeCIPRequest(req)
		if err != nil {
			return nil, fmt.Errorf("encode embedded request %d: %w", i, err)
		}
		if offset > 0xFFFF {
			return nil, fmt.Errorf("multiple service payload too large")
		}
		offsets[i] = uint16(offset)
		payload = append(payload, encoded...)
		offset += len(encoded)
	}

	for i, off := range offsets {
		start := 2 + i*2
		codec.PutUint16(order, payload[start:start+2], off)
	}
	return payload, nil
}

// ParseMultipleServiceRequestPayload decodes embedded CIP requests from a 0x0A payload.
func ParseMultipleServiceRequestPayload(payload []byte) ([]protocol.CIPRequest, error) {
	requests, err := parseMultipleServicePayload(payload, func(data []byte) (protocol.CIPRequest, error) {
		return protocol.DecodeCIPRequest(data)
	})
	if err != nil {
		return nil, err
	}
	return requests, nil
}

// BuildMultipleServiceResponsePayload encodes embedded CIP responses for service 0x0A.
func BuildMultipleServiceResponsePayload(responses []protocol.CIPResponse) ([]byte, error) {
	if len(responses) == 0 {
		return nil, fmt.Errorf("multiple service response requires at least one embedded response")
	}
	order := CurrentProtocolProfile().CIPByteOrder
	count := len(responses)
	headerLen := 2 + 2*count
	payload := make([]byte, headerLen)
	codec.PutUint16(order, payload[0:2], uint16(count))

	offset := headerLen
	offsets := make([]uint16, count)
	for i, resp := range responses {
		encoded, err := protocol.EncodeCIPResponse(resp)
		if err != nil {
			return nil, fmt.Errorf("encode embedded response %d: %w", i, err)
		}
		if offset > 0xFFFF {
			return nil, fmt.Errorf("multiple service payload too large")
		}
		offsets[i] = uint16(offset)
		payload = append(payload, encoded...)
		offset += len(encoded)
	}

	for i, off := range offsets {
		start := 2 + i*2
		codec.PutUint16(order, payload[start:start+2], off)
	}
	return payload, nil
}

// ParseMultipleServiceResponsePayload decodes embedded CIP responses from a 0x0A payload.
func ParseMultipleServiceResponsePayload(payload []byte, path protocol.CIPPath) ([]protocol.CIPResponse, error) {
	responses, err := parseMultipleServicePayload(payload, func(data []byte) (protocol.CIPResponse, error) {
		return protocol.DecodeCIPResponse(data, path)
	})
	if err != nil {
		return nil, err
	}
	return responses, nil
}

func parseMultipleServicePayload[T any](payload []byte, decode func([]byte) (T, error)) ([]T, error) {
	if len(payload) < 2 {
		return nil, fmt.Errorf("multiple service payload too short")
	}
	order := CurrentProtocolProfile().CIPByteOrder
	count := int(order.Uint16(payload[0:2]))
	if count == 0 {
		return nil, fmt.Errorf("multiple service payload missing services")
	}
	headerLen := 2 + 2*count
	if len(payload) < headerLen {
		return nil, fmt.Errorf("multiple service payload header too short")
	}

	offsets := make([]int, count)
	for i := 0; i < count; i++ {
		start := 2 + i*2
		offsets[i] = int(order.Uint16(payload[start : start+2]))
	}

	results := make([]T, 0, count)
	for i := 0; i < count; i++ {
		start := offsets[i]
		if start < headerLen || start >= len(payload) {
			return nil, fmt.Errorf("multiple service offset %d out of range", start)
		}
		end := len(payload)
		if i+1 < count {
			end = offsets[i+1]
			if end <= start {
				return nil, fmt.Errorf("multiple service offsets out of order")
			}
		}
		decoded, err := decode(payload[start:end])
		if err != nil {
			return nil, fmt.Errorf("decode embedded service %d: %w", i, err)
		}
		results = append(results, decoded)
	}
	return results, nil
}
