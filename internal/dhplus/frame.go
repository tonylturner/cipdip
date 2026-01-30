package dhplus

// DH+ frame encoding and decoding.

import (
	"encoding/binary"
	"fmt"
)

// EncodeFrame encodes a DH+ frame into bytes.
func EncodeFrame(f Frame) ([]byte, error) {
	if f.Dst > MaxNodeAddress {
		return nil, fmt.Errorf("destination node %d exceeds maximum %d", f.Dst, MaxNodeAddress)
	}
	if f.Src > MaxNodeAddress {
		return nil, fmt.Errorf("source node %d exceeds maximum %d", f.Src, MaxNodeAddress)
	}

	buf := make([]byte, HeaderSize+len(f.Data))
	buf[0] = f.Dst
	buf[1] = f.Src
	buf[2] = uint8(f.Command)
	buf[3] = f.Status
	binary.LittleEndian.PutUint16(buf[4:6], f.TNS)
	copy(buf[HeaderSize:], f.Data)

	return buf, nil
}

// DecodeFrame decodes a DH+ frame from bytes.
func DecodeFrame(data []byte) (Frame, error) {
	if len(data) < HeaderSize {
		return Frame{}, fmt.Errorf("DH+ frame too short: %d bytes (minimum %d)", len(data), HeaderSize)
	}

	f := Frame{
		Dst:     data[0],
		Src:     data[1],
		Command: CommandCode(data[2]),
		Status:  data[3],
		TNS:     binary.LittleEndian.Uint16(data[4:6]),
	}

	if len(data) > HeaderSize {
		f.Data = make([]byte, len(data)-HeaderSize)
		copy(f.Data, data[HeaderSize:])
	}

	return f, nil
}

// ValidateFrame checks if a decoded frame has structurally valid fields.
func ValidateFrame(f Frame) error {
	if f.Dst > MaxNodeAddress {
		return fmt.Errorf("destination node %d exceeds maximum %d", f.Dst, MaxNodeAddress)
	}
	if f.Src > MaxNodeAddress {
		return fmt.Errorf("source node %d exceeds maximum %d", f.Src, MaxNodeAddress)
	}
	return nil
}
