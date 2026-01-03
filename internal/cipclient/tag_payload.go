package cipclient

import "encoding/binary"

// BuildReadTagPayload encodes a Read_Tag request payload.
func BuildReadTagPayload(elementCount uint16) []byte {
	payload := make([]byte, 2)
	if elementCount == 0 {
		elementCount = 1
	}
	binary.LittleEndian.PutUint16(payload, elementCount)
	return payload
}

// BuildReadTagFragmentedPayload encodes a Read_Tag_Fragmented request payload.
func BuildReadTagFragmentedPayload(elementCount uint16, byteOffset uint32) []byte {
	if elementCount == 0 {
		elementCount = 1
	}
	payload := make([]byte, 6)
	binary.LittleEndian.PutUint16(payload[0:2], elementCount)
	binary.LittleEndian.PutUint32(payload[2:6], byteOffset)
	return payload
}

// BuildWriteTagFragmentedPayload encodes a Write_Tag_Fragmented request payload.
func BuildWriteTagFragmentedPayload(typeCode uint16, elementCount uint16, byteOffset uint32, data []byte) []byte {
	if elementCount == 0 {
		elementCount = 1
	}
	payload := make([]byte, 8+len(data))
	binary.LittleEndian.PutUint16(payload[0:2], typeCode)
	binary.LittleEndian.PutUint16(payload[2:4], elementCount)
	binary.LittleEndian.PutUint32(payload[4:8], byteOffset)
	copy(payload[8:], data)
	return payload
}

// BuildWriteTagPayload encodes a Write_Tag request payload.
func BuildWriteTagPayload(typeCode uint16, elementCount uint16, data []byte) []byte {
	if elementCount == 0 {
		elementCount = 1
	}
	payload := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint16(payload[0:2], typeCode)
	binary.LittleEndian.PutUint16(payload[2:4], elementCount)
	copy(payload[4:], data)
	return payload
}
