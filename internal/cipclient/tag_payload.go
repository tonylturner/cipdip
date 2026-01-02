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

// CIPTypeCode returns a CIP type code for a tag data type.
func CIPTypeCode(tagType string) uint16 {
	switch tagType {
	case "BOOL":
		return 0x00C1
	case "SINT":
		return 0x00C2
	case "INT":
		return 0x00C3
	case "DINT":
		return 0x00C4
	case "LINT":
		return 0x00C5
	case "REAL":
		return 0x00CA
	case "LREAL":
		return 0x00CB
	default:
		return 0x00C4
	}
}
