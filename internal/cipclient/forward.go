package cipclient

// ForwardOpen/ForwardClose implementation for connected I/O messaging

import (
	"fmt"
	"strings"
)

// BuildForwardOpenRequest builds a ForwardOpen CIP request
// ForwardOpen is service 0x54 on Connection Manager (class 0x06)
func BuildForwardOpenRequest(params ConnectionParams) ([]byte, error) {
	var data []byte
	profile := CurrentProtocolProfile()

	// Service code (0x54 = Forward_Open)
	data = append(data, uint8(CIPServiceForwardOpen))

	// Connection Manager path (class 0x06, instance 0x01)
	// EPATH: 0x20 (8-bit class) + 0x06, 0x24 (8-bit instance) + 0x01
	if profile.IncludeCIPPathSize {
		data = append(data, 0x02) // 2 words (4 bytes)
	}
	data = append(data, 0x20, 0x06) // Class 0x06
	data = append(data, 0x24, 0x01) // Instance 0x01

	payload, err := BuildForwardOpenPayload(params)
	if err != nil {
		return nil, err
	}
	data = append(data, payload...)

	return data, nil
}

// ParseForwardOpenResponse parses a ForwardOpen response
func ParseForwardOpenResponse(data []byte) (connectionID uint32, oToTConnID uint32, tToOConnID uint32, err error) {
	// ForwardOpen response structure:
	// - General status (1 byte)
	// - Additional status size (1 byte)
	// - Additional status (variable)
	// - O->T connection ID (4 bytes)
	// - T->O connection ID (4 bytes)
	// - Connection serial number (2 bytes)
	// - Originator vendor ID (2 bytes)
	// - Originator serial number (4 bytes)
	// - Connection timeout multiplier (1 byte)

	if len(data) < 1 {
		return 0, 0, 0, fmt.Errorf("response too short")
	}

	status := data[0]
	if status != 0x00 {
		// Check for additional status
		if len(data) > 1 {
			extStatusSize := int(data[1])
			if len(data) < 2+extStatusSize {
				return 0, 0, 0, fmt.Errorf("forward open failed with status 0x%02X", status)
			}
			return 0, 0, 0, fmt.Errorf("forward open failed with status 0x%02X", status)
		}
		return 0, 0, 0, fmt.Errorf("forward open failed with status 0x%02X", status)
	}

	offset := 1
	if len(data) > offset {
		extStatusSize := int(data[offset])
		offset += 1 + extStatusSize
	}

	// Parse connection IDs
	if len(data) < offset+8 {
		return 0, 0, 0, fmt.Errorf("response too short for connection IDs")
	}

	order := currentCIPByteOrder()
	oToTConnID = order.Uint32(data[offset : offset+4])
	offset += 4
	tToOConnID = order.Uint32(data[offset : offset+4])
	offset += 4

	// Use O->T connection ID as the primary connection ID
	connectionID = oToTConnID

	return connectionID, oToTConnID, tToOConnID, nil
}

// BuildForwardCloseRequest builds a ForwardClose CIP request
// ForwardClose is service 0x4E on Connection Manager (class 0x06)
func BuildForwardCloseRequest(connectionID uint32) ([]byte, error) {
	var data []byte
	profile := CurrentProtocolProfile()

	// Service code (0x4E = Forward_Close)
	data = append(data, uint8(CIPServiceForwardClose))

	// Connection Manager path (class 0x06, instance 0x01)
	if profile.IncludeCIPPathSize {
		data = append(data, 0x02) // 2 words (4 bytes)
	}
	data = append(data, 0x20, 0x06) // Class 0x06
	data = append(data, 0x24, 0x01) // Instance 0x01

	payload, err := BuildForwardClosePayload(connectionID)
	if err != nil {
		return nil, err
	}
	data = append(data, payload...)

	return data, nil
}

// BuildForwardOpenPayload builds the payload section for ForwardOpen (after EPATH).
func BuildForwardOpenPayload(params ConnectionParams) ([]byte, error) {
	var data []byte
	order := currentCIPByteOrder()

	// Priority and tick time (1 byte)
	// Bits 0-3: Priority (0=low, 1=scheduled, 2=high, 3=urgent)
	// Bits 4-7: Tick time (typically 0)
	priorityByte := byte(0)
	switch params.Priority {
	case "low":
		priorityByte = 0x00
	case "scheduled":
		priorityByte = 0x01
	case "high":
		priorityByte = 0x02
	case "urgent":
		priorityByte = 0x03
	default:
		priorityByte = 0x01 // Default to scheduled
	}
	data = append(data, priorityByte)

	// Connection timeout (2 bytes, in seconds, typically 30)
	timeout := uint16(30)
	data = appendUint16(order, data, timeout)

	// O->T RPI (4 bytes, in microseconds)
	rpiOToT := uint32(params.OToTRPIMs * 1000) // Convert ms to microseconds
	data = appendUint32(order, data, rpiOToT)

	// O->T connection parameters (4 bytes)
	// Bit 0: Connection type (0=explicit, 1=IO)
	// Bit 1: Priority (from priority byte)
	// Bits 2-3: Connection size (0=8 bytes, 1=16 bytes, 2=32 bytes, 3=variable)
	oToTParams := uint32(0x00000001) // IO connection
	oToTParams |= uint32(priorityByte) << 1
	if params.OToTSizeBytes <= 8 {
		oToTParams |= 0x00 << 2
	} else if params.OToTSizeBytes <= 16 {
		oToTParams |= 0x01 << 2
	} else if params.OToTSizeBytes <= 32 {
		oToTParams |= 0x02 << 2
	} else {
		oToTParams |= 0x03 << 2 // Variable
	}
	data = appendUint32(order, data, oToTParams)

	// T->O RPI (4 bytes, in microseconds)
	rpiTToO := uint32(params.TToORPIMs * 1000) // Convert ms to microseconds
	data = appendUint32(order, data, rpiTToO)

	// T->O connection parameters (4 bytes, similar to O->T)
	tToOParams := uint32(0x00000001) // IO connection
	tToOParams |= uint32(priorityByte) << 1
	if params.TToOSizeBytes <= 8 {
		tToOParams |= 0x00 << 2
	} else if params.TToOSizeBytes <= 16 {
		tToOParams |= 0x01 << 2
	} else if params.TToOSizeBytes <= 32 {
		tToOParams |= 0x02 << 2
	} else {
		tToOParams |= 0x03 << 2 // Variable
	}
	data = appendUint32(order, data, tToOParams)

	// Transport class and trigger (1 byte)
	transportByte := byte(params.TransportClassTrigger)
	if params.TransportClassTrigger == 3 {
		transportByte = 0x03 // Cyclic
	}
	data = append(data, transportByte)

	// Connection path size (1 byte, in 16-bit words)
	var connPath []byte
	if params.ConnectionPathHex != "" {
		hexStr := strings.ReplaceAll(params.ConnectionPathHex, " ", "")
		if len(hexStr)%2 != 0 {
			return nil, fmt.Errorf("connection_path_hex must have even number of hex digits")
		}
		connPath = make([]byte, len(hexStr)/2)
		for i := 0; i < len(hexStr); i += 2 {
			var b byte
			if _, err := fmt.Sscanf(hexStr[i:i+2], "%02x", &b); err != nil {
				return nil, fmt.Errorf("invalid hex in connection_path_hex: %w", err)
			}
			connPath[i/2] = b
		}
	} else {
		connPath = EncodeEPATH(CIPPath{
			Class:    params.Class,
			Instance: params.Instance,
		})
	}

	pathSizeWords := len(connPath) / 2
	if len(connPath)%2 != 0 {
		pathSizeWords++
	}
	data = append(data, uint8(pathSizeWords))
	data = append(data, connPath...)
	if len(connPath)%2 != 0 {
		data = append(data, 0x00)
	}
	return data, nil
}

// BuildForwardClosePayload builds the payload section for ForwardClose (after EPATH).
func BuildForwardClosePayload(connectionID uint32) ([]byte, error) {
	var data []byte
	order := currentCIPByteOrder()

	pathBytes := []byte{0x34}
	pathBytes = appendUint32(order, pathBytes, connectionID)
	pathSizeWords := len(pathBytes) / 2
	if len(pathBytes)%2 != 0 {
		pathSizeWords++
	}
	data = append(data, uint8(pathSizeWords))
	data = append(data, pathBytes...)
	if len(pathBytes)%2 != 0 {
		data = append(data, 0x00)
	}
	return data, nil
}

// ParseForwardCloseResponse parses a ForwardClose response
func ParseForwardCloseResponse(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("response too short")
	}

	status := data[0]
	if status != 0x00 {
		return fmt.Errorf("forward close failed with status 0x%02X", status)
	}

	return nil
}
