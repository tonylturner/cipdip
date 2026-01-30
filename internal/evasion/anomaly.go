package evasion

// Protocol anomaly injection for DPI evasion.
//
// Generates structurally valid but semantically unusual CIP/ENIP packets.
// These test whether DPI engines correctly handle edge cases in the protocol.

import (
	"encoding/binary"
	"fmt"
)

// AnomalyPacket is an unusual-but-valid protocol packet.
type AnomalyPacket struct {
	Name        string
	Description string
	Payload     []byte
}

// BuildAnomalyPackets generates anomaly packets based on config.
func BuildAnomalyPackets(cfg AnomalyConfig, sessionHandle uint32) []AnomalyPacket {
	var packets []AnomalyPacket

	if cfg.ZeroLengthPayload {
		packets = append(packets, buildZeroLengthPayload(sessionHandle))
	}
	if cfg.MaxLengthEPATH {
		packets = append(packets, buildMaxLengthEPATH(sessionHandle))
	}
	if cfg.ReservedServiceCodes {
		packets = append(packets, buildReservedServiceCodes(sessionHandle)...)
	}
	if cfg.UnusualCPFItems {
		packets = append(packets, buildUnusualCPFItems(sessionHandle)...)
	}
	if cfg.MaxConnectionParams {
		packets = append(packets, buildMaxConnectionParams(sessionHandle))
	}

	return packets
}

// buildZeroLengthPayload creates a SendRRData with a zero-length CIP payload.
func buildZeroLengthPayload(sessionHandle uint32) AnomalyPacket {
	// SendRRData with CPF containing an unconnected data item with 0 bytes.
	cipData := make([]byte, 16)
	// Interface handle(4) + timeout(2)
	binary.LittleEndian.PutUint16(cipData[6:8], 2) // CPF count
	// Null addr: type=0x0000, len=0
	binary.LittleEndian.PutUint16(cipData[8:10], 0x0000)
	binary.LittleEndian.PutUint16(cipData[10:12], 0)
	// Unconnected data: type=0x00B2, len=0
	binary.LittleEndian.PutUint16(cipData[12:14], 0x00B2)
	binary.LittleEndian.PutUint16(cipData[14:16], 0) // zero length!

	frame := buildENIPHeader(0x006F, sessionHandle, cipData)
	return AnomalyPacket{
		Name:        "zero_length_payload",
		Description: "SendRRData with zero-length CIP service data",
		Payload:     frame,
	}
}

// buildMaxLengthEPATH creates a request with a maximum-length EPATH.
func buildMaxLengthEPATH(sessionHandle uint32) AnomalyPacket {
	// Build a CIP request with 127 path words (254 bytes) of valid
	// class/instance segments. This is the maximum EPATH length.
	pathWords := 127
	pathBytes := pathWords * 2

	cipPayload := make([]byte, 2+pathBytes)
	cipPayload[0] = 0x0E // Get_Attribute_Single service
	cipPayload[1] = byte(pathWords)

	// Fill with alternating class/instance segments
	for i := 0; i < pathWords; i++ {
		offset := 2 + i*2
		if i%2 == 0 {
			cipPayload[offset] = 0x20   // 8-bit class segment
			cipPayload[offset+1] = 0x01 // Class 1 (Identity)
		} else {
			cipPayload[offset] = 0x24   // 8-bit instance segment
			cipPayload[offset+1] = 0x01 // Instance 1
		}
	}

	// Wrap in SendRRData CPF
	sendRRData := wrapInSendRRData(cipPayload)
	frame := buildENIPHeader(0x006F, sessionHandle, sendRRData)

	return AnomalyPacket{
		Name:        "max_length_epath",
		Description: "CIP request with 127-word EPATH (maximum length)",
		Payload:     frame,
	}
}

// buildReservedServiceCodes creates requests using reserved/unassigned CIP service codes.
func buildReservedServiceCodes(sessionHandle uint32) []AnomalyPacket {
	// Service codes 0x60-0x7F are vendor-specific, 0x20-0x2F are mostly reserved.
	reservedCodes := []uint8{0x20, 0x21, 0x3F, 0x60, 0x7F}
	var packets []AnomalyPacket

	for _, sc := range reservedCodes {
		cipPayload := []byte{
			sc,   // Reserved service code
			0x02, // Path size: 2 words
			0x20, 0x01, // Class 1
			0x24, 0x01, // Instance 1
		}
		sendRRData := wrapInSendRRData(cipPayload)
		frame := buildENIPHeader(0x006F, sessionHandle, sendRRData)

		packets = append(packets, AnomalyPacket{
			Name:        fmt.Sprintf("reserved_service_0x%02X", sc),
			Description: fmt.Sprintf("CIP request with reserved service code 0x%02X", sc),
			Payload:     frame,
		})
	}
	return packets
}

// buildUnusualCPFItems creates ENIP frames with unusual but valid CPF item types.
func buildUnusualCPFItems(sessionHandle uint32) []AnomalyPacket {
	// Valid but unusual CPF item types.
	unusualTypes := []struct {
		typeID uint16
		name   string
	}{
		{0x0086, "sockaddr_o2t"},    // Socket Address O→T
		{0x8000, "sequenced_addr"},  // Sequenced address
		{0x8002, "unconnected_msg"}, // Unconnected message
	}

	var packets []AnomalyPacket
	for _, ut := range unusualTypes {
		buf := make([]byte, 12)
		binary.LittleEndian.PutUint16(buf[6:8], 1) // CPF count: 1 item
		binary.LittleEndian.PutUint16(buf[8:10], ut.typeID)
		binary.LittleEndian.PutUint16(buf[10:12], 0) // Zero length

		frame := buildENIPHeader(0x006F, sessionHandle, buf)
		packets = append(packets, AnomalyPacket{
			Name:        fmt.Sprintf("unusual_cpf_%s", ut.name),
			Description: fmt.Sprintf("SendRRData with CPF item type 0x%04X (%s)", ut.typeID, ut.name),
			Payload:     frame,
		})
	}
	return packets
}

// buildMaxConnectionParams creates a ForwardOpen with extreme parameter values.
func buildMaxConnectionParams(sessionHandle uint32) AnomalyPacket {
	// ForwardOpen (service 0x54) with maximum RPI, connection sizes, etc.
	cipPayload := make([]byte, 40)
	cipPayload[0] = 0x54 // ForwardOpen service
	cipPayload[1] = 0x02 // Path size
	cipPayload[2] = 0x20 // Class segment
	cipPayload[3] = 0x06 // Connection Manager
	cipPayload[4] = 0x24 // Instance segment
	cipPayload[5] = 0x01 // Instance 1

	// After path: ForwardOpen parameters
	offset := 6
	cipPayload[offset] = 0x0A   // Priority/time tick
	cipPayload[offset+1] = 0xFF // Max timeout ticks
	// O→T network connection ID
	binary.LittleEndian.PutUint32(cipPayload[offset+2:], 0xFFFFFFFF)
	// T→O network connection ID
	binary.LittleEndian.PutUint32(cipPayload[offset+6:], 0xFFFFFFFE)
	// Connection serial
	binary.LittleEndian.PutUint16(cipPayload[offset+10:], 0xFFFF)
	// Originator vendor ID
	binary.LittleEndian.PutUint16(cipPayload[offset+12:], 0xFFFF)
	// Originator serial
	binary.LittleEndian.PutUint32(cipPayload[offset+14:], 0xFFFFFFFF)
	// Connection timeout multiplier
	cipPayload[offset+18] = 0xFF
	// RPI values (maximum = 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(cipPayload[offset+22:], 0xFFFFFFFF)
	// Connection size (max)
	binary.LittleEndian.PutUint16(cipPayload[offset+26:], 0xFFFF)

	sendRRData := wrapInSendRRData(cipPayload)
	frame := buildENIPHeader(0x006F, sessionHandle, sendRRData)

	return AnomalyPacket{
		Name:        "max_connection_params",
		Description: "ForwardOpen with maximum parameter values",
		Payload:     frame,
	}
}

// wrapInSendRRData wraps a CIP payload in a SendRRData CPF structure.
func wrapInSendRRData(cipPayload []byte) []byte {
	// Interface handle(4) + timeout(2) + CPF count(2) + null addr item(4) + data item header(4) + CIP data
	buf := make([]byte, 16+len(cipPayload))
	// Interface handle = 0, timeout = 0
	binary.LittleEndian.PutUint16(buf[6:8], 2) // CPF item count
	// Item 0: Null Address
	binary.LittleEndian.PutUint16(buf[8:10], 0x0000)
	binary.LittleEndian.PutUint16(buf[10:12], 0)
	// Item 1: Unconnected Data
	binary.LittleEndian.PutUint16(buf[12:14], 0x00B2)
	binary.LittleEndian.PutUint16(buf[14:16], uint16(len(cipPayload)))
	copy(buf[16:], cipPayload)
	return buf
}
