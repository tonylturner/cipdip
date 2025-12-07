package cipclient

// EtherNet/IP (ENIP) protocol handling

import (
	"encoding/binary"
	"fmt"
)

// ENIP command codes
const (
	ENIPCommandRegisterSession    uint16 = 0x0065
	ENIPCommandUnregisterSession  uint16 = 0x0066
	ENIPCommandSendRRData         uint16 = 0x006F
	ENIPCommandSendUnitData       uint16 = 0x0070
	ENIPCommandListIdentity       uint16 = 0x0063
	ENIPCommandListServices       uint16 = 0x0004
	ENIPCommandListInterfaces     uint16 = 0x0064
)

// ENIP status codes
const (
	ENIPStatusSuccess uint32 = 0x00000000
)

// ENIPEncapsulation represents an EtherNet/IP encapsulation header
type ENIPEncapsulation struct {
	Command     uint16
	Length      uint16
	SessionID   uint32
	Status      uint32
	SenderContext [8]byte
	Options     uint32
	Data        []byte
}

// EncodeENIP encodes an EtherNet/IP encapsulation packet
func EncodeENIP(encap ENIPEncapsulation) []byte {
	// EtherNet/IP encapsulation header is 24 bytes
	header := make([]byte, 24)

	// Command (2 bytes, big-endian)
	binary.BigEndian.PutUint16(header[0:2], encap.Command)

	// Length (2 bytes, big-endian) - length of data field
	binary.BigEndian.PutUint16(header[2:4], uint16(len(encap.Data)))

	// Session Handle (4 bytes, big-endian)
	binary.BigEndian.PutUint32(header[4:8], encap.SessionID)

	// Status (4 bytes, big-endian)
	binary.BigEndian.PutUint32(header[8:12], encap.Status)

	// Sender Context (8 bytes)
	copy(header[12:20], encap.SenderContext[:])

	// Options (4 bytes, big-endian)
	binary.BigEndian.PutUint32(header[20:24], encap.Options)

	// Append data
	packet := append(header, encap.Data...)

	return packet
}

// DecodeENIP decodes an EtherNet/IP encapsulation packet
func DecodeENIP(data []byte) (ENIPEncapsulation, error) {
	if len(data) < 24 {
		return ENIPEncapsulation{}, fmt.Errorf("packet too short: %d bytes (minimum 24)", len(data))
	}

	var encap ENIPEncapsulation

	encap.Command = binary.BigEndian.Uint16(data[0:2])
	encap.Length = binary.BigEndian.Uint16(data[2:4])
	encap.SessionID = binary.BigEndian.Uint32(data[4:8])
	encap.Status = binary.BigEndian.Uint32(data[8:12])
	copy(encap.SenderContext[:], data[12:20])
	encap.Options = binary.BigEndian.Uint32(data[20:24])

	// Extract data field
	if len(data) > 24 {
		encap.Data = data[24:]
	}

	return encap, nil
}

// BuildSendRRData builds a SendRRData encapsulation for UCMM
func BuildSendRRData(sessionID uint32, senderContext [8]byte, cipData []byte) []byte {
	// SendRRData structure:
	// - Interface Handle (4 bytes, always 0 for UCMM)
	// - Timeout (2 bytes, typically 0)
	// - CIP data (variable length)

	var sendData []byte

	// Interface Handle (4 bytes, 0 for UCMM)
	sendData = binary.BigEndian.AppendUint32(sendData, 0)

	// Timeout (2 bytes, 0 = no timeout)
	sendData = binary.BigEndian.AppendUint16(sendData, 0)

	// CIP data
	sendData = append(sendData, cipData...)

	encap := ENIPEncapsulation{
		Command:      ENIPCommandSendRRData,
		Length:       uint16(len(sendData)),
		SessionID:    sessionID,
		Status:       0,
		SenderContext: senderContext,
		Options:      0,
		Data:         sendData,
	}

	return EncodeENIP(encap)
}

// BuildSendUnitData builds a SendUnitData encapsulation for connected messaging
func BuildSendUnitData(sessionID uint32, senderContext [8]byte, connectionID uint32, cipData []byte) []byte {
	// SendUnitData structure:
	// - Connection ID (4 bytes)
	// - CIP data (variable length)

	var sendData []byte

	// Connection ID (4 bytes)
	sendData = binary.BigEndian.AppendUint32(sendData, connectionID)

	// CIP data
	sendData = append(sendData, cipData...)

	encap := ENIPEncapsulation{
		Command:      ENIPCommandSendUnitData,
		Length:       uint16(len(sendData)),
		SessionID:    sessionID,
		Status:       0,
		SenderContext: senderContext,
		Options:      0,
		Data:         sendData,
	}

	return EncodeENIP(encap)
}

// BuildRegisterSession builds a RegisterSession encapsulation
func BuildRegisterSession(senderContext [8]byte) []byte {
	// RegisterSession data:
	// - Protocol Version (2 bytes, typically 1)
	// - Option Flags (2 bytes, typically 0)

	var regData []byte
	regData = binary.BigEndian.AppendUint16(regData, 1) // Protocol version
	regData = binary.BigEndian.AppendUint16(regData, 0) // Option flags

	encap := ENIPEncapsulation{
		Command:      ENIPCommandRegisterSession,
		Length:       uint16(len(regData)),
		SessionID:    0, // Will be set by server
		Status:       0,
		SenderContext: senderContext,
		Options:      0,
		Data:         regData,
	}

	return EncodeENIP(encap)
}

// BuildUnregisterSession builds an UnregisterSession encapsulation
func BuildUnregisterSession(sessionID uint32, senderContext [8]byte) []byte {
	encap := ENIPEncapsulation{
		Command:      ENIPCommandUnregisterSession,
		Length:       0,
		SessionID:    sessionID,
		Status:       0,
		SenderContext: senderContext,
		Options:      0,
		Data:         nil,
	}

	return EncodeENIP(encap)
}

// BuildListIdentity builds a ListIdentity encapsulation
func BuildListIdentity(senderContext [8]byte) []byte {
	encap := ENIPEncapsulation{
		Command:      ENIPCommandListIdentity,
		Length:       0,
		SessionID:    0,
		Status:       0,
		SenderContext: senderContext,
		Options:      0,
		Data:         nil,
	}

	return EncodeENIP(encap)
}

// ParseSendRRDataResponse parses the response from SendRRData
func ParseSendRRDataResponse(data []byte) ([]byte, error) {
	// SendRRData response structure:
	// - Interface Handle (4 bytes)
	// - Timeout (2 bytes)
	// - CIP data (variable length)

	if len(data) < 6 {
		return nil, fmt.Errorf("response too short: %d bytes (minimum 6)", len(data))
	}

	// Skip Interface Handle (4 bytes) and Timeout (2 bytes)
	cipData := data[6:]

	return cipData, nil
}

// ParseSendUnitDataResponse parses the response from SendUnitData
func ParseSendUnitDataResponse(data []byte) ([]byte, error) {
	// SendUnitData response structure:
	// - Connection ID (4 bytes)
	// - CIP data (variable length)

	if len(data) < 4 {
		return nil, fmt.Errorf("response too short: %d bytes (minimum 4)", len(data))
	}

	// Skip Connection ID (4 bytes)
	cipData := data[4:]

	return cipData, nil
}
