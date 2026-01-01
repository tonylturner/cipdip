package cipclient

// EtherNet/IP (ENIP) protocol handling

import (
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
	ENIPStatusSuccess              uint32 = 0x00000000
	ENIPStatusInvalidCommand        uint32 = 0x00000001
	ENIPStatusInsufficientMemory    uint32 = 0x00000002
	ENIPStatusIncorrectData         uint32 = 0x00000003
	ENIPStatusInvalidSessionHandle  uint32 = 0x0064
	ENIPStatusInvalidLength          uint32 = 0x0065
	ENIPStatusUnsupportedCommand    uint32 = 0x0066
)

// ENIPStatus represents an ENIP status code
type ENIPStatus uint32

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

// CPF item type IDs
const (
	CPFItemNullAddress      uint16 = 0x0000
	CPFItemConnectedAddress uint16 = 0x00A1
	CPFItemConnectedData    uint16 = 0x00B1
	CPFItemUnconnectedData  uint16 = 0x00B2
)

// CPFItem represents a Common Packet Format item.
type CPFItem struct {
	TypeID uint16
	Data   []byte
}

// EncodeENIP encodes an EtherNet/IP encapsulation packet
func EncodeENIP(encap ENIPEncapsulation) []byte {
	// EtherNet/IP encapsulation header is 24 bytes
	header := make([]byte, 24)
	order := currentENIPByteOrder()

	// Command (2 bytes, per ENIP byte order)
	order.PutUint16(header[0:2], encap.Command)

	// Length (2 bytes) - length of data field
	order.PutUint16(header[2:4], uint16(len(encap.Data)))

	// Session Handle (4 bytes)
	order.PutUint32(header[4:8], encap.SessionID)

	// Status (4 bytes)
	order.PutUint32(header[8:12], encap.Status)

	// Sender Context (8 bytes)
	copy(header[12:20], encap.SenderContext[:])

	// Options (4 bytes)
	order.PutUint32(header[20:24], encap.Options)

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
	order := currentENIPByteOrder()

	encap.Command = order.Uint16(data[0:2])
	encap.Length = order.Uint16(data[2:4])
	encap.SessionID = order.Uint32(data[4:8])
	encap.Status = order.Uint32(data[8:12])
	copy(encap.SenderContext[:], data[12:20])
	encap.Options = order.Uint32(data[20:24])

	// Extract data field
	if len(data) > 24 {
		encap.Data = data[24:]
	}

	return encap, nil
}

// BuildSendRRData builds a SendRRData encapsulation for UCMM
func BuildSendRRData(sessionID uint32, senderContext [8]byte, cipData []byte) []byte {
	sendData := BuildSendRRDataPayload(cipData)

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
	sendData := BuildSendUnitDataPayload(connectionID, cipData)

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
	order := currentENIPByteOrder()
	regData = appendUint16(order, regData, 1) // Protocol version
	regData = appendUint16(order, regData, 0) // Option flags

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

// BuildSendRRDataPayload builds the SendRRData data field (interface handle + timeout + CPF/CIP).
func BuildSendRRDataPayload(cipData []byte) []byte {
	var sendData []byte
	order := currentENIPByteOrder()
	profile := CurrentProtocolProfile()

	sendData = appendUint32(order, sendData, 0) // Interface handle
	sendData = appendUint16(order, sendData, 0) // Timeout

	if profile.UseCPF {
		cpf := EncodeCPFItems([]CPFItem{
			{TypeID: CPFItemNullAddress, Data: nil},
			{TypeID: CPFItemUnconnectedData, Data: cipData},
		})
		sendData = append(sendData, cpf...)
	} else {
		sendData = append(sendData, cipData...)
	}

	return sendData
}

// BuildSendUnitDataPayload builds the SendUnitData data field (interface handle + timeout + CPF/legacy).
func BuildSendUnitDataPayload(connectionID uint32, cipData []byte) []byte {
	var sendData []byte
	order := currentENIPByteOrder()
	profile := CurrentProtocolProfile()

	if profile.UseCPF {
		sendData = appendUint32(order, sendData, 0) // Interface handle
		sendData = appendUint16(order, sendData, 0) // Timeout
		cpf := EncodeCPFItems([]CPFItem{
			{TypeID: CPFItemConnectedAddress, Data: encodeConnectionID(connectionID)},
			{TypeID: CPFItemConnectedData, Data: cipData},
		})
		sendData = append(sendData, cpf...)
	} else {
		sendData = appendUint32(order, sendData, connectionID)
		sendData = append(sendData, cipData...)
	}

	return sendData
}

// ParseSendRRDataRequest extracts CIP data from a SendRRData request.
func ParseSendRRDataRequest(data []byte) ([]byte, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("SendRRData data too short: %d bytes (minimum 6)", len(data))
	}

	profile := CurrentProtocolProfile()
	payload := data[6:]
	if !profile.UseCPF {
		return payload, nil
	}

	items, err := ParseCPFItems(payload)
	if err != nil {
		return nil, err
	}

	for _, item := range items {
		if item.TypeID == CPFItemUnconnectedData {
			return item.Data, nil
		}
	}

	return nil, fmt.Errorf("missing unconnected data item")
}

// ParseSendUnitDataRequest extracts connection ID and data from a SendUnitData request.
func ParseSendUnitDataRequest(data []byte) (uint32, []byte, error) {
	profile := CurrentProtocolProfile()
	order := currentENIPByteOrder()

	if !profile.UseCPF {
		if len(data) < 4 {
			return 0, nil, fmt.Errorf("SendUnitData data too short: %d bytes (minimum 4)", len(data))
		}
		connID := order.Uint32(data[0:4])
		return connID, data[4:], nil
	}

	if len(data) < 6 {
		return 0, nil, fmt.Errorf("SendUnitData data too short: %d bytes (minimum 6)", len(data))
	}

	items, err := ParseCPFItems(data[6:])
	if err != nil {
		return 0, nil, err
	}

	var connID uint32
	var payload []byte
	for _, item := range items {
		switch item.TypeID {
		case CPFItemConnectedAddress:
			if len(item.Data) < 4 {
				return 0, nil, fmt.Errorf("connected address item too short")
			}
			connID = order.Uint32(item.Data[0:4])
		case CPFItemConnectedData:
			payload = item.Data
		}
	}

	if connID == 0 {
		return 0, nil, fmt.Errorf("missing connected address item")
	}
	if payload == nil {
		return 0, nil, fmt.Errorf("missing connected data item")
	}

	return connID, payload, nil
}

// ParseSendRRDataResponse parses the response from SendRRData
func ParseSendRRDataResponse(data []byte) ([]byte, error) {
	return ParseSendRRDataRequest(data)
}

// ParseSendUnitDataResponse parses the response from SendUnitData
func ParseSendUnitDataResponse(data []byte) ([]byte, error) {
	_, payload, err := ParseSendUnitDataRequest(data)
	return payload, err
}

// EncodeCPFItems encodes items in Common Packet Format.
func EncodeCPFItems(items []CPFItem) []byte {
	order := currentENIPByteOrder()
	data := make([]byte, 0, 4*len(items)+2)
	data = appendUint16(order, data, uint16(len(items)))
	for _, item := range items {
		data = appendUint16(order, data, item.TypeID)
		data = appendUint16(order, data, uint16(len(item.Data)))
		data = append(data, item.Data...)
	}
	return data
}

// ParseCPFItems decodes Common Packet Format items.
func ParseCPFItems(data []byte) ([]CPFItem, error) {
	order := currentENIPByteOrder()
	if len(data) < 2 {
		return nil, fmt.Errorf("CPF data too short")
	}

	count := int(order.Uint16(data[0:2]))
	offset := 2
	items := make([]CPFItem, 0, count)
	for i := 0; i < count; i++ {
		if len(data) < offset+4 {
			return nil, fmt.Errorf("CPF item header too short")
		}
		typeID := order.Uint16(data[offset : offset+2])
		length := int(order.Uint16(data[offset+2 : offset+4]))
		offset += 4
		if len(data) < offset+length {
			return nil, fmt.Errorf("CPF item data too short")
		}
		itemData := data[offset : offset+length]
		offset += length
		items = append(items, CPFItem{TypeID: typeID, Data: itemData})
	}

	return items, nil
}

func encodeConnectionID(connectionID uint32) []byte {
	order := currentENIPByteOrder()
	var buf [4]byte
	order.PutUint32(buf[:], connectionID)
	return buf[:]
}
