package modbus

// Modbus TCP (MBAP) codec: encode and decode Modbus PDUs with MBAP framing.

import (
	"encoding/binary"
	"fmt"
)

// errTooShort returns a standardised validation error for short buffers.
func errTooShort(what string, got, need int) error {
	return fmt.Errorf("%s too short: %d bytes (minimum %d)", what, got, need)
}

// MinPDUSize is the minimum PDU size (function code only).
const MinPDUSize = 1

// MaxPDUSize is the maximum Modbus PDU size (253 bytes per spec).
const MaxPDUSize = 253

// MaxADUSize is the maximum Modbus TCP ADU size (MBAP header + PDU).
const MaxADUSize = MBAPHeaderSize + MaxPDUSize

// EncodeRequestTCP encodes a Modbus request into a TCP (MBAP) frame.
func EncodeRequestTCP(req Request) []byte {
	pduLen := 1 + len(req.Data) // function code + data
	h := MBAPHeader{
		TransactionID: req.TransactionID,
		ProtocolID:    0x0000,
		Length:        uint16(1 + pduLen), // UnitID + PDU
		UnitID:        req.UnitID,
	}
	buf := EncodeMBAPHeader(h)
	buf = append(buf, byte(req.Function))
	buf = append(buf, req.Data...)
	return buf
}

// DecodeRequestTCP decodes a Modbus TCP (MBAP) frame into a Request.
func DecodeRequestTCP(data []byte) (Request, error) {
	hdr, err := DecodeMBAPHeader(data)
	if err != nil {
		return Request{}, err
	}
	if hdr.ProtocolID != 0x0000 {
		return Request{}, fmt.Errorf("invalid Modbus protocol ID: 0x%04X", hdr.ProtocolID)
	}
	// Length field covers UnitID (1 byte) + PDU.
	pduStart := MBAPHeaderSize
	pduEnd := MBAPHeaderSize + int(hdr.Length) - 1 // subtract 1 for UnitID already in header
	if pduEnd > len(data) {
		return Request{}, errTooShort("Modbus TCP frame", len(data), pduEnd)
	}
	if pduEnd < pduStart+1 {
		return Request{}, errTooShort("Modbus PDU", pduEnd-pduStart, MinPDUSize)
	}
	return Request{
		TransactionID: hdr.TransactionID,
		UnitID:        hdr.UnitID,
		Function:      FunctionCode(data[pduStart]),
		Data:          cloneBytes(data[pduStart+1 : pduEnd]),
	}, nil
}

// EncodeResponseTCP encodes a Modbus response into a TCP (MBAP) frame.
func EncodeResponseTCP(resp Response) []byte {
	pduLen := 1 + len(resp.Data) // function code + data
	h := MBAPHeader{
		TransactionID: resp.TransactionID,
		ProtocolID:    0x0000,
		Length:        uint16(1 + pduLen), // UnitID + PDU
		UnitID:        resp.UnitID,
	}
	buf := EncodeMBAPHeader(h)
	buf = append(buf, byte(resp.Function))
	buf = append(buf, resp.Data...)
	return buf
}

// DecodeResponseTCP decodes a Modbus TCP (MBAP) frame into a Response.
func DecodeResponseTCP(data []byte) (Response, error) {
	hdr, err := DecodeMBAPHeader(data)
	if err != nil {
		return Response{}, err
	}
	if hdr.ProtocolID != 0x0000 {
		return Response{}, fmt.Errorf("invalid Modbus protocol ID: 0x%04X", hdr.ProtocolID)
	}
	pduStart := MBAPHeaderSize
	pduEnd := MBAPHeaderSize + int(hdr.Length) - 1
	if pduEnd > len(data) {
		return Response{}, errTooShort("Modbus TCP frame", len(data), pduEnd)
	}
	if pduEnd < pduStart+1 {
		return Response{}, errTooShort("Modbus PDU", pduEnd-pduStart, MinPDUSize)
	}
	return Response{
		TransactionID: hdr.TransactionID,
		UnitID:        hdr.UnitID,
		Function:      FunctionCode(data[pduStart]),
		Data:          cloneBytes(data[pduStart+1 : pduEnd]),
	}, nil
}

// EncodeExceptionResponse creates an exception response frame (TCP).
func EncodeExceptionResponse(transactionID uint16, unitID uint8, fc FunctionCode, exc ExceptionCode) []byte {
	return EncodeResponseTCP(Response{
		TransactionID: transactionID,
		UnitID:        unitID,
		Function:      fc | 0x80,
		Data:          []byte{byte(exc)},
	})
}

// --- PDU-level helpers (function-code-specific request builders) ---

// ReadCoilsRequest builds the data payload for FC 0x01 (Read Coils).
func ReadCoilsRequest(startAddr uint16, quantity uint16) []byte {
	return encodeAddrQty(startAddr, quantity)
}

// ReadDiscreteInputsRequest builds the data payload for FC 0x02.
func ReadDiscreteInputsRequest(startAddr uint16, quantity uint16) []byte {
	return encodeAddrQty(startAddr, quantity)
}

// ReadHoldingRegistersRequest builds the data payload for FC 0x03.
func ReadHoldingRegistersRequest(startAddr uint16, quantity uint16) []byte {
	return encodeAddrQty(startAddr, quantity)
}

// ReadInputRegistersRequest builds the data payload for FC 0x04.
func ReadInputRegistersRequest(startAddr uint16, quantity uint16) []byte {
	return encodeAddrQty(startAddr, quantity)
}

// WriteSingleCoilRequest builds the data payload for FC 0x05.
// value should be true (ON = 0xFF00) or false (OFF = 0x0000).
func WriteSingleCoilRequest(addr uint16, value bool) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], addr)
	if value {
		binary.BigEndian.PutUint16(buf[2:4], 0xFF00)
	}
	return buf
}

// WriteSingleRegisterRequest builds the data payload for FC 0x06.
func WriteSingleRegisterRequest(addr uint16, value uint16) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], addr)
	binary.BigEndian.PutUint16(buf[2:4], value)
	return buf
}

// WriteMultipleCoilsRequest builds the data payload for FC 0x0F.
func WriteMultipleCoilsRequest(startAddr uint16, quantity uint16, values []byte) []byte {
	byteCount := byte((quantity + 7) / 8)
	buf := make([]byte, 5+int(byteCount))
	binary.BigEndian.PutUint16(buf[0:2], startAddr)
	binary.BigEndian.PutUint16(buf[2:4], quantity)
	buf[4] = byteCount
	copy(buf[5:], values)
	return buf
}

// WriteMultipleRegistersRequest builds the data payload for FC 0x10.
func WriteMultipleRegistersRequest(startAddr uint16, quantity uint16, values []byte) []byte {
	byteCount := byte(quantity * 2)
	buf := make([]byte, 5+int(byteCount))
	binary.BigEndian.PutUint16(buf[0:2], startAddr)
	binary.BigEndian.PutUint16(buf[2:4], quantity)
	buf[4] = byteCount
	copy(buf[5:], values)
	return buf
}

// MaskWriteRegisterRequest builds the data payload for FC 0x16.
func MaskWriteRegisterRequest(addr uint16, andMask uint16, orMask uint16) []byte {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint16(buf[0:2], addr)
	binary.BigEndian.PutUint16(buf[2:4], andMask)
	binary.BigEndian.PutUint16(buf[4:6], orMask)
	return buf
}

// --- PDU-level response parsing helpers ---

// DecodeReadRegistersResponse parses the data field of a read registers
// response (FC 0x03 or 0x04) into a slice of uint16 register values.
func DecodeReadRegistersResponse(data []byte) ([]uint16, error) {
	if len(data) < 1 {
		return nil, errTooShort("read registers response", len(data), 1)
	}
	byteCount := int(data[0])
	if len(data) < 1+byteCount {
		return nil, errTooShort("read registers response data", len(data), 1+byteCount)
	}
	if byteCount%2 != 0 {
		return nil, fmt.Errorf("odd byte count in register response: %d", byteCount)
	}
	regs := make([]uint16, byteCount/2)
	for i := range regs {
		regs[i] = binary.BigEndian.Uint16(data[1+i*2 : 1+i*2+2])
	}
	return regs, nil
}

// DecodeReadCoilsResponse parses the data field of a read coils/discrete
// inputs response (FC 0x01 or 0x02) into a byte slice of coil values.
func DecodeReadCoilsResponse(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, errTooShort("read coils response", len(data), 1)
	}
	byteCount := int(data[0])
	if len(data) < 1+byteCount {
		return nil, errTooShort("read coils response data", len(data), 1+byteCount)
	}
	out := make([]byte, byteCount)
	copy(out, data[1:1+byteCount])
	return out, nil
}

// IsModbusTCP returns true if data appears to be a Modbus TCP (MBAP) frame.
// It checks for protocol ID 0x0000 and plausible length.
func IsModbusTCP(data []byte) bool {
	if len(data) < MBAPHeaderSize+1 {
		return false
	}
	protocolID := binary.BigEndian.Uint16(data[2:4])
	if protocolID != 0x0000 {
		return false
	}
	length := binary.BigEndian.Uint16(data[4:6])
	if length < 2 || length > MaxPDUSize+1 {
		return false
	}
	// Check that the function code byte is a known function code.
	fc := FunctionCode(data[MBAPHeaderSize])
	return IsKnownFunction(fc) || IsKnownFunction(fc&0x7F)
}

// --- internal helpers ---

func encodeAddrQty(addr, qty uint16) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], addr)
	binary.BigEndian.PutUint16(buf[2:4], qty)
	return buf
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
