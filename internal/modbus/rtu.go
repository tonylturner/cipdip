package modbus

// RTU and ASCII over TCP framing with auto-detection.
//
// RTU: [UnitID(1)] [FC(1)] [Data(N)] [CRC-16(2)]
// ASCII: ':' [UnitID(2 hex)] [FC(2 hex)] [Data(2N hex)] [LRC(2 hex)] CR LF

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// RTU framing constants.
const (
	RTUMinFrameSize = 4  // unit_id + fc + crc(2)
	RTUMaxFrameSize = 256 // 1 + 253 PDU + 2 CRC
	RTUCRCSize      = 2
)

// ASCII framing constants.
const (
	ASCIIStartByte byte = ':' // 0x3A
	ASCIICRByte    byte = '\r'
	ASCIILFByte    byte = '\n'
	ASCIIMinLen         = 9 // : + unit(2) + fc(2) + lrc(2) + CR + LF
)

// DetectMode examines the first bytes of a TCP stream payload and returns
// the most likely Modbus transport mode.
//
// Detection order:
//  1. First byte ':' (0x3A) → ASCII
//  2. Bytes [2:4] == 0x0000 (protocol ID) → TCP (MBAP)
//  3. Otherwise → RTU (validated with CRC-16 if enough data)
func DetectMode(data []byte) TransportMode {
	if len(data) == 0 {
		return ModeTCP // default
	}
	// ASCII: starts with ':'
	if data[0] == ASCIIStartByte {
		return ModeASCII
	}
	// TCP (MBAP): check protocol ID at offset 2 and validate length field.
	if len(data) >= MBAPHeaderSize {
		protocolID := binary.BigEndian.Uint16(data[2:4])
		if protocolID == 0x0000 {
			length := binary.BigEndian.Uint16(data[4:6])
			// Length field = UnitID(1) + PDU. Must be >= 2 (unit + FC) and
			// the frame must actually contain that many bytes.
			if length >= 2 && int(length)+6 <= len(data) {
				return ModeTCP
			}
		}
	}
	// Default: RTU
	return ModeRTU
}

// --- RTU framing ---

// EncodeRequestRTU encodes a Modbus request into an RTU frame (with CRC-16).
func EncodeRequestRTU(req Request) []byte {
	pdu := make([]byte, 0, 2+len(req.Data)+RTUCRCSize)
	pdu = append(pdu, req.UnitID)
	pdu = append(pdu, byte(req.Function))
	pdu = append(pdu, req.Data...)
	crc := CRC16(pdu)
	pdu = append(pdu, byte(crc), byte(crc>>8)) // CRC is little-endian
	return pdu
}

// DecodeRequestRTU decodes a Modbus RTU frame into a Request.
func DecodeRequestRTU(data []byte) (Request, error) {
	if len(data) < RTUMinFrameSize {
		return Request{}, errTooShort("RTU frame", len(data), RTUMinFrameSize)
	}
	// Verify CRC
	payload := data[:len(data)-RTUCRCSize]
	gotCRC := uint16(data[len(data)-2]) | uint16(data[len(data)-1])<<8
	wantCRC := CRC16(payload)
	if gotCRC != wantCRC {
		return Request{}, fmt.Errorf("RTU CRC mismatch: got 0x%04X, want 0x%04X", gotCRC, wantCRC)
	}
	return Request{
		UnitID:   data[0],
		Function: FunctionCode(data[1]),
		Data:     cloneBytes(data[2 : len(data)-RTUCRCSize]),
	}, nil
}

// EncodeResponseRTU encodes a Modbus response into an RTU frame (with CRC-16).
func EncodeResponseRTU(resp Response) []byte {
	pdu := make([]byte, 0, 2+len(resp.Data)+RTUCRCSize)
	pdu = append(pdu, resp.UnitID)
	pdu = append(pdu, byte(resp.Function))
	pdu = append(pdu, resp.Data...)
	crc := CRC16(pdu)
	pdu = append(pdu, byte(crc), byte(crc>>8))
	return pdu
}

// DecodeResponseRTU decodes a Modbus RTU frame into a Response.
func DecodeResponseRTU(data []byte) (Response, error) {
	if len(data) < RTUMinFrameSize {
		return Response{}, errTooShort("RTU frame", len(data), RTUMinFrameSize)
	}
	payload := data[:len(data)-RTUCRCSize]
	gotCRC := uint16(data[len(data)-2]) | uint16(data[len(data)-1])<<8
	wantCRC := CRC16(payload)
	if gotCRC != wantCRC {
		return Response{}, fmt.Errorf("RTU CRC mismatch: got 0x%04X, want 0x%04X", gotCRC, wantCRC)
	}
	return Response{
		UnitID:   data[0],
		Function: FunctionCode(data[1]),
		Data:     cloneBytes(data[2 : len(data)-RTUCRCSize]),
	}, nil
}

// ValidateCRC checks the CRC-16 of an RTU frame.
func ValidateCRC(data []byte) bool {
	if len(data) < RTUMinFrameSize {
		return false
	}
	payload := data[:len(data)-RTUCRCSize]
	gotCRC := uint16(data[len(data)-2]) | uint16(data[len(data)-1])<<8
	return gotCRC == CRC16(payload)
}

// CRC16 computes the Modbus CRC-16 for the given data.
// Uses the standard Modbus polynomial 0xA001 (reflected form of 0x8005).
func CRC16(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&0x0001 != 0 {
				crc = (crc >> 1) ^ 0xA001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

// --- ASCII framing ---

// EncodeRequestASCII encodes a Modbus request into ASCII framing.
// Format: ':' + hex(UnitID + FC + Data) + hex(LRC) + CR + LF
func EncodeRequestASCII(req Request) []byte {
	pdu := make([]byte, 0, 2+len(req.Data))
	pdu = append(pdu, req.UnitID)
	pdu = append(pdu, byte(req.Function))
	pdu = append(pdu, req.Data...)
	lrc := LRC(pdu)

	hexStr := hex.EncodeToString(append(pdu, lrc))
	frame := make([]byte, 0, 1+len(hexStr)+2)
	frame = append(frame, ASCIIStartByte)
	frame = append(frame, toUpperHex(hexStr)...)
	frame = append(frame, ASCIICRByte, ASCIILFByte)
	return frame
}

// DecodeRequestASCII decodes a Modbus ASCII frame into a Request.
func DecodeRequestASCII(data []byte) (Request, error) {
	raw, err := decodeASCIIFrame(data)
	if err != nil {
		return Request{}, err
	}
	if len(raw) < 2 {
		return Request{}, errTooShort("ASCII PDU", len(raw), 2)
	}
	// Last byte is LRC
	payload := raw[:len(raw)-1]
	gotLRC := raw[len(raw)-1]
	wantLRC := LRC(payload)
	if gotLRC != wantLRC {
		return Request{}, fmt.Errorf("ASCII LRC mismatch: got 0x%02X, want 0x%02X", gotLRC, wantLRC)
	}
	return Request{
		UnitID:   payload[0],
		Function: FunctionCode(payload[1]),
		Data:     cloneBytes(payload[2:]),
	}, nil
}

// EncodeResponseASCII encodes a Modbus response into ASCII framing.
func EncodeResponseASCII(resp Response) []byte {
	pdu := make([]byte, 0, 2+len(resp.Data))
	pdu = append(pdu, resp.UnitID)
	pdu = append(pdu, byte(resp.Function))
	pdu = append(pdu, resp.Data...)
	lrc := LRC(pdu)

	hexStr := hex.EncodeToString(append(pdu, lrc))
	frame := make([]byte, 0, 1+len(hexStr)+2)
	frame = append(frame, ASCIIStartByte)
	frame = append(frame, toUpperHex(hexStr)...)
	frame = append(frame, ASCIICRByte, ASCIILFByte)
	return frame
}

// DecodeResponseASCII decodes a Modbus ASCII frame into a Response.
func DecodeResponseASCII(data []byte) (Response, error) {
	raw, err := decodeASCIIFrame(data)
	if err != nil {
		return Response{}, err
	}
	if len(raw) < 2 {
		return Response{}, errTooShort("ASCII PDU", len(raw), 2)
	}
	payload := raw[:len(raw)-1]
	gotLRC := raw[len(raw)-1]
	wantLRC := LRC(payload)
	if gotLRC != wantLRC {
		return Response{}, fmt.Errorf("ASCII LRC mismatch: got 0x%02X, want 0x%02X", gotLRC, wantLRC)
	}
	return Response{
		UnitID:   payload[0],
		Function: FunctionCode(payload[1]),
		Data:     cloneBytes(payload[2:]),
	}, nil
}

// LRC computes the Longitudinal Redundancy Check for Modbus ASCII.
// LRC = two's complement of sum of all bytes.
func LRC(data []byte) byte {
	var sum byte
	for _, b := range data {
		sum += b
	}
	return (^sum) + 1
}

// ValidateLRC verifies the LRC of a decoded ASCII payload.
func ValidateLRC(payload []byte) bool {
	if len(payload) < 2 {
		return false
	}
	data := payload[:len(payload)-1]
	gotLRC := payload[len(payload)-1]
	return gotLRC == LRC(data)
}

// --- internal ASCII helpers ---

// decodeASCIIFrame strips the ':' prefix and CR/LF suffix, then hex-decodes.
func decodeASCIIFrame(data []byte) ([]byte, error) {
	if len(data) < ASCIIMinLen {
		return nil, errTooShort("ASCII frame", len(data), ASCIIMinLen)
	}
	if data[0] != ASCIIStartByte {
		return nil, fmt.Errorf("ASCII frame missing start byte: got 0x%02X", data[0])
	}
	// Find end: CR LF
	end := len(data)
	if data[end-1] == ASCIILFByte {
		end--
	}
	if end > 0 && data[end-1] == ASCIICRByte {
		end--
	}
	hexData := data[1:end]
	if len(hexData)%2 != 0 {
		return nil, fmt.Errorf("ASCII frame hex data has odd length: %d", len(hexData))
	}
	raw := make([]byte, len(hexData)/2)
	_, err := hex.Decode(raw, hexData)
	if err != nil {
		return nil, fmt.Errorf("ASCII frame hex decode: %w", err)
	}
	return raw, nil
}

// toUpperHex converts a lowercase hex string to uppercase.
func toUpperHex(s string) []byte {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'f' {
			b[i] = c - 32
		}
	}
	return b
}
