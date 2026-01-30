package pccc

// PCCC message encoding and decoding.
//
// PCCC messages have this structure when tunneled via CIP Execute PCCC (0x4B):
//   CMD (1) | STS (1) | TNS (2 LE) | [FNC (1)] | [Data...]
//
// The CMD byte determines whether FNC is present (CmdExtended uses FNC,
// simple commands like CmdProtectedRead/Write do not).

import (
	"encoding/binary"
	"fmt"
)

// MinRequestLen is the minimum PCCC request length (CMD + STS + TNS).
const MinRequestLen = 4

// EncodeRequest encodes a PCCC request into bytes.
func EncodeRequest(req Request) []byte {
	size := 4 // CMD + STS + TNS
	hasFnc := req.Command.HasFunctionCode()
	if hasFnc {
		size++ // FNC byte
	}
	size += len(req.Data)

	buf := make([]byte, size)
	buf[0] = uint8(req.Command)
	buf[1] = req.Status
	binary.LittleEndian.PutUint16(buf[2:4], req.TNS)

	offset := 4
	if hasFnc {
		buf[offset] = uint8(req.Function)
		offset++
	}
	copy(buf[offset:], req.Data)

	return buf
}

// DecodeRequest decodes a PCCC request from bytes.
func DecodeRequest(data []byte) (Request, error) {
	if len(data) < MinRequestLen {
		return Request{}, fmt.Errorf("PCCC request too short: %d bytes (minimum %d)", len(data), MinRequestLen)
	}

	req := Request{
		Command: Command(data[0]),
		Status:  data[1],
		TNS:     binary.LittleEndian.Uint16(data[2:4]),
	}

	offset := 4
	if req.Command.HasFunctionCode() {
		if len(data) < 5 {
			return Request{}, fmt.Errorf("PCCC extended command missing function code")
		}
		req.Function = FunctionCode(data[offset])
		offset++
	}

	if offset < len(data) {
		req.Data = make([]byte, len(data)-offset)
		copy(req.Data, data[offset:])
	}

	return req, nil
}

// EncodeResponse encodes a PCCC response into bytes.
func EncodeResponse(resp Response) []byte {
	size := 4 // CMD + STS + TNS
	hasFnc := resp.Command.HasFunctionCode()
	if hasFnc {
		size++ // FNC byte
	}
	if resp.Status != 0 {
		size++ // ExtSTS byte
	}
	size += len(resp.Data)

	buf := make([]byte, size)
	buf[0] = uint8(resp.Command)
	buf[1] = resp.Status
	binary.LittleEndian.PutUint16(buf[2:4], resp.TNS)

	offset := 4
	if hasFnc {
		buf[offset] = uint8(resp.Function)
		offset++
	}
	if resp.Status != 0 {
		buf[offset] = resp.ExtSTS
		offset++
	}
	copy(buf[offset:], resp.Data)

	return buf
}

// DecodeResponse decodes a PCCC response from bytes.
func DecodeResponse(data []byte) (Response, error) {
	if len(data) < MinRequestLen {
		return Response{}, fmt.Errorf("PCCC response too short: %d bytes (minimum %d)", len(data), MinRequestLen)
	}

	resp := Response{
		Command: Command(data[0]),
		Status:  data[1],
		TNS:     binary.LittleEndian.Uint16(data[2:4]),
	}

	offset := 4
	if resp.Command.HasFunctionCode() {
		if len(data) < 5 {
			return Response{}, fmt.Errorf("PCCC extended response missing function code")
		}
		resp.Function = FunctionCode(data[offset])
		offset++
	}

	if resp.Status != 0 && offset < len(data) {
		resp.ExtSTS = data[offset]
		offset++
	}

	if offset < len(data) {
		resp.Data = make([]byte, len(data)-offset)
		copy(resp.Data, data[offset:])
	}

	return resp, nil
}

// TypedReadRequest builds a Typed Read request (CMD 0x0F, FNC 0x68).
func TypedReadRequest(tns uint16, addr Address, byteCount uint8) Request {
	data := buildAddressData(addr, byteCount)
	return Request{
		Command:  CmdExtended,
		Status:   0,
		TNS:      tns,
		Function: FncTypedRead,
		Data:     data,
	}
}

// TypedWriteRequest builds a Typed Write request (CMD 0x0F, FNC 0x67).
func TypedWriteRequest(tns uint16, addr Address, writeData []byte) Request {
	data := buildAddressData(addr, uint8(len(writeData)))
	data = append(data, writeData...)
	return Request{
		Command:  CmdExtended,
		Status:   0,
		TNS:      tns,
		Function: FncTypedWrite,
		Data:     data,
	}
}

// EchoRequest builds an Echo request (CMD 0x0F, FNC 0x06).
func EchoRequest(tns uint16, payload []byte) Request {
	return Request{
		Command:  CmdExtended,
		Status:   0,
		TNS:      tns,
		Function: FncEcho,
		Data:     payload,
	}
}

// DiagnosticStatusRequest builds a diagnostic status request.
func DiagnosticStatusRequest(tns uint16) Request {
	return Request{
		Command:  CmdExtended,
		Status:   0,
		TNS:      tns,
		Function: FncDiagnosticRead,
	}
}

// buildAddressData encodes the address fields for typed read/write.
// Format: byte_count(1), file_number(1), file_type(1), element_lo(1), element_hi(1), [sub_element(1)]
func buildAddressData(addr Address, byteCount uint8) []byte {
	// For element > 255, use 3-address format
	if addr.Element > 255 {
		data := make([]byte, 5)
		data[0] = byteCount
		data[1] = addr.FileNumber
		data[2] = uint8(addr.FileType)
		data[3] = uint8(addr.Element & 0xFF)
		data[4] = uint8(addr.Element >> 8)
		if addr.HasSub {
			data = append(data, addr.SubElement)
		}
		return data
	}

	data := make([]byte, 4)
	data[0] = byteCount
	data[1] = addr.FileNumber
	data[2] = uint8(addr.FileType)
	data[3] = uint8(addr.Element)
	if addr.HasSub {
		data = append(data, addr.SubElement)
	}
	return data
}

// DecodeTypedReadData extracts the address fields from a typed read/write request's Data.
// Returns the parsed address and remaining data (empty for reads, write data for writes).
func DecodeTypedReadData(data []byte) (byteCount uint8, addr Address, remaining []byte, err error) {
	if len(data) < 4 {
		return 0, Address{}, nil, fmt.Errorf("typed read data too short: %d bytes (minimum 4)", len(data))
	}

	byteCount = data[0]
	addr.FileNumber = data[1]
	addr.FileType = FileType(data[2])
	addr.Element = uint16(data[3])

	offset := 4
	// Check if there's a sub-element or high byte for element
	if offset < len(data) {
		// Heuristic: if this is a structured type, next byte is sub-element
		if isStructuredType(addr.FileType) && offset < len(data) {
			addr.SubElement = data[offset]
			addr.HasSub = true
			offset++
		}
	}

	if offset < len(data) {
		remaining = data[offset:]
	}

	return byteCount, addr, remaining, nil
}

// isStructuredType returns true for file types that use sub-elements.
func isStructuredType(ft FileType) bool {
	switch ft {
	case FileTypeTimer, FileTypeCounter, FileTypeControl:
		return true
	default:
		return false
	}
}

// IsPCCCPayload performs a heuristic check to determine if a byte slice
// looks like a PCCC request or response. Used for protocol detection.
func IsPCCCPayload(data []byte) bool {
	if len(data) < MinRequestLen {
		return false
	}

	cmd := Command(data[0])
	sts := data[1]

	// Check for known command codes
	switch cmd {
	case CmdProtectedWrite, CmdUnprotectedRead, CmdProtectedRead,
		CmdUnprotectedWrite, CmdExtended:
		// Valid command
	default:
		return false
	}

	// For requests, status should be 0
	// For responses, status can be non-zero but should be in range
	if sts > 0x1F && sts != 0xF0 {
		return false
	}

	// For extended commands, check that function code is in a known range
	if cmd == CmdExtended && len(data) >= 5 {
		fnc := FunctionCode(data[4])
		if !isKnownFunction(fnc) {
			return false
		}
	}

	return true
}

// isKnownFunction returns true for recognized PCCC function codes.
func isKnownFunction(f FunctionCode) bool {
	switch f {
	case FncEcho, FncSetCPUMode, FncTypedRead, FncTypedWrite,
		FncTypedRead3Addr, FncTypedWrite3Addr,
		FncWordRangeRead, FncWordRangeWrite,
		FncBitRead, FncBitWrite,
		FncDiagnosticRead, FncChangeMode, FncReadSLCFileInfo:
		return true
	default:
		return false
	}
}
