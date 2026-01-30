package modbus

import (
	"testing"
)

// --- CRC-16 tests ---

func TestCRC16KnownValue(t *testing.T) {
	// Verify CRC-16 via round-trip: encode RTU frame and check the CRC appended.
	data := []byte{0x01, 0x03, 0x00, 0x6B, 0x00, 0x03}
	crc := CRC16(data)
	// Build complete RTU frame: data + CRC (little-endian)
	frame := append(data, byte(crc), byte(crc>>8))
	// Verify the full frame passes CRC validation
	if !ValidateCRC(frame) {
		t.Errorf("CRC-16 round-trip failed for CRC=0x%04X", crc)
	}
	// CRC over the entire frame (including CRC bytes) should be 0
	fullCRC := CRC16(frame)
	if fullCRC != 0 {
		t.Errorf("CRC-16 of entire frame = 0x%04X, want 0x0000", fullCRC)
	}
}

func TestCRC16Empty(t *testing.T) {
	got := CRC16(nil)
	if got != 0xFFFF {
		t.Errorf("CRC16(nil) = 0x%04X, want 0xFFFF", got)
	}
}

// --- LRC tests ---

func TestLRCKnownValue(t *testing.T) {
	// Example: unit=0x01, FC=0x03, addr=0x006B, qty=0x0003
	data := []byte{0x01, 0x03, 0x00, 0x6B, 0x00, 0x03}
	got := LRC(data)
	// LRC = twos complement of (0x01+0x03+0x00+0x6B+0x00+0x03) = twos_comp(0x72) = 0x8E
	want := byte(0x8E)
	if got != want {
		t.Errorf("LRC = 0x%02X, want 0x%02X", got, want)
	}
}

func TestValidateLRC(t *testing.T) {
	data := []byte{0x01, 0x03, 0x00, 0x6B, 0x00, 0x03}
	lrc := LRC(data)
	if !ValidateLRC(append(data, lrc)) {
		t.Error("ValidateLRC returned false for valid payload")
	}
	if ValidateLRC(append(data, lrc^0xFF)) {
		t.Error("ValidateLRC returned true for invalid payload")
	}
}

// --- RTU round-trip tests ---

func TestRTURequestRoundTrip(t *testing.T) {
	req := Request{
		UnitID:   0x01,
		Function: FcReadHoldingRegisters,
		Data:     ReadHoldingRegistersRequest(0x006B, 3),
	}
	frame := EncodeRequestRTU(req)

	decoded, err := DecodeRequestRTU(frame)
	if err != nil {
		t.Fatalf("DecodeRequestRTU: %v", err)
	}
	if decoded.UnitID != req.UnitID {
		t.Errorf("UnitID = %d, want %d", decoded.UnitID, req.UnitID)
	}
	if decoded.Function != req.Function {
		t.Errorf("Function = 0x%02X, want 0x%02X", decoded.Function, req.Function)
	}
	if len(decoded.Data) != len(req.Data) {
		t.Fatalf("Data len = %d, want %d", len(decoded.Data), len(req.Data))
	}
}

func TestRTUResponseRoundTrip(t *testing.T) {
	resp := Response{
		UnitID:   0x01,
		Function: FcReadHoldingRegisters,
		Data:     []byte{0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03},
	}
	frame := EncodeResponseRTU(resp)

	decoded, err := DecodeResponseRTU(frame)
	if err != nil {
		t.Fatalf("DecodeResponseRTU: %v", err)
	}
	if decoded.UnitID != resp.UnitID {
		t.Errorf("UnitID = %d, want %d", decoded.UnitID, resp.UnitID)
	}
	if decoded.Function != resp.Function {
		t.Errorf("Function = 0x%02X, want 0x%02X", decoded.Function, resp.Function)
	}
}

func TestRTUCRCValidation(t *testing.T) {
	req := Request{
		UnitID:   0x01,
		Function: FcReadCoils,
		Data:     ReadCoilsRequest(0, 10),
	}
	frame := EncodeRequestRTU(req)

	if !ValidateCRC(frame) {
		t.Error("ValidateCRC returned false for valid frame")
	}

	// Corrupt one byte
	frame[2] ^= 0xFF
	if ValidateCRC(frame) {
		t.Error("ValidateCRC returned true for corrupted frame")
	}
}

func TestRTUDecodeShortFrame(t *testing.T) {
	_, err := DecodeRequestRTU([]byte{0x01, 0x03})
	if err == nil {
		t.Fatal("expected error for short RTU frame")
	}
}

func TestRTUDecodeBadCRC(t *testing.T) {
	frame := []byte{0x01, 0x03, 0x00, 0x00} // CRC bytes are wrong
	_, err := DecodeRequestRTU(frame)
	if err == nil {
		t.Fatal("expected error for bad CRC")
	}
}

// --- ASCII round-trip tests ---

func TestASCIIRequestRoundTrip(t *testing.T) {
	req := Request{
		UnitID:   0x01,
		Function: FcReadHoldingRegisters,
		Data:     ReadHoldingRegistersRequest(0x006B, 3),
	}
	frame := EncodeRequestASCII(req)

	// Verify framing
	if frame[0] != ':' {
		t.Errorf("first byte = 0x%02X, want ':'", frame[0])
	}
	if frame[len(frame)-2] != '\r' || frame[len(frame)-1] != '\n' {
		t.Error("missing CR LF terminator")
	}

	decoded, err := DecodeRequestASCII(frame)
	if err != nil {
		t.Fatalf("DecodeRequestASCII: %v", err)
	}
	if decoded.UnitID != req.UnitID {
		t.Errorf("UnitID = %d, want %d", decoded.UnitID, req.UnitID)
	}
	if decoded.Function != req.Function {
		t.Errorf("Function = 0x%02X, want 0x%02X", decoded.Function, req.Function)
	}
	if len(decoded.Data) != len(req.Data) {
		t.Fatalf("Data len = %d, want %d", len(decoded.Data), len(req.Data))
	}
}

func TestASCIIResponseRoundTrip(t *testing.T) {
	resp := Response{
		UnitID:   0x01,
		Function: FcReadHoldingRegisters,
		Data:     []byte{0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03},
	}
	frame := EncodeResponseASCII(resp)

	decoded, err := DecodeResponseASCII(frame)
	if err != nil {
		t.Fatalf("DecodeResponseASCII: %v", err)
	}
	if decoded.UnitID != resp.UnitID {
		t.Errorf("UnitID = %d, want %d", decoded.UnitID, resp.UnitID)
	}
	if decoded.Function != resp.Function {
		t.Errorf("Function = 0x%02X, want 0x%02X", decoded.Function, resp.Function)
	}
}

func TestASCIIDecodeMissingStart(t *testing.T) {
	_, err := DecodeRequestASCII([]byte("010300000003\r\n"))
	if err == nil {
		t.Fatal("expected error for missing start byte")
	}
}

func TestASCIIDecodeShort(t *testing.T) {
	_, err := DecodeRequestASCII([]byte(":01\r\n"))
	if err == nil {
		t.Fatal("expected error for short ASCII frame")
	}
}

func TestASCIIDecodeBadLRC(t *testing.T) {
	// Build valid frame then corrupt LRC
	req := Request{
		UnitID:   0x01,
		Function: FcReadCoils,
		Data:     ReadCoilsRequest(0, 10),
	}
	frame := EncodeRequestASCII(req)
	// Corrupt one hex char in the LRC (second to last hex pair before CRLF)
	frame[len(frame)-4] = 'F'
	frame[len(frame)-3] = 'F'

	_, err := DecodeRequestASCII(frame)
	if err == nil {
		t.Fatal("expected error for bad LRC")
	}
}

// --- Auto-detection tests ---

func TestDetectModeTCP(t *testing.T) {
	frame := EncodeRequestTCP(Request{
		TransactionID: 1,
		UnitID:        1,
		Function:      FcReadCoils,
		Data:          ReadCoilsRequest(0, 10),
	})
	if mode := DetectMode(frame); mode != ModeTCP {
		t.Errorf("DetectMode = %v, want ModeTCP", mode)
	}
}

func TestDetectModeASCII(t *testing.T) {
	frame := EncodeRequestASCII(Request{
		UnitID:   1,
		Function: FcReadCoils,
		Data:     ReadCoilsRequest(0, 10),
	})
	if mode := DetectMode(frame); mode != ModeASCII {
		t.Errorf("DetectMode = %v, want ModeASCII", mode)
	}
}

func TestDetectModeRTU(t *testing.T) {
	frame := EncodeRequestRTU(Request{
		UnitID:   1,
		Function: FcReadCoils,
		Data:     ReadCoilsRequest(0, 10),
	})
	if mode := DetectMode(frame); mode != ModeRTU {
		t.Errorf("DetectMode = %v, want ModeRTU", mode)
	}
}

func TestDetectModeEmpty(t *testing.T) {
	if mode := DetectMode(nil); mode != ModeTCP {
		t.Errorf("DetectMode(nil) = %v, want ModeTCP (default)", mode)
	}
}

// --- toUpperHex test ---

func TestToUpperHex(t *testing.T) {
	got := string(toUpperHex("0a1b2c3d"))
	want := "0A1B2C3D"
	if got != want {
		t.Errorf("toUpperHex = %q, want %q", got, want)
	}
}
