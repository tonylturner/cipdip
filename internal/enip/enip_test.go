package enip

import (
	"encoding/binary"
	"testing"
)

func TestEncodeENIP(t *testing.T) {
	prev := CurrentOptions()
	SetOptions(Options{ByteOrder: binary.LittleEndian, UseCPF: true})
	defer SetOptions(prev)

	encap := ENIPEncapsulation{
		Command:       ENIPCommandRegisterSession,
		Length:        4,
		SessionID:     0x12345678,
		Status:        0,
		SenderContext: [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Options:       0,
		Data:          []byte{0x01, 0x00, 0x00, 0x00},
	}

	packet := EncodeENIP(encap)

	// Should be 24 bytes (header) + 4 bytes (data) = 28 bytes.
	if len(packet) != 28 {
		t.Errorf("packet length: got %d, want 28", len(packet))
	}

	order := currentENIPByteOrder()
	cmd := order.Uint16(packet[0:2])
	if cmd != 0x0065 {
		t.Errorf("command: got 0x%04X, want 0x0065", cmd)
	}

	length := order.Uint16(packet[2:4])
	if length != 0x0004 {
		t.Errorf("length: got 0x%04X, want 0x0004", length)
	}
}

func TestDecodeENIP(t *testing.T) {
	prev := CurrentOptions()
	SetOptions(Options{ByteOrder: binary.LittleEndian, UseCPF: true})
	defer SetOptions(prev)

	encap := ENIPEncapsulation{
		Command:       ENIPCommandRegisterSession,
		Length:        4,
		SessionID:     0x12345678,
		Status:        0,
		SenderContext: [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Options:       0,
		Data:          []byte{0x01, 0x00, 0x00, 0x00},
	}

	packet := EncodeENIP(encap)
	decoded, err := DecodeENIP(packet)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	if decoded.Command != encap.Command {
		t.Errorf("command: got 0x%04X, want 0x%04X", decoded.Command, encap.Command)
	}

	if decoded.Length != encap.Length {
		t.Errorf("length: got %d, want %d", decoded.Length, encap.Length)
	}

	if decoded.SessionID != encap.SessionID {
		t.Errorf("session ID: got 0x%08X, want 0x%08X", decoded.SessionID, encap.SessionID)
	}

	if len(decoded.Data) != len(encap.Data) {
		t.Errorf("data length: got %d, want %d", len(decoded.Data), len(encap.Data))
	}
}

func TestDecodeENIPTooShort(t *testing.T) {
	if _, err := DecodeENIP([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Fatalf("expected error for short ENIP packet")
	}
}

func TestBuildRegisterSession(t *testing.T) {
	prev := CurrentOptions()
	SetOptions(Options{ByteOrder: binary.LittleEndian, UseCPF: true})
	defer SetOptions(prev)

	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	packet := BuildRegisterSession(senderContext)

	// Should be 24 bytes (header) + 4 bytes (data) = 28 bytes.
	if len(packet) != 28 {
		t.Errorf("packet length: got %d, want 28", len(packet))
	}

	encap, err := DecodeENIP(packet)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	if encap.Command != ENIPCommandRegisterSession {
		t.Errorf("command: got 0x%04X, want 0x%04X", encap.Command, ENIPCommandRegisterSession)
	}

	if len(encap.Data) != 4 {
		t.Errorf("data length: got %d, want 4", len(encap.Data))
	}

	if encap.SenderContext != senderContext {
		t.Errorf("sender context: got %v, want %v", encap.SenderContext, senderContext)
	}
}

func TestBuildSendRRData(t *testing.T) {
	prev := CurrentOptions()
	SetOptions(Options{ByteOrder: binary.LittleEndian, UseCPF: true})
	defer SetOptions(prev)

	sessionID := uint32(0x12345678)
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	cipData := []byte{0x0E, 0x20, 0x04, 0x24, 0x65, 0x30, 0x03}

	packet := BuildSendRRData(sessionID, senderContext, cipData)

	encap, err := DecodeENIP(packet)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	if encap.Command != ENIPCommandSendRRData {
		t.Errorf("command: got 0x%04X, want 0x%04X", encap.Command, ENIPCommandSendRRData)
	}

	if encap.SessionID != sessionID {
		t.Errorf("session ID: got 0x%08X, want 0x%08X", encap.SessionID, sessionID)
	}

	cipRespData, err := ParseSendRRDataResponse(encap.Data)
	if err != nil {
		t.Fatalf("ParseSendRRDataResponse failed: %v", err)
	}

	if len(cipRespData) != len(cipData) {
		t.Errorf("CIP data length: got %d, want %d", len(cipRespData), len(cipData))
	}
}
