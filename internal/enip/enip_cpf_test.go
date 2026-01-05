package enip

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseSendRRDataRequestRequiresCPFInStrictMode(t *testing.T) {
	prev := CurrentOptions()
	SetOptions(Options{ByteOrder: binary.LittleEndian, UseCPF: true})
	defer SetOptions(prev)

	cipPayload := []byte{0x0E, 0x00, 0x20, 0x04, 0x24, 0x01, 0x30, 0x01}
	data := append(make([]byte, 6), cipPayload...)
	if _, err := ParseSendRRDataRequest(data); err == nil {
		t.Fatalf("expected CPF parse error in strict mode")
	}
}

func TestParseSendRRDataRequestAllowsNoCPFInLegacy(t *testing.T) {
	prev := CurrentOptions()
	SetOptions(Options{ByteOrder: binary.BigEndian, UseCPF: false})
	defer SetOptions(prev)

	cipPayload := []byte{0x0E, 0x00, 0x20, 0x04, 0x24, 0x01, 0x30, 0x01}
	data := append(make([]byte, 6), cipPayload...)
	parsed, err := ParseSendRRDataRequest(data)
	if err != nil {
		t.Fatalf("unexpected error in legacy mode: %v", err)
	}
	if !bytes.Equal(parsed, cipPayload) {
		t.Fatalf("unexpected payload: %v", parsed)
	}
}

func TestParseSendUnitDataRequestRequiresCPFInStrictMode(t *testing.T) {
	prev := CurrentOptions()
	SetOptions(Options{ByteOrder: binary.LittleEndian, UseCPF: true})
	defer SetOptions(prev)

	cipPayload := []byte{0x0E, 0x00, 0x20, 0x04, 0x24, 0x01, 0x30, 0x01}
	data := append(make([]byte, 4), cipPayload...)
	if _, _, err := ParseSendUnitDataRequest(data); err == nil {
		t.Fatalf("expected CPF parse error in strict mode")
	}
}

func TestParseSendUnitDataRequestAllowsNoCPFInLegacy(t *testing.T) {
	prev := CurrentOptions()
	SetOptions(Options{ByteOrder: binary.BigEndian, UseCPF: false})
	defer SetOptions(prev)

	cipPayload := []byte{0x0E, 0x00, 0x20, 0x04, 0x24, 0x01, 0x30, 0x01}
	data := append([]byte{0x78, 0x56, 0x34, 0x12}, cipPayload...)
	connID, payload, err := ParseSendUnitDataRequest(data)
	if err != nil {
		t.Fatalf("unexpected error in legacy mode: %v", err)
	}
	if connID != 0x78563412 {
		t.Fatalf("unexpected connection ID: 0x%08X", connID)
	}
	if !bytes.Equal(payload, cipPayload) {
		t.Fatalf("unexpected payload: %v", payload)
	}
}
