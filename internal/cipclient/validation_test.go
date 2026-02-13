package cipclient

import (
	"github.com/tonylturner/cipdip/internal/enip"
	"testing"
)

func TestValidateSendRRDataStrictCPF(t *testing.T) {
	prev := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prev)

	validator := NewPacketValidator(true)
	encap := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandSendRRData,
		Length:        6,
		SessionID:     0x12345678,
		Status:        0,
		SenderContext: [8]byte{0x01},
		Options:       0,
		Data:          make([]byte, 6),
	}
	if err := validator.ValidateENIP(encap); err == nil {
		t.Fatalf("expected CPF validation error for SendRRData")
	}
}

func TestValidateSendUnitDataStrictCPF(t *testing.T) {
	prev := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prev)

	validator := NewPacketValidator(true)
	encap := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandSendUnitData,
		Length:        6,
		SessionID:     0x12345678,
		Status:        0,
		SenderContext: [8]byte{0x01},
		Options:       0,
		Data:          make([]byte, 6),
	}
	if err := validator.ValidateENIP(encap); err == nil {
		t.Fatalf("expected CPF validation error for SendUnitData")
	}
}

func TestValidateSendRRDataLegacyNoCPF(t *testing.T) {
	prev := CurrentProtocolProfile()
	SetProtocolProfile(LegacyCompatProfile)
	defer SetProtocolProfile(prev)

	validator := NewPacketValidator(false)
	cipData := []byte{0x0E, 0x20, 0x04, 0x24, 0x01, 0x30, 0x01}
	payload := append(make([]byte, 6), cipData...)
	encap := enip.ENIPEncapsulation{
		Command:   enip.ENIPCommandSendRRData,
		Length:    uint16(len(payload)),
		SessionID: 0x12345678,
		Status:    0,
		Options:   0,
		Data:      payload,
	}
	if err := validator.ValidateENIP(encap); err != nil {
		t.Fatalf("unexpected validation error in legacy mode: %v", err)
	}
}

func TestValidateSendRRDataStrictWithCPF(t *testing.T) {
	prev := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prev)

	validator := NewPacketValidator(true)
	cipPayload := []byte{0x0E, 0x00, 0x20, 0x04, 0x24, 0x01, 0x30, 0x01}
	sendData := enip.BuildSendRRDataPayload(cipPayload)
	encap := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandSendRRData,
		Length:        uint16(len(sendData)),
		SessionID:     0x12345678,
		Status:        0,
		SenderContext: [8]byte{0x01},
		Options:       0,
		Data:          sendData,
	}
	if err := validator.ValidateENIP(encap); err != nil {
		t.Fatalf("unexpected validation error with CPF: %v", err)
	}
}

func TestValidateSendUnitDataLegacyConnID(t *testing.T) {
	prev := CurrentProtocolProfile()
	SetProtocolProfile(LegacyCompatProfile)
	defer SetProtocolProfile(prev)

	validator := NewPacketValidator(false)
	payload := []byte{
		0x78, 0x56, 0x34, 0x12, // connection ID
		0x01, 0x02, 0x03,
	}
	encap := enip.ENIPEncapsulation{
		Command:   enip.ENIPCommandSendUnitData,
		Length:    uint16(len(payload)),
		SessionID: 0x12345678,
		Status:    0,
		Options:   0,
		Data:      payload,
	}
	if err := validator.ValidateENIP(encap); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	encap.Data = []byte{0x00, 0x00, 0x00, 0x00}
	if err := validator.ValidateENIP(encap); err == nil {
		t.Fatalf("expected connection ID validation error")
	}
}
