package client

import (
	"github.com/tonylturner/cipdip/internal/enip"
	"testing"
)

func TestBuildListServices(t *testing.T) {
	senderContext := [8]byte{0x01, 0x02, 0x03}
	packet := BuildListServices(senderContext)

	encap, err := enip.DecodeENIP(packet)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}
	if encap.Command != enip.ENIPCommandListServices {
		t.Fatalf("command: got 0x%04X, want 0x%04X", encap.Command, enip.ENIPCommandListServices)
	}
	if encap.Length != 0 {
		t.Fatalf("length: got %d, want 0", encap.Length)
	}
	if encap.SessionID != 0 {
		t.Fatalf("session ID: got 0x%08X, want 0", encap.SessionID)
	}
	if encap.Status != 0 {
		t.Fatalf("status: got 0x%08X, want 0", encap.Status)
	}
	if encap.SenderContext != senderContext {
		t.Fatalf("sender context mismatch")
	}
	if len(encap.Data) != 0 {
		t.Fatalf("data length: got %d, want 0", len(encap.Data))
	}
}

func TestBuildListInterfaces(t *testing.T) {
	senderContext := [8]byte{0x04, 0x05, 0x06}
	packet := BuildListInterfaces(senderContext)

	encap, err := enip.DecodeENIP(packet)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}
	if encap.Command != enip.ENIPCommandListInterfaces {
		t.Fatalf("command: got 0x%04X, want 0x%04X", encap.Command, enip.ENIPCommandListInterfaces)
	}
	if encap.Length != 0 {
		t.Fatalf("length: got %d, want 0", encap.Length)
	}
	if encap.SessionID != 0 {
		t.Fatalf("session ID: got 0x%08X, want 0", encap.SessionID)
	}
	if encap.Status != 0 {
		t.Fatalf("status: got 0x%08X, want 0", encap.Status)
	}
	if encap.SenderContext != senderContext {
		t.Fatalf("sender context mismatch")
	}
	if len(encap.Data) != 0 {
		t.Fatalf("data length: got %d, want 0", len(encap.Data))
	}
}

func TestParseListServicesResponse(t *testing.T) {
	items := []enip.CPFItem{
		{TypeID: 0x0100, Data: []byte{0x01, 0x02}},
		{TypeID: 0x0101, Data: []byte{0xAA}},
	}
	payload := enip.EncodeCPFItems(items)
	encap := enip.ENIPEncapsulation{
		Command:   enip.ENIPCommandListServices,
		Length:    uint16(len(payload)),
		SessionID: 0,
		Status:    enip.ENIPStatusSuccess,
		Data:      payload,
	}
	packet := enip.EncodeENIP(encap)

	parsed, err := ParseListServicesResponse(packet)
	if err != nil {
		t.Fatalf("ParseListServicesResponse failed: %v", err)
	}
	if len(parsed) != len(items) {
		t.Fatalf("items: got %d, want %d", len(parsed), len(items))
	}
	if parsed[0].TypeID != items[0].TypeID || string(parsed[0].Data) != string(items[0].Data) {
		t.Fatalf("item[0] mismatch")
	}
}

func TestParseListInterfacesResponse(t *testing.T) {
	items := []enip.CPFItem{
		{TypeID: 0x0200, Data: []byte{0x10, 0x20}},
	}
	payload := enip.EncodeCPFItems(items)
	encap := enip.ENIPEncapsulation{
		Command:   enip.ENIPCommandListInterfaces,
		Length:    uint16(len(payload)),
		SessionID: 0,
		Status:    enip.ENIPStatusSuccess,
		Data:      payload,
	}
	packet := enip.EncodeENIP(encap)

	parsed, err := ParseListInterfacesResponse(packet)
	if err != nil {
		t.Fatalf("ParseListInterfacesResponse failed: %v", err)
	}
	if len(parsed) != len(items) {
		t.Fatalf("items: got %d, want %d", len(parsed), len(items))
	}
	if parsed[0].TypeID != items[0].TypeID || string(parsed[0].Data) != string(items[0].Data) {
		t.Fatalf("item[0] mismatch")
	}
}

func TestParseListResponseErrors(t *testing.T) {
	t.Run("wrong command", func(t *testing.T) {
		encap := enip.ENIPEncapsulation{
			Command: enip.ENIPCommandListServices,
			Status:  enip.ENIPStatusSuccess,
		}
		packet := enip.EncodeENIP(encap)
		if _, err := ParseListInterfacesResponse(packet); err == nil {
			t.Fatalf("expected error for wrong command")
		}
	})

	t.Run("error status", func(t *testing.T) {
		encap := enip.ENIPEncapsulation{
			Command: enip.ENIPCommandListServices,
			Status:  enip.ENIPStatusInvalidCommand,
		}
		packet := enip.EncodeENIP(encap)
		if _, err := ParseListServicesResponse(packet); err == nil {
			t.Fatalf("expected error for error status")
		}
	})

	t.Run("invalid cpf data", func(t *testing.T) {
		encap := enip.ENIPEncapsulation{
			Command: enip.ENIPCommandListServices,
			Length:  1,
			Status:  enip.ENIPStatusSuccess,
			Data:    []byte{0x00},
		}
		packet := enip.EncodeENIP(encap)
		if _, err := ParseListServicesResponse(packet); err == nil {
			t.Fatalf("expected error for invalid cpf data")
		}
	})
}

