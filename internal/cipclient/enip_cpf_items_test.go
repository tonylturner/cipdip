package cipclient

import (
	"bytes"
	"testing"
)

func TestEncodeParseCPFItemsRoundTrip(t *testing.T) {
	items := []CPFItem{
		{TypeID: CPFItemNullAddress, Data: nil},
		{TypeID: CPFItemUnconnectedData, Data: []byte{0x01, 0x02, 0x03}},
	}
	encoded := EncodeCPFItems(items)
	parsed, err := ParseCPFItems(encoded)
	if err != nil {
		t.Fatalf("ParseCPFItems error: %v", err)
	}
	if len(parsed) != len(items) {
		t.Fatalf("expected %d items, got %d", len(items), len(parsed))
	}
	for i := range items {
		if parsed[i].TypeID != items[i].TypeID {
			t.Fatalf("item %d type mismatch: got 0x%04X want 0x%04X", i, parsed[i].TypeID, items[i].TypeID)
		}
		if !bytes.Equal(parsed[i].Data, items[i].Data) {
			t.Fatalf("item %d data mismatch: got %v want %v", i, parsed[i].Data, items[i].Data)
		}
	}
}

func TestParseCPFItemsErrors(t *testing.T) {
	if _, err := ParseCPFItems([]byte{}); err == nil {
		t.Fatalf("expected short data error")
	}
	// Count says 1, but header missing.
	if _, err := ParseCPFItems([]byte{0x01, 0x00, 0x00}); err == nil {
		t.Fatalf("expected header too short error")
	}
	// Count 1, header ok, length 2, data missing.
	if _, err := ParseCPFItems([]byte{0x01, 0x00, 0xB2, 0x00, 0x02, 0x00, 0x01}); err == nil {
		t.Fatalf("expected item data too short error")
	}
}

func TestParseSendUnitDataRequestMissingItems(t *testing.T) {
	profileMu.Lock()
	prev := currentProfile
	currentProfile = StrictODVAProfile
	profileMu.Unlock()
	defer func() {
		profileMu.Lock()
		currentProfile = prev
		profileMu.Unlock()
	}()

	// CPF with only connected data item (missing address).
	cpf := EncodeCPFItems([]CPFItem{
		{TypeID: CPFItemConnectedData, Data: []byte{0x01, 0x02}},
	})
	data := append(make([]byte, 6), cpf...)
	if _, _, err := ParseSendUnitDataRequest(data); err == nil {
		t.Fatalf("expected missing connected address error")
	}

	// CPF with only connected address item (missing data).
	cpf = EncodeCPFItems([]CPFItem{
		{TypeID: CPFItemConnectedAddress, Data: []byte{0x01, 0x02, 0x03, 0x04}},
	})
	data = append(make([]byte, 6), cpf...)
	if _, _, err := ParseSendUnitDataRequest(data); err == nil {
		t.Fatalf("expected missing connected data error")
	}
}
