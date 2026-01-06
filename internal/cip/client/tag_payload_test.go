package client

import "testing"

func TestBuildReadTagFragmentedPayload(t *testing.T) {
	payload := BuildReadTagFragmentedPayload(0, 0x11223344)
	if len(payload) != 6 {
		t.Fatalf("expected payload length 6, got %d", len(payload))
	}
	if payload[0] != 0x01 || payload[1] != 0x00 {
		t.Fatalf("expected default element count 1, got %02X %02X", payload[1], payload[0])
	}
	if payload[2] != 0x44 || payload[3] != 0x33 || payload[4] != 0x22 || payload[5] != 0x11 {
		t.Fatalf("unexpected byte offset encoding: %02X %02X %02X %02X", payload[2], payload[3], payload[4], payload[5])
	}
}

func TestBuildWriteTagFragmentedPayload(t *testing.T) {
	data := []byte{0xDE, 0xAD}
	payload := BuildWriteTagFragmentedPayload(0x00C4, 0, 0x01020304, data)
	if len(payload) != 10 {
		t.Fatalf("expected payload length 10, got %d", len(payload))
	}
	if payload[0] != 0xC4 || payload[1] != 0x00 {
		t.Fatalf("unexpected type code encoding: %02X %02X", payload[1], payload[0])
	}
	if payload[2] != 0x01 || payload[3] != 0x00 {
		t.Fatalf("expected default element count 1, got %02X %02X", payload[3], payload[2])
	}
	if payload[4] != 0x04 || payload[5] != 0x03 || payload[6] != 0x02 || payload[7] != 0x01 {
		t.Fatalf("unexpected byte offset encoding: %02X %02X %02X %02X", payload[4], payload[5], payload[6], payload[7])
	}
	if payload[8] != 0xDE || payload[9] != 0xAD {
		t.Fatalf("unexpected data bytes: %02X %02X", payload[8], payload[9])
	}
}

func TestBuildReadWriteTagPayloads(t *testing.T) {
	readPayload := BuildReadTagPayload(0)
	if len(readPayload) != 2 {
		t.Fatalf("expected read payload length 2, got %d", len(readPayload))
	}
	if readPayload[0] != 0x01 || readPayload[1] != 0x00 {
		t.Fatalf("expected default element count 1, got %02X %02X", readPayload[1], readPayload[0])
	}

	writePayload := BuildWriteTagPayload(0x00C4, 0, []byte{0x01, 0x02})
	if len(writePayload) != 6 {
		t.Fatalf("expected write payload length 6, got %d", len(writePayload))
	}
	if writePayload[0] != 0xC4 || writePayload[1] != 0x00 {
		t.Fatalf("unexpected type code encoding: %02X %02X", writePayload[1], writePayload[0])
	}
	if writePayload[2] != 0x01 || writePayload[3] != 0x00 {
		t.Fatalf("expected default element count 1, got %02X %02X", writePayload[3], writePayload[2])
	}
	if writePayload[4] != 0x01 || writePayload[5] != 0x02 {
		t.Fatalf("unexpected data bytes: %02X %02X", writePayload[4], writePayload[5])
	}
}

