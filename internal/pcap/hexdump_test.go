package pcap

import (
	"strings"
	"testing"
)

// TestHexDump tests hex dump formatting
func TestHexDump(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

	dump := HexDump(data, 16)

	// Should contain offset
	if !strings.Contains(dump, "0000:") {
		t.Error("Hex dump should contain offset")
	}

	// Should contain hex bytes
	if !strings.Contains(dump, "00 01 02 03") {
		t.Error("Hex dump should contain hex bytes")
	}

	// Should contain ASCII representation
	if !strings.Contains(dump, "|") {
		t.Error("Hex dump should contain ASCII representation")
	}
}

// TestFormatPacketHex tests packet hex formatting
func TestFormatPacketHex(t *testing.T) {
	// Create a minimal ENIP packet
	data := make([]byte, 24)
	data[0] = 0x00
	data[1] = 0x65 // RegisterSession
	data[2] = 0x00
	data[3] = 0x04                              // Length
	data = append(data, 0x00, 0x01, 0x00, 0x00) // Data

	// Test simple format
	simple := FormatPacketHex(data, false)
	if len(simple) == 0 {
		t.Error("Simple format should produce output")
	}

	// Test annotated format
	annotated := FormatPacketHex(data, true)
	if !strings.Contains(annotated, "ENIP Header") {
		t.Error("Annotated format should contain header label")
	}
}
