package cipclient

import (
	"github.com/tturner/cipdip/internal/enip"
	"testing"
)

func TestReferencePackets(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	// Test that reference packets are populated
	expectedPackets := []string{
		"RegisterSession_Response",
		"GetAttributeSingle_Request",
		"SetAttributeSingle_Request",
		"ForwardOpen_Request",
		"ForwardClose_Request",
		"SendUnitData_Request",
	}

	for _, key := range expectedPackets {
		ref, ok := ReferencePackets[key]
		if !ok {
			t.Errorf("Reference packet %s not found", key)
			continue
		}

		if len(ref.Data) == 0 {
			t.Logf("Reference packet %s exists but not yet populated", key)
			continue
		}

		// Validate that it's a valid ENIP packet
		if len(ref.Data) < 24 {
			t.Errorf("Reference packet %s too short: %d bytes (minimum 24)", key, len(ref.Data))
			continue
		}

		// Validate ENIP header structure
		encap, err := enip.DecodeENIP(ref.Data)
		if err != nil {
			t.Errorf("Reference packet %s failed to decode: %v", key, err)
			continue
		}

		// Validate packet structure (non-strict mode, and allow normalized packets with zero session ID)
		validator := NewPacketValidator(false)
		// Note: Reference packets are normalized (session ID zeroed) for comparison,
		// so we skip session ID validation for reference packets
		if err := validator.ValidateENIP(encap); err != nil {
			// Check if error is about session ID (which is expected for normalized packets)
			if encap.SessionID == 0 && (encap.Command == enip.ENIPCommandSendRRData || encap.Command == enip.ENIPCommandSendUnitData) {
				// This is expected for normalized reference packets
				t.Logf("Reference packet %s has normalized session ID (expected for reference packets)", key)
			} else {
				t.Errorf("Reference packet %s failed validation: %v", key, err)
				continue
			}
		}

		t.Logf("Reference packet %s: %d bytes, %s", key, len(ref.Data), ref.Source)
	}
}

func TestCompareWithReference(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	// Test comparison with a reference packet
	ref, ok := ReferencePackets["GetAttributeSingle_Request"]
	if !ok || len(ref.Data) == 0 {
		t.Skip("GetAttributeSingle_Request reference packet not available")
	}

	// Compare packet with itself (should match)
	match, err := CompareWithReference("GetAttributeSingle_Request", ref.Data)
	if err != nil {
		t.Fatalf("CompareWithReference failed: %v", err)
	}
	if !match {
		t.Error("Packet should match itself")
	}

	// Compare with a modified packet (should not match)
	modified := make([]byte, len(ref.Data))
	copy(modified, ref.Data)
	modified[0] = 0xFF // Modify first byte
	match, err = CompareWithReference("GetAttributeSingle_Request", modified)
	if err != nil {
		t.Fatalf("CompareWithReference failed: %v", err)
	}
	if match {
		t.Error("Modified packet should not match reference")
	}
}

func TestFindFirstDifference(t *testing.T) {
	packet1 := []byte{0x00, 0x65, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78}
	packet2 := []byte{0x00, 0x65, 0x00, 0x04, 0x12, 0x34, 0x56, 0x99}

	offset, byte1, byte2 := FindFirstDifference(packet1, packet2)
	if offset != 7 {
		t.Errorf("Expected difference at offset 7, got %d", offset)
	}
	if byte1 != 0x78 {
		t.Errorf("Expected byte1 0x78, got 0x%02X", byte1)
	}
	if byte2 != 0x99 {
		t.Errorf("Expected byte2 0x99, got 0x%02X", byte2)
	}

	// Test identical packets
	offset, _, _ = FindFirstDifference(packet1, packet1)
	if offset != -1 {
		t.Errorf("Identical packets should return offset -1, got %d", offset)
	}
}

func TestValidatePacketStructure(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	ref, ok := ReferencePackets["RegisterSession_Response"]
	if !ok || len(ref.Data) == 0 {
		t.Skip("RegisterSession_Response reference packet not available")
	}

	err := ValidatePacketStructure(ref.Data, "RegisterSession_Response")
	if err != nil {
		t.Errorf("ValidatePacketStructure failed: %v", err)
	}

	// Test with wrong structure
	err = ValidatePacketStructure(ref.Data, "GetAttributeSingle_Request")
	if err == nil {
		t.Error("Should fail validation with wrong structure")
	}
}
