package validation

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedPCAPsValidateWithTshark(t *testing.T) {
	tshark := NewWiresharkValidator("")
	if _, err := tshark.ValidatePacket([]byte{}); err != nil {
		if strings.Contains(err.Error(), "tshark not found") {
			t.Skip("tshark not available, skipping PCAP validation test")
		}
	}

	specs, err := DefaultValidationPCAPSpecs()
	if err != nil {
		t.Fatalf("DefaultValidationPCAPSpecs error: %v", err)
	}

	for _, spec := range specs {
		spec := spec
		t.Run(spec.Name, func(t *testing.T) {
			enipPackets, err := BuildValidationENIPPackets(spec)
			if err != nil {
				t.Fatalf("BuildValidationENIPPackets(%s) error: %v", spec.Name, err)
			}

			pcapPath := filepath.Join(t.TempDir(), spec.Name+".pcap")
			if err := WriteENIPPCAP(pcapPath, enipPackets); err != nil {
				t.Fatalf("WriteENIPPCAP(%s) error: %v", spec.Name, err)
			}

			results, err := tshark.ValidatePCAP(pcapPath)
			if err != nil {
				t.Fatalf("ValidatePCAP(%s) error: %v", spec.Name, err)
			}
			if len(results) != len(enipPackets) {
				t.Fatalf("ValidatePCAP(%s) returned %d results, want %d", spec.Name, len(results), len(enipPackets))
			}
			for i, result := range results {
				if !result.Valid {
					t.Fatalf("tshark invalid packet %s #%d: %v %v", spec.Name, i, result.Errors, result.Warnings)
				}
			}
		})
	}
}
