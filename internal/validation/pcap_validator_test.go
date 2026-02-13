package validation_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/cipdip/internal/validation"
	"github.com/tonylturner/cipdip/internal/validation/fixtures"
)

func TestGeneratedPCAPsValidateWithTshark(t *testing.T) {
	tshark := validation.NewWiresharkValidator("")
	if _, err := tshark.ValidatePacket([]byte{}); err != nil {
		if strings.Contains(err.Error(), "tshark not found") {
			t.Skip("tshark not available, skipping PCAP validation test")
		}
	}

	specs, err := fixtures.DefaultValidationPCAPSpecs()
	if err != nil {
		t.Fatalf("DefaultValidationPCAPSpecs error: %v", err)
	}

	for _, spec := range specs {
		spec := spec
		t.Run(spec.Name, func(t *testing.T) {
			packets, err := fixtures.BuildValidationPackets(spec)
			if err != nil {
				t.Fatalf("BuildValidationPackets(%s) error: %v", spec.Name, err)
			}

			pcapPath := filepath.Join(t.TempDir(), spec.Name+".pcap")
			manifestPath := validation.ValidationManifestPath(pcapPath)
			expectations := make([]validation.PacketExpectation, 0, len(packets))
			for _, pkt := range packets {
				expectations = append(expectations, pkt.Expect)
			}
			if err := fixtures.WriteENIPPCAP(pcapPath, packets); err != nil {
				t.Fatalf("WriteENIPPCAP(%s) error: %v", spec.Name, err)
			}
			if err := validation.WriteValidationManifest(manifestPath, validation.ValidationManifest{
				PCAP:    filepath.Base(pcapPath),
				Packets: expectations,
			}); err != nil {
				t.Fatalf("WriteValidationManifest(%s) error: %v", spec.Name, err)
			}

			results, err := tshark.ValidatePCAP(pcapPath)
			if err != nil {
				t.Fatalf("ValidatePCAP(%s) error: %v", spec.Name, err)
			}
			if len(results) != len(packets) {
				t.Fatalf("ValidatePCAP(%s) returned %d results, want %d", spec.Name, len(results), len(packets))
			}

			manifest, err := validation.LoadValidationManifest(manifestPath)
			if err != nil {
				t.Fatalf("LoadValidationManifest(%s) error: %v", spec.Name, err)
			}
			if manifest == nil {
				t.Fatalf("manifest missing for %s", spec.Name)
			}
			if len(manifest.Packets) != len(results) {
				t.Fatalf("manifest packet mismatch for %s: %d vs %d", spec.Name, len(manifest.Packets), len(results))
			}

			for i, result := range results {
				pairing := validation.BuildPairingResults(*manifest, results)
				baseID := strings.TrimSuffix(strings.TrimSuffix(manifest.Packets[i].ID, "/request"), "/response")
				eval := validation.EvaluatePacket(manifest.Packets[i], result, "tshark", "balanced", "basic", "client_wire", pairing[baseID])
				if !eval.Pass {
					t.Fatalf("validation failed %s #%d (%s): %+v", spec.Name, i, eval.Expected.ID, eval.Scenarios)
				}
				if strings.EqualFold(eval.Expected.Outcome, "valid") && eval.Expected.Direction == "request" {
					if eval.Grade != validation.GradePass {
						t.Fatalf("grade-a regression %s #%d (%s): grade=%s labels=%v", spec.Name, i, eval.Expected.ID, eval.Grade, eval.FailureLabels)
					}
				}
				if strings.EqualFold(eval.Expected.Outcome, "invalid") && eval.Expected.Direction == "request" {
					if eval.Grade != validation.GradeExpectedInvalid {
						t.Fatalf("expected-invalid regression %s #%d (%s): grade=%s", spec.Name, i, eval.Expected.ID, eval.Grade)
					}
				}
			}
		})
	}
}
