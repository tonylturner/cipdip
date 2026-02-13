package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tonylturner/cipdip/internal/orch/bundle"
	"github.com/tonylturner/cipdip/internal/pcap"
)

func TestFindRolePcap(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test bundle structure
	b, err := bundle.Create(tmpDir, "test-run")
	if err != nil {
		t.Fatalf("Failed to create bundle: %v", err)
	}

	// Create a test PCAP file
	clientPcap := filepath.Join(b.RoleDir("client"), "client.pcap")
	if err := os.WriteFile(clientPcap, []byte("fake pcap data"), 0644); err != nil {
		t.Fatalf("Failed to create test pcap: %v", err)
	}

	// Test finding the PCAP
	found, err := findRolePcap(b, "client")
	if err != nil {
		t.Fatalf("findRolePcap() error = %v", err)
	}

	if found != clientPcap {
		t.Errorf("findRolePcap() = %v, want %v", found, clientPcap)
	}
}

func TestFindRolePcap_NoPcap(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test bundle structure without PCAP
	b, err := bundle.Create(tmpDir, "test-run")
	if err != nil {
		t.Fatalf("Failed to create bundle: %v", err)
	}

	// Test finding non-existent PCAP
	_, err = findRolePcap(b, "client")
	if err == nil {
		t.Error("findRolePcap() should fail when no PCAP exists")
	}
}

func TestFindRolePcap_FallbackName(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test bundle structure
	b, err := bundle.Create(tmpDir, "test-run")
	if err != nil {
		t.Fatalf("Failed to create bundle: %v", err)
	}

	// Create a PCAP with non-standard name
	otherPcap := filepath.Join(b.RoleDir("client"), "capture.pcap")
	if err := os.WriteFile(otherPcap, []byte("fake pcap data"), 0644); err != nil {
		t.Fatalf("Failed to create test pcap: %v", err)
	}

	// Should fall back to the available PCAP
	found, err := findRolePcap(b, "client")
	if err != nil {
		t.Fatalf("findRolePcap() error = %v", err)
	}

	if found != otherPcap {
		t.Errorf("findRolePcap() = %v, want %v", found, otherPcap)
	}
}

func TestGenerateDiffSummary(t *testing.T) {
	// Create a mock diff result
	pcapDiff := &pcap.DiffResult{
		BaselinePacketCount: 100,
		ComparePacketCount:  110,
		BaselineCIPCount:    50,
		CompareCIPCount:     55,
		AddedServices: []pcap.ServiceInfo{
			{ServiceCode: 0x01, ServiceName: "Get_Attribute_Single"},
		},
		RemovedServices: []pcap.ServiceInfo{},
		CommonServices: []pcap.ServiceInfo{
			{ServiceCode: 0x0E, ServiceName: "Get_Attribute_All"},
		},
		AddedClasses:   []uint16{0x0002},
		RemovedClasses: []uint16{},
		CommonClasses:  []uint16{0x0001},
		BaselineTiming: &pcap.TimingStats{
			PacketCount:  50,
			P95LatencyMs: 10.0,
		},
		CompareTiming: &pcap.TimingStats{
			PacketCount:  55,
			P95LatencyMs: 12.0,
		},
		BaselineRPI: &pcap.RPIStats{
			JitterMs: 5.0,
		},
		CompareRPI: &pcap.RPIStats{
			JitterMs: 7.0,
		},
	}

	result := &BundleDiffResult{
		PcapDiff: pcapDiff,
	}

	summary := generateDiffSummary(result)

	if summary.ServicesAdded != 1 {
		t.Errorf("ServicesAdded = %d, want 1", summary.ServicesAdded)
	}
	if summary.ServicesRemoved != 0 {
		t.Errorf("ServicesRemoved = %d, want 0", summary.ServicesRemoved)
	}
	if summary.ServicesCommon != 1 {
		t.Errorf("ServicesCommon = %d, want 1", summary.ServicesCommon)
	}
	if summary.ClassesAdded != 1 {
		t.Errorf("ClassesAdded = %d, want 1", summary.ClassesAdded)
	}
	if summary.PacketCountDelta != 10 {
		t.Errorf("PacketCountDelta = %d, want 10", summary.PacketCountDelta)
	}
	if summary.CIPCountDelta != 5 {
		t.Errorf("CIPCountDelta = %d, want 5", summary.CIPCountDelta)
	}
	if summary.LatencyDeltaMs != 2.0 {
		t.Errorf("LatencyDeltaMs = %f, want 2.0", summary.LatencyDeltaMs)
	}
	if summary.JitterDeltaMs != 2.0 {
		t.Errorf("JitterDeltaMs = %f, want 2.0", summary.JitterDeltaMs)
	}
	if !summary.HasSignificantDiff {
		t.Error("HasSignificantDiff should be true")
	}
	if summary.DiffScore == 0 {
		t.Error("DiffScore should be > 0")
	}
}

func TestGenerateDiffSummary_NoDiff(t *testing.T) {
	pcapDiff := &pcap.DiffResult{
		BaselinePacketCount: 100,
		ComparePacketCount:  100,
		BaselineCIPCount:    50,
		CompareCIPCount:     50,
		AddedServices:       []pcap.ServiceInfo{},
		RemovedServices:     []pcap.ServiceInfo{},
		CommonServices: []pcap.ServiceInfo{
			{ServiceCode: 0x01},
		},
		AddedClasses:   []uint16{},
		RemovedClasses: []uint16{},
		CommonClasses:  []uint16{0x0001},
	}

	result := &BundleDiffResult{
		PcapDiff: pcapDiff,
	}

	summary := generateDiffSummary(result)

	if summary.HasSignificantDiff {
		t.Error("HasSignificantDiff should be false when no differences")
	}
	if summary.DiffScore != 0 {
		t.Errorf("DiffScore = %d, want 0", summary.DiffScore)
	}
}

func TestFormatBundleDiffText(t *testing.T) {
	result := &BundleDiffResult{
		Role:           "client",
		BaselineBundle: "/path/to/baseline",
		CompareBundle:  "/path/to/compare",
		BaselinePcap:   "/path/to/baseline/roles/client/client.pcap",
		ComparePcap:    "/path/to/compare/roles/client/client.pcap",
		PcapDiff: &pcap.DiffResult{
			BaselinePath:        "/path/to/baseline/roles/client/client.pcap",
			ComparePath:         "/path/to/compare/roles/client/client.pcap",
			BaselinePacketCount: 100,
			ComparePacketCount:  100,
			BaselineCIPCount:    50,
			CompareCIPCount:     50,
		},
		Summary: &DiffSummary{
			ServicesAdded:   0,
			ServicesRemoved: 0,
			ServicesCommon:  5,
			DiffScore:       0,
		},
	}

	output := formatBundleDiffText(result)

	if output == "" {
		t.Error("formatBundleDiffText() should produce output")
	}
	if !contains(output, "Bundle Diff Report") {
		t.Error("Output should contain title")
	}
	if !contains(output, "client") {
		t.Error("Output should contain role")
	}
}

func TestFormatBundleDiffMarkdown(t *testing.T) {
	result := &BundleDiffResult{
		Role:           "client",
		BaselineBundle: "/path/to/baseline",
		CompareBundle:  "/path/to/compare",
		PcapDiff: &pcap.DiffResult{
			BaselinePacketCount: 100,
			ComparePacketCount:  110,
			AddedServices: []pcap.ServiceInfo{
				{ServiceCode: 0x01, ServiceName: "Test", Class: 0x0001, Count: 5},
			},
		},
		Summary: &DiffSummary{
			ServicesAdded:      1,
			HasSignificantDiff: true,
			DiffScore:          10,
		},
	}

	output := formatBundleDiffMarkdown(result)

	if output == "" {
		t.Error("formatBundleDiffMarkdown() should produce output")
	}
	if !contains(output, "# Bundle Diff Report") {
		t.Error("Output should contain markdown title")
	}
	if !contains(output, "| Baseline |") {
		t.Error("Output should contain markdown table")
	}
	if !contains(output, "Added Services") {
		t.Error("Output should contain added services section")
	}
}

func TestMin(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{5, 5, 5},
		{0, 10, 0},
		{-1, 1, -1},
	}

	for _, tt := range tests {
		got := min(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
