package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	report := ValidationReport{
		GeneratedAt:   "2024-01-15T10:00:00Z",
		CIPDIPVersion: "1.0.0",
		PCAPs: []PCAPReport{
			{
				PCAP:         "test.pcap",
				PacketCount:  100,
				Pass:         true,
				InvalidCount: 0,
			},
		},
	}

	var buf bytes.Buffer
	err := WriteJSON(&buf, report)
	if err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	// Verify output is valid JSON
	var decoded ValidationReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	// Verify fields were preserved
	if decoded.GeneratedAt != report.GeneratedAt {
		t.Errorf("GeneratedAt mismatch: got %q, want %q", decoded.GeneratedAt, report.GeneratedAt)
	}
	if len(decoded.PCAPs) != 1 {
		t.Errorf("Expected 1 PCAP, got %d", len(decoded.PCAPs))
	}
}

func TestWriteJSONFile(t *testing.T) {
	report := ValidationReport{
		GeneratedAt:   "2024-01-15T10:00:00Z",
		CIPDIPVersion: "1.0.0",
		PCAPs: []PCAPReport{
			{
				PCAP:         "test.pcap",
				PacketCount:  100,
				Pass:         true,
				InvalidCount: 0,
			},
		},
	}

	// Create temp file
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test_report.json")

	err := WriteJSONFile(path, report)
	if err != nil {
		t.Fatalf("WriteJSONFile failed: %v", err)
	}

	// Verify file exists and is valid JSON
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var decoded ValidationReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Output file is not valid JSON: %v", err)
	}

	// Verify fields were preserved
	if decoded.GeneratedAt != report.GeneratedAt {
		t.Errorf("GeneratedAt mismatch: got %q, want %q", decoded.GeneratedAt, report.GeneratedAt)
	}
}

func TestWriteJSONIndentation(t *testing.T) {
	report := struct {
		Name   string `json:"name"`
		Nested struct {
			Value int `json:"value"`
		} `json:"nested"`
	}{
		Name: "test",
	}
	report.Nested.Value = 42

	var buf bytes.Buffer
	err := WriteJSON(&buf, report)
	if err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	output := buf.String()
	// Should be indented with 2 spaces
	if !bytes.Contains(buf.Bytes(), []byte("  ")) {
		t.Error("Output should be indented with spaces")
	}
	// Should have newlines
	if !bytes.Contains(buf.Bytes(), []byte("\n")) {
		t.Error("Output should have newlines")
	}
	// Should not be compact
	if len(output) < 50 {
		t.Error("Output appears to be compact, expected pretty-printed")
	}
}

func TestWriteJSONEmptyReport(t *testing.T) {
	report := ValidationReport{}

	var buf bytes.Buffer
	err := WriteJSON(&buf, report)
	if err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	// Should still produce valid JSON
	var decoded ValidationReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}
}

func TestWriteJSONMultiplePCAPs(t *testing.T) {
	report := ValidationReport{
		GeneratedAt: "2024-01-15T10:00:00Z",
		PCAPs: []PCAPReport{
			{PCAP: "test1.pcap", PacketCount: 100, Pass: true},
			{PCAP: "test2.pcap", PacketCount: 200, Pass: false, InvalidCount: 5},
			{PCAP: "test3.pcap", PacketCount: 50, Pass: true},
		},
	}

	var buf bytes.Buffer
	err := WriteJSON(&buf, report)
	if err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	var decoded ValidationReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	if len(decoded.PCAPs) != 3 {
		t.Errorf("Expected 3 PCAPs, got %d", len(decoded.PCAPs))
	}

	// Verify second PCAP has invalid count
	if decoded.PCAPs[1].InvalidCount != 5 {
		t.Errorf("Expected InvalidCount 5, got %d", decoded.PCAPs[1].InvalidCount)
	}
}

func TestWriteJSONFilePermissions(t *testing.T) {
	report := ValidationReport{GeneratedAt: "2024-01-15T10:00:00Z"}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "perms_test.json")

	err := WriteJSONFile(path, report)
	if err != nil {
		t.Fatalf("WriteJSONFile failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}

	// Check that file is readable (0644 permission)
	mode := info.Mode().Perm()
	if mode&0400 == 0 {
		t.Error("File should be owner-readable")
	}
	if mode&0040 == 0 {
		t.Error("File should be group-readable")
	}
	if mode&0004 == 0 {
		t.Error("File should be world-readable")
	}
}
