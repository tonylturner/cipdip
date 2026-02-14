package artifact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/cipdip/internal/metrics"
)

func TestNewOutputManager(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "output")

	m, err := NewOutputManager(outDir)
	if err != nil {
		t.Fatalf("NewOutputManager() error = %v", err)
	}

	if m.OutputDir() != outDir {
		t.Errorf("OutputDir() = %q, want %q", m.OutputDir(), outDir)
	}
	if m.RunID() == "" {
		t.Error("RunID() should not be empty")
	}

	// Verify directory was created
	info, err := os.Stat(outDir)
	if err != nil {
		t.Fatalf("output dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("output path should be a directory")
	}
}

func TestNewOutputManager_InvalidPath(t *testing.T) {
	// Use a path that cannot be created
	_, err := NewOutputManager("/dev/null/impossible")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestOutputManager_SetProfile(t *testing.T) {
	m, _ := NewOutputManager(t.TempDir())
	m.SetProfile("water_pump", "hmi", "logix_like")

	if m.metadata.Profile != "water_pump" {
		t.Errorf("Profile = %q, want %q", m.metadata.Profile, "water_pump")
	}
	if m.metadata.Role != "hmi" {
		t.Errorf("Role = %q, want %q", m.metadata.Role, "hmi")
	}
	if m.metadata.Personality != "logix_like" {
		t.Errorf("Personality = %q, want %q", m.metadata.Personality, "logix_like")
	}
}

func TestOutputManager_SetScenario(t *testing.T) {
	m, _ := NewOutputManager(t.TempDir())
	m.SetScenario("baseline")

	if m.metadata.Scenario != "baseline" {
		t.Errorf("Scenario = %q, want %q", m.metadata.Scenario, "baseline")
	}
}

func TestOutputManager_SetTarget(t *testing.T) {
	m, _ := NewOutputManager(t.TempDir())
	m.SetTarget("10.0.0.50", 44818)

	if m.metadata.TargetIP != "10.0.0.50" {
		t.Errorf("TargetIP = %q, want %q", m.metadata.TargetIP, "10.0.0.50")
	}
	if m.metadata.TargetPort != 44818 {
		t.Errorf("TargetPort = %d, want %d", m.metadata.TargetPort, 44818)
	}
}

func TestOutputManager_SetConfig(t *testing.T) {
	m, _ := NewOutputManager(t.TempDir())
	m.SetConfig(100, 8)

	if m.metadata.PollIntervalMs != 100 {
		t.Errorf("PollIntervalMs = %d, want 100", m.metadata.PollIntervalMs)
	}
	if m.metadata.BatchSize != 8 {
		t.Errorf("BatchSize = %d, want 8", m.metadata.BatchSize)
	}
}

func TestOutputManager_SetFiles(t *testing.T) {
	m, _ := NewOutputManager(t.TempDir())
	m.SetPCAPFile("capture.pcap")
	m.SetMetricsFile("metrics.csv")

	if m.metadata.Artifacts.PCAPFile != "capture.pcap" {
		t.Errorf("PCAPFile = %q, want %q", m.metadata.Artifacts.PCAPFile, "capture.pcap")
	}
	if m.metadata.Artifacts.MetricsCSV != "metrics.csv" {
		t.Errorf("MetricsCSV = %q, want %q", m.metadata.Artifacts.MetricsCSV, "metrics.csv")
	}
}

func TestOutputManager_Paths(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewOutputManager(dir)

	if !strings.HasPrefix(m.PCAPPath(), dir) {
		t.Errorf("PCAPPath() should start with output dir")
	}
	if !strings.HasSuffix(m.PCAPPath(), ".pcap") {
		t.Errorf("PCAPPath() should end with .pcap")
	}
	if !strings.HasPrefix(m.MetricsPath(), dir) {
		t.Errorf("MetricsPath() should start with output dir")
	}
	if !strings.HasSuffix(m.MetricsPath(), ".csv") {
		t.Errorf("MetricsPath() should end with .csv")
	}
	if !strings.HasPrefix(m.SummaryPath(), dir) {
		t.Errorf("SummaryPath() should start with output dir")
	}
	if !strings.HasSuffix(m.SummaryPath(), ".txt") {
		t.Errorf("SummaryPath() should end with .txt")
	}
	if m.RunJSONPath() != filepath.Join(dir, "run.json") {
		t.Errorf("RunJSONPath() = %q, want %q", m.RunJSONPath(), filepath.Join(dir, "run.json"))
	}
}

func TestOutputManager_Finalize(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewOutputManager(dir)

	m.SetProfile("test_profile", "hmi", "logix_like")
	m.SetTarget("10.0.0.50", 44818)
	m.SetPCAPFile("capture.pcap")
	m.SetMetricsFile("metrics.csv")

	summary := &metrics.Summary{
		TotalOperations: 100,
		SuccessfulOps:   95,
		FailedOps:       5,
		TimeoutCount:    2,
		AvgRTT:          1.5,
		P50RTT:          1.2,
		P95RTT:          3.0,
		P99RTT:          5.0,
		MaxRTT:          8.0,
	}

	err := m.Finalize(summary, nil, 0, nil)
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}

	// Verify run.json was written
	runJSON, err := os.ReadFile(m.RunJSONPath())
	if err != nil {
		t.Fatalf("read run.json: %v", err)
	}

	var meta RunMetadata
	if err := json.Unmarshal(runJSON, &meta); err != nil {
		t.Fatalf("unmarshal run.json: %v", err)
	}

	if meta.RunID == "" {
		t.Error("run_id should not be empty")
	}
	if meta.Profile != "test_profile" {
		t.Errorf("profile = %q, want %q", meta.Profile, "test_profile")
	}
	if meta.Stats.TotalOperations != 100 {
		t.Errorf("total_operations = %d, want 100", meta.Stats.TotalOperations)
	}
	if meta.Stats.SuccessfulOps != 95 {
		t.Errorf("successful_ops = %d, want 95", meta.Stats.SuccessfulOps)
	}
	if meta.Stats.AvgRTTMs != 1.5 {
		t.Errorf("avg_rtt_ms = %f, want 1.5", meta.Stats.AvgRTTMs)
	}
	if meta.Duration == "" {
		t.Error("duration should not be empty")
	}

	// Verify summary.txt was written
	summaryPath := m.SummaryPath()
	summaryData, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}

	summaryStr := string(summaryData)
	if !strings.Contains(summaryStr, "CIPDIP Run Summary") {
		t.Error("summary should contain header")
	}
	if !strings.Contains(summaryStr, "test_profile") {
		t.Error("summary should contain profile name")
	}
	if !strings.Contains(summaryStr, "10.0.0.50") {
		t.Error("summary should contain target IP")
	}
}

func TestOutputManager_Finalize_WithError(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewOutputManager(dir)
	m.SetTarget("10.0.0.50", 44818)

	err := m.Finalize(nil, nil, 1, os.ErrPermission)
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}

	runJSON, err := os.ReadFile(m.RunJSONPath())
	if err != nil {
		t.Fatalf("read run.json: %v", err)
	}

	var meta RunMetadata
	json.Unmarshal(runJSON, &meta)

	if meta.ExitCode != 1 {
		t.Errorf("exit_code = %d, want 1", meta.ExitCode)
	}
	if meta.Error == "" {
		t.Error("error should not be empty")
	}
}

func TestOutputManager_Finalize_NilSummary(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewOutputManager(dir)
	m.SetScenario("baseline")
	m.SetTarget("10.0.0.50", 44818)

	err := m.Finalize(nil, nil, 0, nil)
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}

	// Summary file should still exist, just with minimal content
	summaryData, err := os.ReadFile(m.SummaryPath())
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	if !strings.Contains(string(summaryData), "baseline") {
		t.Error("summary should contain scenario name")
	}
}

func TestMax(t *testing.T) {
	if max(1, 2) != 2 {
		t.Error("max(1,2) should be 2")
	}
	if max(5, 3) != 5 {
		t.Error("max(5,3) should be 5")
	}
	if max(4, 4) != 4 {
		t.Error("max(4,4) should be 4")
	}
}
