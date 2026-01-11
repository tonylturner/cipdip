// Package artifact handles structured output artifacts for profile runs.
package artifact

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tturner/cipdip/internal/metrics"
)

// RunMetadata contains metadata about a profile run.
type RunMetadata struct {
	// Run identification
	RunID     string    `json:"run_id"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Duration  string    `json:"duration"`

	// Profile information
	Profile     string `json:"profile,omitempty"`
	Role        string `json:"role,omitempty"`
	Scenario    string `json:"scenario,omitempty"`
	Personality string `json:"personality,omitempty"`

	// Target information
	TargetIP   string `json:"target_ip"`
	TargetPort int    `json:"target_port"`

	// Configuration
	PollIntervalMs int `json:"poll_interval_ms,omitempty"`
	BatchSize      int `json:"batch_size,omitempty"`

	// Results
	Stats    RunStats `json:"stats"`
	ExitCode int      `json:"exit_code"`
	Error    string   `json:"error,omitempty"`

	// Artifact paths (relative to output directory)
	Artifacts ArtifactPaths `json:"artifacts"`
}

// RunStats contains statistics from a profile run.
type RunStats struct {
	TotalOperations int `json:"total_operations"`
	SuccessfulOps   int `json:"successful_ops"`
	FailedOps       int `json:"failed_ops"`
	TimeoutCount    int `json:"timeout_count"`
	ReconnectCount  int `json:"reconnect_count"`
	// RTT in milliseconds
	AvgRTTMs float64 `json:"avg_rtt_ms"`
	P50RTTMs float64 `json:"p50_rtt_ms"`
	P95RTTMs float64 `json:"p95_rtt_ms"`
	P99RTTMs float64 `json:"p99_rtt_ms"`
	MaxRTTMs float64 `json:"max_rtt_ms"`
}

// ArtifactPaths contains relative paths to generated artifacts.
type ArtifactPaths struct {
	RunJSON     string `json:"run_json"`
	MetricsCSV  string `json:"metrics_csv,omitempty"`
	SummaryTxt  string `json:"summary_txt,omitempty"`
	PCAPFile    string `json:"pcap_file,omitempty"`
}

// OutputManager manages artifact output for a run.
type OutputManager struct {
	outputDir string
	runID     string
	metadata  *RunMetadata
}

// NewOutputManager creates a new output manager for the given directory.
func NewOutputManager(outputDir string) (*OutputManager, error) {
	// Generate run ID from timestamp
	runID := time.Now().Format("20060102-150405")

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	return &OutputManager{
		outputDir: outputDir,
		runID:     runID,
		metadata: &RunMetadata{
			RunID:     runID,
			StartTime: time.Now(),
			Artifacts: ArtifactPaths{
				RunJSON: "run.json",
			},
		},
	}, nil
}

// OutputDir returns the output directory path.
func (m *OutputManager) OutputDir() string {
	return m.outputDir
}

// RunID returns the run identifier.
func (m *OutputManager) RunID() string {
	return m.runID
}

// SetProfile sets profile information in metadata.
func (m *OutputManager) SetProfile(name, role, personality string) {
	m.metadata.Profile = name
	m.metadata.Role = role
	m.metadata.Personality = personality
}

// SetScenario sets scenario information in metadata.
func (m *OutputManager) SetScenario(name string) {
	m.metadata.Scenario = name
}

// SetTarget sets target information in metadata.
func (m *OutputManager) SetTarget(ip string, port int) {
	m.metadata.TargetIP = ip
	m.metadata.TargetPort = port
}

// SetConfig sets configuration information in metadata.
func (m *OutputManager) SetConfig(pollIntervalMs, batchSize int) {
	m.metadata.PollIntervalMs = pollIntervalMs
	m.metadata.BatchSize = batchSize
}

// SetPCAPFile sets the PCAP file path (relative to output directory).
func (m *OutputManager) SetPCAPFile(filename string) {
	m.metadata.Artifacts.PCAPFile = filename
}

// SetMetricsFile sets the metrics file path (relative to output directory).
func (m *OutputManager) SetMetricsFile(filename string) {
	m.metadata.Artifacts.MetricsCSV = filename
}

// PCAPPath returns the full path for the PCAP file.
func (m *OutputManager) PCAPPath() string {
	return filepath.Join(m.outputDir, fmt.Sprintf("capture_%s.pcap", m.runID))
}

// MetricsPath returns the full path for the metrics file.
func (m *OutputManager) MetricsPath() string {
	return filepath.Join(m.outputDir, fmt.Sprintf("metrics_%s.csv", m.runID))
}

// SummaryPath returns the full path for the summary file.
func (m *OutputManager) SummaryPath() string {
	return filepath.Join(m.outputDir, fmt.Sprintf("summary_%s.txt", m.runID))
}

// RunJSONPath returns the full path for the run.json file.
func (m *OutputManager) RunJSONPath() string {
	return filepath.Join(m.outputDir, "run.json")
}

// Finalize completes the run and writes all artifacts.
func (m *OutputManager) Finalize(summary *metrics.Summary, allMetrics []metrics.Metric, exitCode int, runErr error) error {
	m.metadata.EndTime = time.Now()
	m.metadata.Duration = m.metadata.EndTime.Sub(m.metadata.StartTime).String()
	m.metadata.ExitCode = exitCode

	if runErr != nil {
		m.metadata.Error = runErr.Error()
	}

	// Populate stats from summary
	if summary != nil {
		m.metadata.Stats = RunStats{
			TotalOperations: summary.TotalOperations,
			SuccessfulOps:   summary.SuccessfulOps,
			FailedOps:       summary.FailedOps,
			TimeoutCount:    summary.TimeoutCount,
			AvgRTTMs:        summary.AvgRTT,
			P50RTTMs:        summary.P50RTT,
			P95RTTMs:        summary.P95RTT,
			P99RTTMs:        summary.P99RTT,
			MaxRTTMs:        summary.MaxRTT,
		}
	}

	// Write summary text file
	if err := m.writeSummary(summary); err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	m.metadata.Artifacts.SummaryTxt = filepath.Base(m.SummaryPath())

	// Write run.json
	if err := m.writeRunJSON(); err != nil {
		return fmt.Errorf("write run.json: %w", err)
	}

	return nil
}

// writeSummary writes a human-readable summary file.
func (m *OutputManager) writeSummary(summary *metrics.Summary) error {
	f, err := os.Create(m.SummaryPath())
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "CIPDIP Run Summary\n")
	fmt.Fprintf(f, "==================\n\n")

	fmt.Fprintf(f, "Run ID:     %s\n", m.metadata.RunID)
	fmt.Fprintf(f, "Start Time: %s\n", m.metadata.StartTime.Format(time.RFC3339))
	fmt.Fprintf(f, "End Time:   %s\n", m.metadata.EndTime.Format(time.RFC3339))
	fmt.Fprintf(f, "Duration:   %s\n\n", m.metadata.Duration)

	if m.metadata.Profile != "" {
		fmt.Fprintf(f, "Profile:     %s\n", m.metadata.Profile)
		fmt.Fprintf(f, "Role:        %s\n", m.metadata.Role)
		fmt.Fprintf(f, "Personality: %s\n\n", m.metadata.Personality)
	} else if m.metadata.Scenario != "" {
		fmt.Fprintf(f, "Scenario: %s\n\n", m.metadata.Scenario)
	}

	fmt.Fprintf(f, "Target: %s:%d\n\n", m.metadata.TargetIP, m.metadata.TargetPort)

	if summary != nil {
		fmt.Fprintf(f, "Results\n")
		fmt.Fprintf(f, "-------\n")
		fmt.Fprintf(f, "Total Operations: %d\n", summary.TotalOperations)
		fmt.Fprintf(f, "Successful:       %d (%.1f%%)\n", summary.SuccessfulOps,
			float64(summary.SuccessfulOps)/float64(max(summary.TotalOperations, 1))*100)
		fmt.Fprintf(f, "Failed:           %d\n", summary.FailedOps)
		fmt.Fprintf(f, "Timeouts:         %d\n\n", summary.TimeoutCount)

		fmt.Fprintf(f, "RTT (ms)\n")
		fmt.Fprintf(f, "--------\n")
		fmt.Fprintf(f, "Average: %.2f\n", summary.AvgRTT)
		fmt.Fprintf(f, "P50:     %.2f\n", summary.P50RTT)
		fmt.Fprintf(f, "P95:     %.2f\n", summary.P95RTT)
		fmt.Fprintf(f, "P99:     %.2f\n", summary.P99RTT)
		fmt.Fprintf(f, "Max:     %.2f\n\n", summary.MaxRTT)
	}

	if m.metadata.Error != "" {
		fmt.Fprintf(f, "Error: %s\n\n", m.metadata.Error)
	}

	fmt.Fprintf(f, "Artifacts\n")
	fmt.Fprintf(f, "---------\n")
	if m.metadata.Artifacts.PCAPFile != "" {
		fmt.Fprintf(f, "PCAP:    %s\n", m.metadata.Artifacts.PCAPFile)
	}
	if m.metadata.Artifacts.MetricsCSV != "" {
		fmt.Fprintf(f, "Metrics: %s\n", m.metadata.Artifacts.MetricsCSV)
	}
	fmt.Fprintf(f, "Summary: %s\n", m.metadata.Artifacts.SummaryTxt)
	fmt.Fprintf(f, "Run JSON: %s\n", m.metadata.Artifacts.RunJSON)

	return nil
}

// writeRunJSON writes the run metadata as JSON.
func (m *OutputManager) writeRunJSON() error {
	data, err := json.MarshalIndent(m.metadata, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.RunJSONPath(), data, 0644)
}

// max returns the larger of two int values.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
