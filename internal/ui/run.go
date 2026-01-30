package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// RunSummary is the structured metadata emitted for every run.
type RunSummary struct {
	Status     string   `json:"status"`
	Command    []string `json:"command"`
	StartedAt  string   `json:"started_at"`
	FinishedAt string   `json:"finished_at"`
	ExitCode   int      `json:"exit_code"`
}

// RunMetrics captures detailed metrics from a run for export.
type RunMetrics struct {
	RunType   string  `json:"run_type"` // "client", "server", "pcap"
	StartedAt string  `json:"started_at"`
	EndedAt   string  `json:"ended_at"`
	Duration  float64 `json:"duration_seconds"`

	// Request metrics
	TotalRequests      int `json:"total_requests"`
	SuccessfulRequests int `json:"successful_requests"`
	FailedRequests     int `json:"failed_requests"`
	Timeouts           int `json:"timeouts"`

	// Connection metrics
	TotalConnections  int `json:"total_connections"`
	ActiveConnections int `json:"active_connections"`

	// Error metrics
	TotalErrors int `json:"total_errors"`

	// Derived metrics
	RequestRate  float64 `json:"requests_per_second,omitempty"`
	SuccessRate  float64 `json:"success_rate,omitempty"` // 0-1
	ErrorRate    float64 `json:"error_rate,omitempty"`   // 0-1
	TimeoutRate  float64 `json:"timeout_rate,omitempty"` // 0-1
	AvgLatencyMs float64 `json:"avg_latency_ms,omitempty"`
}

// RunArtifacts captures the run metadata and log payloads for display.
type RunArtifacts struct {
	RunDir    string
	Command   string
	Summary   *RunSummary
	Stdout    string
	Resolved  string
	HasOutput bool
}

// ListRuns returns run directory names ordered by descending name.
// Returns nil, nil if the runs directory does not exist.
func ListRuns(workspaceRoot string, limit int) ([]string, error) {
	runsDir := filepath.Join(workspaceRoot, "runs")
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read runs dir: %w", err)
	}
	runs := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			runs = append(runs, entry.Name())
		}
	}
	sort.Slice(runs, func(i, j int) bool {
		return runs[i] > runs[j]
	})
	if limit > 0 && len(runs) > limit {
		return runs[:limit], nil
	}
	return runs, nil
}

// CreateRunDir creates a timestamped run directory under workspace/runs.
func CreateRunDir(workspaceRoot, name string) (string, error) {
	if workspaceRoot == "" {
		return "", fmt.Errorf("workspace root is required")
	}
	runName := sanitizeRunName(name)
	if runName == "" {
		runName = "run"
	}
	timestamp := time.Now().UTC().Format("2006-01-02_15-04")
	dir := filepath.Join(workspaceRoot, "runs", fmt.Sprintf("%s_%s", timestamp, runName))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create run dir: %w", err)
	}
	return dir, nil
}

// WriteRunArtifacts writes required run artifacts to the run directory.
func WriteRunArtifacts(runDir string, resolved interface{}, command []string, stdout string, summary RunSummary) error {
	if err := writeYAML(filepath.Join(runDir, "resolved.yaml"), resolved); err != nil {
		return err
	}
	if err := writeText(filepath.Join(runDir, "command.txt"), formatCommand(command)); err != nil {
		return err
	}
	if err := writeText(filepath.Join(runDir, "stdout.log"), stdout); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(runDir, "summary.json"), summary); err != nil {
		return err
	}
	return nil
}

// WriteMetrics writes detailed metrics to metrics.json in the run directory.
func WriteMetrics(runDir string, metrics RunMetrics) error {
	return writeJSON(filepath.Join(runDir, "metrics.json"), metrics)
}

// BuildMetrics creates a RunMetrics from stats and timing information.
func BuildMetrics(runType string, startTime, endTime time.Time, stats StatsUpdate) RunMetrics {
	duration := endTime.Sub(startTime).Seconds()
	if duration < 0.001 {
		duration = 0.001 // avoid division by zero
	}

	metrics := RunMetrics{
		RunType:            runType,
		StartedAt:          startTime.Format(time.RFC3339),
		EndedAt:            endTime.Format(time.RFC3339),
		Duration:           duration,
		TotalRequests:      stats.TotalRequests,
		SuccessfulRequests: stats.SuccessfulRequests,
		FailedRequests:     stats.FailedRequests,
		Timeouts:           stats.Timeouts,
		TotalConnections:   stats.TotalConnections,
		ActiveConnections:  stats.ActiveConnections,
		TotalErrors:        stats.TotalErrors,
	}

	// Calculate derived metrics
	if metrics.TotalRequests > 0 {
		metrics.RequestRate = float64(metrics.TotalRequests) / duration
		metrics.SuccessRate = float64(metrics.SuccessfulRequests) / float64(metrics.TotalRequests)
		metrics.ErrorRate = float64(metrics.FailedRequests) / float64(metrics.TotalRequests)
		metrics.TimeoutRate = float64(metrics.Timeouts) / float64(metrics.TotalRequests)
	}

	return metrics
}

// LoadRunArtifacts reads the core run artifacts from a run directory.
func LoadRunArtifacts(runDir string) (*RunArtifacts, error) {
	artifacts := &RunArtifacts{RunDir: runDir}
	if data, err := os.ReadFile(filepath.Join(runDir, "command.txt")); err == nil {
		artifacts.Command = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile(filepath.Join(runDir, "stdout.log")); err == nil {
		artifacts.Stdout = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile(filepath.Join(runDir, "resolved.yaml")); err == nil {
		artifacts.Resolved = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile(filepath.Join(runDir, "summary.json")); err == nil {
		var summary RunSummary
		if err := json.Unmarshal(data, &summary); err == nil {
			artifacts.Summary = &summary
		}
	}
	artifacts.HasOutput = artifacts.Command != "" || artifacts.Stdout != "" || artifacts.Resolved != "" || artifacts.Summary != nil
	if !artifacts.HasOutput {
		return nil, fmt.Errorf("no artifacts found in %s", runDir)
	}
	return artifacts, nil
}

// LoadRunSummary loads just the summary.json from a run directory.
func LoadRunSummary(path string) (*RunSummary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var summary RunSummary
	if err := json.Unmarshal(data, &summary); err != nil {
		return nil, err
	}
	return &summary, nil
}

func writeYAML(path string, data interface{}) error {
	encoded, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}
	if err := os.WriteFile(path, encoded, 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func writeJSON(path string, data interface{}) error {
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	if err := os.WriteFile(path, encoded, 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func writeText(path string, data string) error {
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func sanitizeRunName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ReplaceAll(name, "/", "-")
	name = strings.ReplaceAll(name, "\\", "-")
	return name
}

func formatCommand(args []string) string {
	parts := make([]string, 0, len(args))
	for _, arg := range args {
		parts = append(parts, quoteArg(arg))
	}
	return strings.Join(parts, " ")
}

// FormatCommand exposes the command formatting for UI and tests.
func FormatCommand(args []string) string {
	return formatCommand(args)
}

func quoteArg(arg string) string {
	if arg == "" {
		return "\"\""
	}
	if strings.ContainsAny(arg, " \t") {
		escaped := strings.ReplaceAll(arg, "\"", "\\\"")
		return fmt.Sprintf("\"%s\"", escaped)
	}
	return arg
}
