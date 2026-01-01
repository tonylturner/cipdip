package metrics

// Metrics output (CSV/JSON) and summary formatting

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Writer handles writing metrics to files
type Writer struct {
	csvFile   *os.File
	csvWriter *csv.Writer
	jsonFile  *os.File
}

// NewWriter creates a new metrics writer
func NewWriter(csvPath, jsonPath string) (*Writer, error) {
	w := &Writer{}

	// Open CSV file if path provided
	if csvPath != "" {
		file, err := os.Create(csvPath)
		if err != nil {
			return nil, fmt.Errorf("create CSV file: %w", err)
		}
		w.csvFile = file
		w.csvWriter = csv.NewWriter(file)

		// Write CSV header
		header := []string{
			"timestamp",
			"scenario",
			"target_type",
			"operation",
			"target_name",
			"service_code",
			"success",
			"rtt_ms",
			"jitter_ms",
			"status",
			"error",
			"outcome",
			"expected_outcome",
		}
		if err := w.csvWriter.Write(header); err != nil {
			file.Close()
			return nil, fmt.Errorf("write CSV header: %w", err)
		}
		w.csvWriter.Flush()
	}

	// Open JSON file if path provided
	if jsonPath != "" {
		file, err := os.Create(jsonPath)
		if err != nil {
			if w.csvFile != nil {
				w.csvFile.Close()
			}
			return nil, fmt.Errorf("create JSON file: %w", err)
		}
		w.jsonFile = file

		// Write JSON array start
		if _, err := file.WriteString("[\n"); err != nil {
			file.Close()
			if w.csvFile != nil {
				w.csvFile.Close()
			}
			return nil, fmt.Errorf("write JSON start: %w", err)
		}
	}

	return w, nil
}

// WriteMetric writes a single metric
func (w *Writer) WriteMetric(m Metric) error {
	// Write to CSV
	if w.csvWriter != nil {
		record := []string{
			m.Timestamp.Format(time.RFC3339Nano),
			m.Scenario,
			string(m.TargetType),
			string(m.Operation),
			m.TargetName,
			m.ServiceCode,
			fmt.Sprintf("%t", m.Success),
			formatRTT(m.RTTMs),
			formatRTT(m.JitterMs),
			fmt.Sprintf("%d", m.Status),
			m.Error,
			m.Outcome,
			m.ExpectedOutcome,
		}
		if err := w.csvWriter.Write(record); err != nil {
			return fmt.Errorf("write CSV record: %w", err)
		}
		w.csvWriter.Flush()
	}

	// Write to JSON
	if w.jsonFile != nil {
		jsonData, err := json.Marshal(m)
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}

		// Check if we need a comma (not the first entry)
		pos, _ := w.jsonFile.Seek(0, 1) // Get current position
		if pos > 2 {                    // More than just "[\n"
			if _, err := w.jsonFile.WriteString(",\n"); err != nil {
				return fmt.Errorf("write JSON comma: %w", err)
			}
		}

		// Write indented JSON
		var buf bytes.Buffer
		if err := json.Indent(&buf, jsonData, "", "  "); err != nil {
			return fmt.Errorf("indent JSON: %w", err)
		}
		if _, err := w.jsonFile.Write(buf.Bytes()); err != nil {
			return fmt.Errorf("write JSON: %w", err)
		}
	}

	return nil
}

// Close closes the writer and flushes all data
func (w *Writer) Close() error {
	var errs []error

	if w.csvWriter != nil {
		w.csvWriter.Flush()
	}
	if w.csvFile != nil {
		if err := w.csvFile.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if w.jsonFile != nil {
		// Write JSON array end
		if _, err := w.jsonFile.WriteString("\n]\n"); err != nil {
			errs = append(errs, err)
		}
		if err := w.jsonFile.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("close writer: %v", errs)
	}

	return nil
}

// formatRTT formats RTT value for CSV (empty string if 0)
func formatRTT(rtt float64) string {
	if rtt == 0 {
		return ""
	}
	return fmt.Sprintf("%.3f", rtt)
}

// FormatSummary formats a summary for human-readable output
func FormatSummary(summary *Summary) string {
	var buf string

	buf += fmt.Sprintf("Total Operations: %d\n", summary.TotalOperations)
	buf += fmt.Sprintf("Successful: %d (%.1f%%)\n",
		summary.SuccessfulOps,
		float64(summary.SuccessfulOps)/float64(summary.TotalOperations)*100)
	buf += fmt.Sprintf("Failed: %d (%.1f%%)\n",
		summary.FailedOps,
		float64(summary.FailedOps)/float64(summary.TotalOperations)*100)

	if summary.TimeoutCount > 0 {
		buf += fmt.Sprintf("Timeouts: %d\n", summary.TimeoutCount)
	}
	if summary.ConnectionFailures > 0 {
		buf += fmt.Sprintf("Connection Failures: %d\n", summary.ConnectionFailures)
	}
	if summary.Misclassifications > 0 {
		buf += fmt.Sprintf("Misclassifications: %d\n", summary.Misclassifications)
	}

	if summary.SuccessfulOps > 0 {
		buf += fmt.Sprintf("\nRTT Statistics (all operations):\n")
		buf += fmt.Sprintf("  Min: %.3f ms\n", summary.MinRTT)
		buf += fmt.Sprintf("  Max: %.3f ms\n", summary.MaxRTT)
		buf += fmt.Sprintf("  Avg: %.3f ms\n", summary.AvgRTT)
		if summary.P50RTT > 0 || summary.P90RTT > 0 || summary.P95RTT > 0 || summary.P99RTT > 0 {
			buf += fmt.Sprintf("  P50: %.3f ms\n", summary.P50RTT)
			buf += fmt.Sprintf("  P90: %.3f ms\n", summary.P90RTT)
			buf += fmt.Sprintf("  P95: %.3f ms\n", summary.P95RTT)
			buf += fmt.Sprintf("  P99: %.3f ms\n", summary.P99RTT)
		}
		if len(summary.RTTBuckets) > 0 {
			buf += fmt.Sprintf("  Buckets: <1ms=%d 1-5ms=%d 5-10ms=%d 10-50ms=%d 50-100ms=%d 100-500ms=%d >500ms=%d\n",
				summary.RTTBuckets["lt_1ms"],
				summary.RTTBuckets["1_5ms"],
				summary.RTTBuckets["5_10ms"],
				summary.RTTBuckets["10_50ms"],
				summary.RTTBuckets["50_100ms"],
				summary.RTTBuckets["100_500ms"],
				summary.RTTBuckets["gt_500ms"],
			)
		}
	}
	if summary.AvgJitter > 0 {
		buf += fmt.Sprintf("\nJitter Statistics (all operations):\n")
		buf += fmt.Sprintf("  Min: %.3f ms\n", summary.MinJitter)
		buf += fmt.Sprintf("  Max: %.3f ms\n", summary.MaxJitter)
		buf += fmt.Sprintf("  Avg: %.3f ms\n", summary.AvgJitter)
		if summary.P50Jitter > 0 || summary.P90Jitter > 0 || summary.P95Jitter > 0 || summary.P99Jitter > 0 {
			buf += fmt.Sprintf("  P50: %.3f ms\n", summary.P50Jitter)
			buf += fmt.Sprintf("  P90: %.3f ms\n", summary.P90Jitter)
			buf += fmt.Sprintf("  P95: %.3f ms\n", summary.P95Jitter)
			buf += fmt.Sprintf("  P99: %.3f ms\n", summary.P99Jitter)
		}
		if len(summary.JitterBuckets) > 0 {
			buf += fmt.Sprintf("  Buckets: <1ms=%d 1-5ms=%d 5-10ms=%d 10-50ms=%d 50-100ms=%d 100-500ms=%d >500ms=%d\n",
				summary.JitterBuckets["lt_1ms"],
				summary.JitterBuckets["1_5ms"],
				summary.JitterBuckets["5_10ms"],
				summary.JitterBuckets["10_50ms"],
				summary.JitterBuckets["50_100ms"],
				summary.JitterBuckets["100_500ms"],
				summary.JitterBuckets["gt_500ms"],
			)
		}
	}

	// Per-operation statistics
	if len(summary.RTTByOperation) > 0 {
		buf += fmt.Sprintf("\nPer-Operation Statistics:\n")
		for op, stats := range summary.RTTByOperation {
			buf += fmt.Sprintf("  %s: %d ops (%d success, %d failed)",
				op, stats.Count, stats.Success, stats.Failed)
			if stats.Success > 0 {
				buf += fmt.Sprintf(" - RTT: min=%.3fms, max=%.3fms, avg=%.3fms",
					stats.MinRTT, stats.MaxRTT, stats.AvgRTT)
			}
			buf += "\n"
		}
	}

	// Per-scenario statistics
	if len(summary.RTTByScenario) > 0 {
		buf += fmt.Sprintf("\nPer-Scenario Statistics:\n")
		for scenario, stats := range summary.RTTByScenario {
			buf += fmt.Sprintf("  %s: %d ops (%d success, %d failed)",
				scenario, stats.Count, stats.Success, stats.Failed)
			if stats.Success > 0 {
				buf += fmt.Sprintf(" - RTT: min=%.3fms, max=%.3fms, avg=%.3fms",
					stats.MinRTT, stats.MaxRTT, stats.AvgRTT)
			}
			buf += "\n"
		}
	}

	return buf
}
