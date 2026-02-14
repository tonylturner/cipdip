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
	csvFile     *os.File
	csvWriter   *csv.Writer
	jsonFile    *os.File
	csvPath     string
	jsonHasData bool // tracks whether JSON array has entries (avoids Seek syscall)
}

// NewWriter creates a new metrics writer
func NewWriter(csvPath, jsonPath string) (*Writer, error) {
	w := &Writer{csvPath: csvPath}

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

// WriteSummary writes a summary CSV with distribution stats.
func (w *Writer) WriteSummary(summary *Summary, metrics []Metric) error {
	if w.csvPath == "" {
		return nil
	}
	summaryPath := w.csvPath + ".summary.csv"
	file, err := os.Create(summaryPath)
	if err != nil {
		return fmt.Errorf("create summary CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	header := []string{
		"scope",
		"scenario",
		"operation",
		"metric",
		"count",
		"min_ms",
		"max_ms",
		"avg_ms",
		"p50_ms",
		"p90_ms",
		"p95_ms",
		"p99_ms",
		"bucket_lt_1ms",
		"bucket_1_5ms",
		"bucket_5_10ms",
		"bucket_10_50ms",
		"bucket_50_100ms",
		"bucket_100_500ms",
		"bucket_gt_500ms",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("write summary CSV header: %w", err)
	}

	writeRow := func(scope, scenario, operation, metricName string, values []float64) error {
		if len(values) == 0 {
			return nil
		}
		buckets := make(map[string]int)
		var sum float64
		min := values[0]
		max := values[0]
		for _, v := range values {
			sum += v
			if v < min {
				min = v
			}
			if v > max {
				max = v
			}
			incrementBucket(buckets, v)
		}
		percentiles := computePercentiles(values)
		record := []string{
			scope,
			scenario,
			operation,
			metricName,
			fmt.Sprintf("%d", len(values)),
			fmt.Sprintf("%.3f", min),
			fmt.Sprintf("%.3f", max),
			fmt.Sprintf("%.3f", sum/float64(len(values))),
			fmt.Sprintf("%.3f", percentiles[0]),
			fmt.Sprintf("%.3f", percentiles[1]),
			fmt.Sprintf("%.3f", percentiles[2]),
			fmt.Sprintf("%.3f", percentiles[3]),
			fmt.Sprintf("%d", buckets["lt_1ms"]),
			fmt.Sprintf("%d", buckets["1_5ms"]),
			fmt.Sprintf("%d", buckets["5_10ms"]),
			fmt.Sprintf("%d", buckets["10_50ms"]),
			fmt.Sprintf("%d", buckets["50_100ms"]),
			fmt.Sprintf("%d", buckets["100_500ms"]),
			fmt.Sprintf("%d", buckets["gt_500ms"]),
		}
		return writer.Write(record)
	}

	// Write count-based aggregate stats row
	countsRecord := []string{
		"counts", "", "", "aggregate",
		fmt.Sprintf("%d", summary.TotalOperations),
		fmt.Sprintf("%d", summary.SuccessfulOps),
		fmt.Sprintf("%d", summary.FailedOps),
		fmt.Sprintf("%.3f", summary.ThroughputOpsPerSec),
		fmt.Sprintf("%d", summary.TimeoutCount),
		fmt.Sprintf("%d", summary.ConnectionFailures),
		fmt.Sprintf("%d", summary.TCPResetCount),
		fmt.Sprintf("%d", summary.Misclassifications),
		"", "", "", "", "", "", "",
	}
	if err := writer.Write(countsRecord); err != nil {
		return fmt.Errorf("write counts row: %w", err)
	}

	overallRTT := make([]float64, 0, len(metrics))
	overallJitter := make([]float64, 0, len(metrics))
	for _, m := range metrics {
		if m.Success && m.RTTMs > 0 {
			overallRTT = append(overallRTT, m.RTTMs)
		}
		if m.JitterMs > 0 {
			overallJitter = append(overallJitter, m.JitterMs)
		}
	}
	if err := writeRow("all", "", "", "rtt_ms", overallRTT); err != nil {
		return fmt.Errorf("write overall rtt summary: %w", err)
	}
	if err := writeRow("all", "", "", "jitter_ms", overallJitter); err != nil {
		return fmt.Errorf("write overall jitter summary: %w", err)
	}

	byScenario := make(map[string][]Metric)
	byOperation := make(map[OperationType][]Metric)
	byScenarioOp := make(map[string]map[OperationType][]Metric)
	for _, m := range metrics {
		byScenario[m.Scenario] = append(byScenario[m.Scenario], m)
		byOperation[m.Operation] = append(byOperation[m.Operation], m)
		if _, ok := byScenarioOp[m.Scenario]; !ok {
			byScenarioOp[m.Scenario] = make(map[OperationType][]Metric)
		}
		byScenarioOp[m.Scenario][m.Operation] = append(byScenarioOp[m.Scenario][m.Operation], m)
	}

	for op, list := range byOperation {
		rtts := make([]float64, 0, len(list))
		jitters := make([]float64, 0, len(list))
		for _, m := range list {
			if m.Success && m.RTTMs > 0 {
				rtts = append(rtts, m.RTTMs)
			}
			if m.JitterMs > 0 {
				jitters = append(jitters, m.JitterMs)
			}
		}
		if err := writeRow("operation", "", string(op), "rtt_ms", rtts); err != nil {
			return fmt.Errorf("write operation rtt summary: %w", err)
		}
		if err := writeRow("operation", "", string(op), "jitter_ms", jitters); err != nil {
			return fmt.Errorf("write operation jitter summary: %w", err)
		}
	}

	for scenario, list := range byScenario {
		rtts := make([]float64, 0, len(list))
		jitters := make([]float64, 0, len(list))
		for _, m := range list {
			if m.Success && m.RTTMs > 0 {
				rtts = append(rtts, m.RTTMs)
			}
			if m.JitterMs > 0 {
				jitters = append(jitters, m.JitterMs)
			}
		}
		if err := writeRow("scenario", scenario, "", "rtt_ms", rtts); err != nil {
			return fmt.Errorf("write scenario rtt summary: %w", err)
		}
		if err := writeRow("scenario", scenario, "", "jitter_ms", jitters); err != nil {
			return fmt.Errorf("write scenario jitter summary: %w", err)
		}
	}

	for scenario, byOp := range byScenarioOp {
		for op, list := range byOp {
			rtts := make([]float64, 0, len(list))
			jitters := make([]float64, 0, len(list))
			for _, m := range list {
				if m.Success && m.RTTMs > 0 {
					rtts = append(rtts, m.RTTMs)
				}
				if m.JitterMs > 0 {
					jitters = append(jitters, m.JitterMs)
				}
			}
			if err := writeRow("scenario_operation", scenario, string(op), "rtt_ms", rtts); err != nil {
				return fmt.Errorf("write scenario operation rtt summary: %w", err)
			}
			if err := writeRow("scenario_operation", scenario, string(op), "jitter_ms", jitters); err != nil {
				return fmt.Errorf("write scenario operation jitter summary: %w", err)
			}
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("flush summary CSV: %w", err)
	}

	_ = summary
	return nil
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
		// Note: Flush is called in Close() for better performance.
		// Per-record flush removed to avoid O(n) syscalls.
	}

	// Write to JSON
	if w.jsonFile != nil {
		jsonData, err := json.Marshal(m)
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}

		// Write comma separator between entries (no Seek syscall needed)
		if w.jsonHasData {
			if _, err := w.jsonFile.WriteString(",\n"); err != nil {
				return fmt.Errorf("write JSON comma: %w", err)
			}
		}
		w.jsonHasData = true

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
	if summary.ThroughputOpsPerSec > 0 {
		buf += fmt.Sprintf("Throughput: %.0f ops/sec\n", summary.ThroughputOpsPerSec)
	}
	buf += fmt.Sprintf("Successful: %d (%.1f%%)\n",
		summary.SuccessfulOps,
		float64(summary.SuccessfulOps)/float64(summary.TotalOperations)*100)
	buf += fmt.Sprintf("Failed: %d (%.1f%%)\n",
		summary.FailedOps,
		float64(summary.FailedOps)/float64(summary.TotalOperations)*100)

	if summary.TimeoutCount > 0 {
		timeoutRate := float64(summary.TimeoutCount) / float64(summary.TotalOperations) * 100
		buf += fmt.Sprintf("Timeouts: %d (%.3f%%)\n", summary.TimeoutCount, timeoutRate)
	}
	if summary.ConnectionFailures > 0 {
		buf += fmt.Sprintf("Connection Failures: %d\n", summary.ConnectionFailures)
	}
	if summary.TCPResetCount > 0 {
		buf += fmt.Sprintf("TCP Resets: %d\n", summary.TCPResetCount)
	}
	if summary.Misclassifications > 0 {
		misclassRate := float64(summary.Misclassifications) / float64(summary.TotalOperations) * 100
		buf += fmt.Sprintf("Misclassifications: %d (%.1f%%)\n", summary.Misclassifications, misclassRate)
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
