package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/metrics"
)

type metricsAnalyzeFlags struct {
	inputFile string
}

func newMetricsAnalyzeCmd() *cobra.Command {
	flags := &metricsAnalyzeFlags{}

	cmd := &cobra.Command{
		Use:   "metrics-analyze",
		Short: "Analyze a metrics CSV file and print summary statistics",
		Long: `Reads a metrics CSV file produced by a previous cipdip client run and prints
the same summary statistics (RTT percentiles, throughput, TCP resets, etc.)
that would have been shown at the end of the run.

If --input is omitted, the first positional argument is used.`,
		Example: `  # Analyze a previously collected metrics file
  cipdip metrics-analyze --input results/batch1_fwa_metrics.csv`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if handleHelpArg(cmd, args) {
				return nil
			}
			if flags.inputFile == "" && len(args) > 0 {
				flags.inputFile = args[0]
			}
			if flags.inputFile == "" {
				return missingFlagError(cmd, "--input")
			}
			return runMetricsAnalyze(flags)
		},
	}

	cmd.Flags().StringVar(&flags.inputFile, "input", "", "Input metrics CSV file (required)")

	return cmd
}

func runMetricsAnalyze(flags *metricsAnalyzeFlags) error {
	file, err := os.Open(flags.inputFile)
	if err != nil {
		return fmt.Errorf("open metrics CSV: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// Read and validate header
	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("read CSV header: %w", err)
	}

	colIndex := make(map[string]int, len(header))
	for i, col := range header {
		colIndex[col] = i
	}

	requiredCols := []string{"timestamp", "scenario", "operation", "success", "rtt_ms"}
	for _, col := range requiredCols {
		if _, ok := colIndex[col]; !ok {
			return fmt.Errorf("CSV missing required column: %s", col)
		}
	}

	sink := metrics.NewSink()
	var firstTime, lastTime time.Time
	rowCount := 0

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read CSV row %d: %w", rowCount+2, err)
		}

		m := metrics.Metric{}

		if idx, ok := colIndex["timestamp"]; ok && idx < len(record) {
			if t, err := time.Parse(time.RFC3339Nano, record[idx]); err == nil {
				m.Timestamp = t
				if rowCount == 0 {
					firstTime = t
				}
				lastTime = t
			}
		}
		if idx, ok := colIndex["scenario"]; ok && idx < len(record) {
			m.Scenario = record[idx]
		}
		if idx, ok := colIndex["target_type"]; ok && idx < len(record) {
			m.TargetType = metrics.TargetType(record[idx])
		}
		if idx, ok := colIndex["operation"]; ok && idx < len(record) {
			m.Operation = metrics.OperationType(record[idx])
		}
		if idx, ok := colIndex["target_name"]; ok && idx < len(record) {
			m.TargetName = record[idx]
		}
		if idx, ok := colIndex["service_code"]; ok && idx < len(record) {
			m.ServiceCode = record[idx]
		}
		if idx, ok := colIndex["success"]; ok && idx < len(record) {
			m.Success = record[idx] == "true"
		}
		if idx, ok := colIndex["rtt_ms"]; ok && idx < len(record) && record[idx] != "" {
			if v, err := strconv.ParseFloat(record[idx], 64); err == nil {
				m.RTTMs = v
			}
		}
		if idx, ok := colIndex["jitter_ms"]; ok && idx < len(record) && record[idx] != "" {
			if v, err := strconv.ParseFloat(record[idx], 64); err == nil {
				m.JitterMs = v
			}
		}
		if idx, ok := colIndex["status"]; ok && idx < len(record) && record[idx] != "" {
			if v, err := strconv.ParseUint(record[idx], 10, 8); err == nil {
				m.Status = uint8(v)
			}
		}
		if idx, ok := colIndex["error"]; ok && idx < len(record) {
			m.Error = record[idx]
		}
		if idx, ok := colIndex["outcome"]; ok && idx < len(record) {
			m.Outcome = record[idx]
		}
		if idx, ok := colIndex["expected_outcome"]; ok && idx < len(record) {
			m.ExpectedOutcome = record[idx]
		}

		sink.Record(m)
		rowCount++
	}

	if rowCount == 0 {
		return fmt.Errorf("no data rows in CSV file")
	}

	summary := sink.GetSummary()

	// Compute duration and throughput from timestamps
	if !firstTime.IsZero() && !lastTime.IsZero() {
		elapsed := lastTime.Sub(firstTime)
		summary.DurationMs = elapsed.Seconds() * 1000
		if elapsed.Seconds() > 0 {
			summary.ThroughputOpsPerSec = float64(summary.TotalOperations) / elapsed.Seconds()
		}
	}

	fmt.Fprintf(os.Stdout, "Metrics analysis: %s (%d records)\n\n", flags.inputFile, rowCount)
	fmt.Fprint(os.Stdout, metrics.FormatSummary(summary))

	return nil
}
