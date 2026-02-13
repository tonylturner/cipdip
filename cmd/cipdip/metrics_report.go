package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/metrics"
)

type metricsReportFlags struct {
	dir string
}

func newMetricsReportCmd() *cobra.Command {
	flags := &metricsReportFlags{}

	cmd := &cobra.Command{
		Use:   "metrics-report",
		Short: "Generate a batch-aligned DPI test report from metrics CSVs",
		Long: `Reads all *_metrics.csv files from a directory (typically produced by
selftest --scenarios all --metrics-dir <dir>), groups them by DPI test batch
(1-8), computes batch-specific metrics, and prints a formatted report.

The report covers all 8 batches defined in the DPI test batches specification
with per-batch metrics tables.`,
		Example: `  # Generate report from selftest output
  cipdip metrics-report --dir /tmp/selftest_metrics

  # Generate report from standalone client runs
  cipdip metrics-report --dir results/`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if handleHelpArg(cmd, args) {
				return nil
			}
			if flags.dir == "" && len(args) > 0 {
				flags.dir = args[0]
			}
			if flags.dir == "" {
				return missingFlagError(cmd, "--dir")
			}
			return runMetricsReport(flags)
		},
	}

	cmd.Flags().StringVar(&flags.dir, "dir", "", "Directory containing *_metrics.csv files (required)")

	return cmd
}

// batchDef maps batch numbers to their scenarios.
type batchDef struct {
	Number    int
	Name      string
	Scenarios []string
}

var batchDefs = []batchDef{
	{Number: 1, Name: "Baseline ODVA Compliance", Scenarios: []string{"baseline"}},
	{Number: 2, Name: "High-Frequency Stress Reads", Scenarios: []string{"stress"}},
	{Number: 3, Name: "Forward Open / I/O Churn", Scenarios: []string{"churn", "io", "mixed_state"}},
	{Number: 4, Name: "Vendor Variant Profile Cycling", Scenarios: []string{"vendor_variants"}},
	{Number: 5, Name: "DPI Explicit Messaging (6-Phase)", Scenarios: []string{"dpi_explicit"}},
	{Number: 6, Name: "Evasion Techniques", Scenarios: []string{"evasion_segment", "evasion_fuzz", "evasion_anomaly", "evasion_timing"}},
	{Number: 7, Name: "Edge Cases + Legacy Protocol Tunneling", Scenarios: []string{"edge_valid", "edge_vendor", "pccc", "modbus"}},
	{Number: 8, Name: "Mixed Realistic Workload (Regression)", Scenarios: []string{"mixed", "mixed_state", "firewall_pack", "firewall_hirschmann", "firewall_moxa", "firewall_dynics"}},
}

// selftestManifest is written by selftest alongside the CSVs.
type selftestManifest struct {
	Timestamp string   `json:"timestamp"`
	Scenarios []string `json:"scenarios"`
	Duration  int      `json:"duration_seconds"`
	Version   string   `json:"version"`
}

// scenarioData holds parsed metrics for a single scenario CSV.
type scenarioData struct {
	Name      string
	Metrics   []metrics.Metric
	FirstTime time.Time
	LastTime  time.Time
}

func runMetricsReport(flags *metricsReportFlags) error {
	// Discover CSV files
	pattern := filepath.Join(flags.dir, "*_metrics.csv")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob metrics CSVs: %w", err)
	}

	// Filter out .summary.csv files
	var csvFiles []string
	for _, f := range files {
		if !strings.HasSuffix(f, ".summary.csv") {
			csvFiles = append(csvFiles, f)
		}
	}

	if len(csvFiles) == 0 {
		return fmt.Errorf("no *_metrics.csv files found in %s", flags.dir)
	}

	// Parse all CSVs
	dataByScenario := make(map[string]*scenarioData)
	var allFirstTimes, allLastTimes []time.Time

	for _, f := range csvFiles {
		base := filepath.Base(f)
		scenarioName := strings.TrimSuffix(base, "_metrics.csv")

		records, firstTime, lastTime, err := metrics.ReadMetricsCSV(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping %s: %v\n", base, err)
			continue
		}

		dataByScenario[scenarioName] = &scenarioData{
			Name:      scenarioName,
			Metrics:   records,
			FirstTime: firstTime,
			LastTime:  lastTime,
		}

		if !firstTime.IsZero() {
			allFirstTimes = append(allFirstTimes, firstTime)
		}
		if !lastTime.IsZero() {
			allLastTimes = append(allLastTimes, lastTime)
		}
	}

	if len(dataByScenario) == 0 {
		return fmt.Errorf("no valid metrics files found in %s", flags.dir)
	}

	// Run coherence check
	checkTimestampCoherence(dataByScenario, allFirstTimes, allLastTimes)

	// Check manifest if present
	checkManifest(flags.dir, dataByScenario)

	// Print report header
	fmt.Fprintf(os.Stdout, "=== CIPDIP DPI Test Report ===\n")
	fmt.Fprintf(os.Stdout, "Source: %s\n", flags.dir)
	fmt.Fprintf(os.Stdout, "Files: %d scenario CSVs loaded\n", len(dataByScenario))

	totalRecords := 0
	for _, sd := range dataByScenario {
		totalRecords += len(sd.Metrics)
	}
	fmt.Fprintf(os.Stdout, "Total records: %d\n\n", totalRecords)

	// Print each batch
	for _, batch := range batchDefs {
		printBatchReport(batch, dataByScenario)
	}

	return nil
}

func checkTimestampCoherence(data map[string]*scenarioData, firsts, lasts []time.Time) {
	if len(firsts) < 2 {
		return
	}

	// Find the overall time range across all files
	sort.Slice(firsts, func(i, j int) bool { return firsts[i].Before(firsts[j]) })
	sort.Slice(lasts, func(i, j int) bool { return lasts[i].Before(lasts[j]) })

	overallFirst := firsts[0]
	overallLast := lasts[len(lasts)-1]

	for name, sd := range data {
		if sd.FirstTime.IsZero() || sd.LastTime.IsZero() {
			continue
		}
		// Check if this file's timestamps are >1h apart from the overall range
		if sd.FirstTime.After(overallLast.Add(time.Hour)) || sd.LastTime.Before(overallFirst.Add(-time.Hour)) {
			fmt.Fprintf(os.Stderr, "Warning: %s timestamps are >1h apart from other files — may be from a different run\n", name)
		}
	}

	totalSpan := overallLast.Sub(overallFirst)
	if totalSpan > 2*time.Hour {
		fmt.Fprintf(os.Stderr, "Warning: timestamp span across all files is %s — may contain mixed runs\n", totalSpan.Round(time.Second))
	}
}

func checkManifest(dir string, data map[string]*scenarioData) {
	manifestPath := filepath.Join(dir, "_manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return // manifest is optional
	}

	var manifest selftestManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not parse _manifest.json: %v\n", err)
		return
	}

	fmt.Fprintf(os.Stdout, "Manifest: selftest run at %s (duration=%ds, version=%s)\n",
		manifest.Timestamp, manifest.Duration, manifest.Version)

	// Check expected scenarios
	for _, expected := range manifest.Scenarios {
		if _, ok := data[expected]; !ok {
			fmt.Fprintf(os.Stderr, "Warning: manifest expects scenario %q but no CSV found\n", expected)
		}
	}

	// Check for unexpected files
	expectedSet := make(map[string]bool, len(manifest.Scenarios))
	for _, s := range manifest.Scenarios {
		expectedSet[s] = true
	}
	for name := range data {
		if !expectedSet[name] {
			fmt.Fprintf(os.Stderr, "Warning: %s_metrics.csv not listed in manifest\n", name)
		}
	}
}

func printBatchReport(batch batchDef, data map[string]*scenarioData) {
	// Collect metrics for this batch
	var batchMetrics []metrics.Metric
	var presentScenarios []string

	for _, s := range batch.Scenarios {
		if sd, ok := data[s]; ok {
			batchMetrics = append(batchMetrics, sd.Metrics...)
			presentScenarios = append(presentScenarios, s)
		}
	}

	fmt.Fprintf(os.Stdout, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Fprintf(os.Stdout, "Batch %d — %s\n", batch.Number, batch.Name)
	fmt.Fprintf(os.Stdout, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	if len(presentScenarios) == 0 {
		fmt.Fprintf(os.Stdout, "  (no data — scenarios %v not found)\n\n", batch.Scenarios)
		return
	}

	missing := difference(batch.Scenarios, presentScenarios)
	if len(missing) > 0 {
		fmt.Fprintf(os.Stdout, "  Missing scenarios: %v\n", missing)
	}
	fmt.Fprintf(os.Stdout, "  Scenarios loaded: %v (%d records)\n\n", presentScenarios, len(batchMetrics))

	switch batch.Number {
	case 1:
		printBatch1(batchMetrics, data)
	case 2:
		printBatch2(batchMetrics, data)
	case 3:
		printBatch3(batchMetrics, data)
	case 4:
		printBatch4(batchMetrics, data)
	case 5:
		printBatch5(batchMetrics, data)
	case 6:
		printBatch6(batchMetrics, data)
	case 7:
		printBatch7(batchMetrics, data)
	case 8:
		printBatch8(batchMetrics, data)
	}

	fmt.Fprintln(os.Stdout)
}

// --- Batch 1: Baseline ODVA Compliance ---
func printBatch1(all []metrics.Metric, _ map[string]*scenarioData) {
	s := buildSummary(all)
	passRate := safePercent(s.SuccessfulOps, s.TotalOperations)

	printTable([][]string{
		{"Metric", "Value"},
		{"Pass-through rate", fmt.Sprintf("%.1f%%", passRate)},
		{"Avg RTT", fmt.Sprintf("%.3f ms", s.AvgRTT)},
		{"P99 RTT", fmt.Sprintf("%.3f ms", s.P99RTT)},
		{"Misclassifications", fmt.Sprintf("%d", s.Misclassifications)},
		{"Timeouts", fmt.Sprintf("%d", s.TimeoutCount)},
		{"TCP Resets", fmt.Sprintf("%d", s.TCPResetCount)},
	})
}

// --- Batch 2: High-Frequency Stress Reads ---
func printBatch2(all []metrics.Metric, data map[string]*scenarioData) {
	s := buildSummary(all)

	throughput := s.ThroughputOpsPerSec
	if throughput == 0 {
		if sd, ok := data["stress"]; ok && !sd.FirstTime.IsZero() && !sd.LastTime.IsZero() {
			elapsed := sd.LastTime.Sub(sd.FirstTime).Seconds()
			if elapsed > 0 {
				throughput = float64(s.TotalOperations) / elapsed
			}
		}
	}
	timeoutRate := safePercent(s.TimeoutCount, s.TotalOperations)

	printTable([][]string{
		{"Metric", "Value"},
		{"Throughput", fmt.Sprintf("%.0f ops/sec", throughput)},
		{"Timeouts", fmt.Sprintf("%d", s.TimeoutCount)},
		{"Timeout rate", fmt.Sprintf("%.3f%%", timeoutRate)},
		{"P50 RTT", fmt.Sprintf("%.3f ms", s.P50RTT)},
		{"P95 RTT", fmt.Sprintf("%.3f ms", s.P95RTT)},
		{"P99 RTT", fmt.Sprintf("%.3f ms", s.P99RTT)},
		{"TCP Resets", fmt.Sprintf("%d", s.TCPResetCount)},
		{"Total failures", fmt.Sprintf("%d", s.FailedOps)},
	})
}

// --- Batch 3: Forward Open / I/O Churn ---
func printBatch3(all []metrics.Metric, data map[string]*scenarioData) {
	// Per-scenario pass rates
	rows := [][]string{{"Scenario", "Ops", "Pass Rate", "FwdOpen Pass%", "FwdClose Pass%", "Session Resets"}}

	for _, scenarioName := range []string{"churn", "io", "mixed_state"} {
		sd, ok := data[scenarioName]
		if !ok {
			continue
		}
		s := buildSummary(sd.Metrics)

		fwdOpenStats := s.RTTByOperation[metrics.OperationForwardOpen]
		fwdCloseStats := s.RTTByOperation[metrics.OperationForwardClose]

		fwdOpenRate := "N/A"
		if fwdOpenStats != nil && fwdOpenStats.Count > 0 {
			fwdOpenRate = fmt.Sprintf("%.1f%%", safePercent(fwdOpenStats.Success, fwdOpenStats.Count))
		}
		fwdCloseRate := "N/A"
		if fwdCloseStats != nil && fwdCloseStats.Count > 0 {
			fwdCloseRate = fmt.Sprintf("%.1f%%", safePercent(fwdCloseStats.Success, fwdCloseStats.Count))
		}

		rows = append(rows, []string{
			scenarioName,
			fmt.Sprintf("%d", s.TotalOperations),
			fmt.Sprintf("%.1f%%", safePercent(s.SuccessfulOps, s.TotalOperations)),
			fwdOpenRate,
			fwdCloseRate,
			fmt.Sprintf("%d", s.TCPResetCount),
		})
	}

	printTable(rows)
}

// --- Batch 4: Vendor Variant Profile Cycling ---
func printBatch4(all []metrics.Metric, _ map[string]*scenarioData) {
	// Group by sub-label (e.g. vendor_variants:schneider_m580)
	byProfile := make(map[string][]metrics.Metric)
	for _, m := range all {
		profile := m.Scenario
		if idx := strings.Index(profile, ":"); idx >= 0 {
			profile = profile[idx+1:]
		}
		byProfile[profile] = append(byProfile[profile], m)
	}

	profiles := sortedKeys(byProfile)
	rows := [][]string{{"Profile", "Ops", "Pass Rate"}}
	for _, p := range profiles {
		ms := byProfile[p]
		s := buildSummary(ms)
		rows = append(rows, []string{
			p,
			fmt.Sprintf("%d", s.TotalOperations),
			fmt.Sprintf("%.1f%%", safePercent(s.SuccessfulOps, s.TotalOperations)),
		})
	}

	printTable(rows)
}

// --- Batch 5: DPI Explicit Messaging (6-Phase) ---
func printBatch5(all []metrics.Metric, _ map[string]*scenarioData) {
	// Group by sub-label (e.g. dpi_explicit:phase_0_baseline_sanity)
	byPhase := make(map[string][]metrics.Metric)
	for _, m := range all {
		phase := m.Scenario
		if idx := strings.Index(phase, ":"); idx >= 0 {
			phase = phase[idx+1:]
		}
		byPhase[phase] = append(byPhase[phase], m)
	}

	phases := sortedKeys(byPhase)
	rows := [][]string{{"Phase", "Total", "Success", "Fail", "Timeouts", "TCP Resets", "Misclass", "Verdict"}}

	for _, p := range phases {
		ms := byPhase[p]
		s := buildSummary(ms)

		passRate := safePercent(s.SuccessfulOps, s.TotalOperations)
		verdict := "Pass"
		if passRate <= 80 {
			verdict = "Fail"
		} else if passRate < 100 {
			verdict = "Warn"
		}

		rows = append(rows, []string{
			p,
			fmt.Sprintf("%d", s.TotalOperations),
			fmt.Sprintf("%d", s.SuccessfulOps),
			fmt.Sprintf("%d", s.FailedOps),
			fmt.Sprintf("%d", s.TimeoutCount),
			fmt.Sprintf("%d", s.TCPResetCount),
			fmt.Sprintf("%d", s.Misclassifications),
			verdict,
		})
	}

	printTable(rows)
}

// --- Batch 6: Evasion Techniques ---
func printBatch6(all []metrics.Metric, data map[string]*scenarioData) {
	for _, scenarioName := range []string{"evasion_segment", "evasion_fuzz", "evasion_anomaly", "evasion_timing"} {
		sd, ok := data[scenarioName]
		if !ok {
			continue
		}

		fmt.Fprintf(os.Stdout, "  %s:\n", scenarioName)

		// Group by target_name (technique)
		byTechnique := make(map[string][]metrics.Metric)
		for _, m := range sd.Metrics {
			name := m.TargetName
			if name == "" {
				name = "(unnamed)"
			}
			byTechnique[name] = append(byTechnique[name], m)
		}

		techniques := sortedKeys(byTechnique)
		rows := [][]string{{"Technique", "Total", "Success", "Failed", "Timeouts"}}

		for _, t := range techniques {
			ms := byTechnique[t]
			s := buildSummary(ms)
			rows = append(rows, []string{
				t,
				fmt.Sprintf("%d", s.TotalOperations),
				fmt.Sprintf("%d", s.SuccessfulOps),
				fmt.Sprintf("%d", s.FailedOps),
				fmt.Sprintf("%d", s.TimeoutCount),
			})
		}

		printTableIndented(rows, 4)
		fmt.Fprintln(os.Stdout)
	}
}

// --- Batch 7: Edge Cases + Legacy Protocol Tunneling ---
func printBatch7(all []metrics.Metric, data map[string]*scenarioData) {
	rows := [][]string{{"Scenario", "Ops", "Pass Rate", "Misclassified"}}

	for _, scenarioName := range []string{"edge_valid", "edge_vendor", "pccc", "modbus"} {
		sd, ok := data[scenarioName]
		if !ok {
			continue
		}
		s := buildSummary(sd.Metrics)
		rows = append(rows, []string{
			scenarioName,
			fmt.Sprintf("%d", s.TotalOperations),
			fmt.Sprintf("%.1f%%", safePercent(s.SuccessfulOps, s.TotalOperations)),
			fmt.Sprintf("%d", s.Misclassifications),
		})
	}

	printTable(rows)
}

// --- Batch 8: Mixed Realistic Workload (Regression) ---
func printBatch8(all []metrics.Metric, data map[string]*scenarioData) {
	s := buildSummary(all)

	overallPassRate := safePercent(s.SuccessfulOps, s.TotalOperations)
	misclassRate := safePercent(s.Misclassifications, s.TotalOperations)

	printTable([][]string{
		{"Metric", "Value"},
		{"Overall pass rate", fmt.Sprintf("%.1f%%", overallPassRate)},
		{"Session resets (TCP)", fmt.Sprintf("%d", s.TCPResetCount)},
		{"Misclassification rate", fmt.Sprintf("%.1f%%", misclassRate)},
		{"P50 RTT", fmt.Sprintf("%.3f ms", s.P50RTT)},
		{"P95 RTT", fmt.Sprintf("%.3f ms", s.P95RTT)},
		{"P99 RTT", fmt.Sprintf("%.3f ms", s.P99RTT)},
		{"Avg jitter", fmt.Sprintf("%.3f ms", s.AvgJitter)},
		{"P99 jitter", fmt.Sprintf("%.3f ms", s.P99Jitter)},
	})

	// Per-scenario breakdown for firewall packs
	fwScenarios := []string{"firewall_pack", "firewall_hirschmann", "firewall_moxa", "firewall_dynics"}
	var hasFW bool
	for _, name := range fwScenarios {
		if _, ok := data[name]; ok {
			hasFW = true
			break
		}
	}

	if hasFW {
		fmt.Fprintf(os.Stdout, "\n  Firewall pack per-scenario:\n")
		fwRows := [][]string{{"Scenario", "Ops", "Pass Rate", "Misclass", "Timeouts"}}
		for _, name := range fwScenarios {
			sd, ok := data[name]
			if !ok {
				continue
			}
			fs := buildSummary(sd.Metrics)
			fwRows = append(fwRows, []string{
				name,
				fmt.Sprintf("%d", fs.TotalOperations),
				fmt.Sprintf("%.1f%%", safePercent(fs.SuccessfulOps, fs.TotalOperations)),
				fmt.Sprintf("%d", fs.Misclassifications),
				fmt.Sprintf("%d", fs.TimeoutCount),
			})
		}
		printTableIndented(fwRows, 4)
	}
}

// --- Helpers ---

// buildSummary creates a Summary from a slice of metrics using a Sink.
func buildSummary(ms []metrics.Metric) *metrics.Summary {
	sink := metrics.NewSink()
	var firstTime, lastTime time.Time
	for i, m := range ms {
		sink.Record(m)
		if i == 0 {
			firstTime = m.Timestamp
		}
		lastTime = m.Timestamp
	}
	s := sink.GetSummary()
	if !firstTime.IsZero() && !lastTime.IsZero() {
		elapsed := lastTime.Sub(firstTime)
		s.DurationMs = elapsed.Seconds() * 1000
		if elapsed.Seconds() > 0 {
			s.ThroughputOpsPerSec = float64(s.TotalOperations) / elapsed.Seconds()
		}
	}
	return s
}

func safePercent(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func difference(all, present []string) []string {
	set := make(map[string]bool, len(present))
	for _, p := range present {
		set[p] = true
	}
	var diff []string
	for _, a := range all {
		if !set[a] {
			diff = append(diff, a)
		}
	}
	return diff
}

// printTable prints a table with auto-sized columns.
func printTable(rows [][]string) {
	printTableIndented(rows, 2)
}

// printTableIndented prints a table with the given indent.
func printTableIndented(rows [][]string, indent int) {
	if len(rows) == 0 {
		return
	}

	// Calculate column widths
	numCols := 0
	for _, row := range rows {
		if len(row) > numCols {
			numCols = len(row)
		}
	}
	widths := make([]int, numCols)
	for _, row := range rows {
		for j, cell := range row {
			if len(cell) > widths[j] {
				widths[j] = len(cell)
			}
		}
	}

	pad := strings.Repeat(" ", indent)

	for i, row := range rows {
		fmt.Fprint(os.Stdout, pad)
		for j, cell := range row {
			if j > 0 {
				fmt.Fprint(os.Stdout, "  ")
			}
			fmt.Fprintf(os.Stdout, "%-*s", widths[j], cell)
		}
		fmt.Fprintln(os.Stdout)

		// Print separator after header
		if i == 0 {
			fmt.Fprint(os.Stdout, pad)
			for j, w := range widths {
				if j > 0 {
					fmt.Fprint(os.Stdout, "  ")
				}
				fmt.Fprint(os.Stdout, strings.Repeat("─", w))
			}
			fmt.Fprintln(os.Stdout)
		}
	}
}
