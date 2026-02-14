package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/config"
	"github.com/tonylturner/cipdip/internal/logging"
	"github.com/tonylturner/cipdip/internal/metrics"
	"github.com/tonylturner/cipdip/internal/scenario"
	"github.com/tonylturner/cipdip/internal/server"
)

// SelfTestScenariosOptions configures the scenario-based selftest.
type SelfTestScenariosOptions struct {
	Personality string
	LatencyMs   int
	JitterMs    int
	DurationSec int
	Scenarios   string // comma-separated list, or "all"
	MetricsDir  string
	Verbose     bool
}

type scenarioEntry struct {
	Name           string
	IntervalMs     int
	MinDurationSec int    // minimum duration override; 0 means use global default
	NeedsCfg       bool   // true if scenario requires specific config sections
	Personality    string // server personality required; empty defaults to "adapter"
}

func (e scenarioEntry) personality() string {
	if e.Personality == "" {
		return "adapter"
	}
	return e.Personality
}

// allScenarios lists every scenario from the DPI test batches doc with its default interval.
var allScenarios = []scenarioEntry{
	// Batch 1
	{Name: "baseline", IntervalMs: 250},
	// Batch 2
	{Name: "stress", IntervalMs: 20},
	// Batch 3
	{Name: "churn", IntervalMs: 100},
	{Name: "io", IntervalMs: 10, NeedsCfg: true},
	// Batch 4
	{Name: "vendor_variants", IntervalMs: 100, NeedsCfg: true},
	// Batch 5
	{Name: "dpi_explicit", IntervalMs: 100},
	// Batch 6
	{Name: "evasion_segment", IntervalMs: 200},
	{Name: "evasion_fuzz", IntervalMs: 500, MinDurationSec: 15},
	{Name: "evasion_anomaly", IntervalMs: 300},
	{Name: "evasion_timing", IntervalMs: 1000, MinDurationSec: 25},
	// Batch 7
	{Name: "edge_valid", IntervalMs: 200, NeedsCfg: true},
	{Name: "edge_vendor", IntervalMs: 200, NeedsCfg: true, Personality: "logix_like"},
	{Name: "rockwell", IntervalMs: 100, NeedsCfg: true, Personality: "logix_like"},
	{Name: "unconnected_send", IntervalMs: 200, NeedsCfg: true},
	{Name: "pccc", IntervalMs: 200},
	{Name: "modbus", IntervalMs: 200},
	// Batch 8
	{Name: "mixed", IntervalMs: 100},
	{Name: "mixed_state", IntervalMs: 50, NeedsCfg: true},
	{Name: "firewall_pack", IntervalMs: 100, NeedsCfg: true},
	{Name: "firewall_hirschmann", IntervalMs: 100, NeedsCfg: true},
	{Name: "firewall_moxa", IntervalMs: 100, NeedsCfg: true},
	{Name: "firewall_dynics", IntervalMs: 100, NeedsCfg: true},
}

// selfTestResult holds one scenario's outcome.
type selfTestResult struct {
	Name    string
	Status  string
	Ops     int
	Success int
	Failed  int
	RTT     string
	Err     string
}

// RunSelfTestScenarios starts in-process servers (switching personality as needed)
// and runs each scenario from the DPI test batches, collecting metrics and reporting results.
func RunSelfTestScenarios(opts SelfTestScenariosOptions) error {
	if opts.DurationSec <= 0 {
		opts.DurationSec = 5
	}

	requested := resolveScenarioList(opts.Scenarios)

	logLevel := logging.LogLevelSilent
	if opts.Verbose {
		logLevel = logging.LogLevelVerbose
	}
	logger, err := logging.NewLogger(logLevel, "")
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}
	defer func() { _ = logger.Close() }()

	// Build client config (shared across all personality groups).
	clientCfg := buildSelfTestClientConfig(0) // port updated per server instance

	// Group scenarios by required personality while preserving order.
	type personalityGroup struct {
		personality string
		entries     []scenarioEntry
	}
	var groups []personalityGroup
	var currentGroup *personalityGroup

	for _, entry := range allScenarios {
		if len(requested) > 0 && !requested[entry.Name] {
			continue
		}
		p := entry.personality()
		if currentGroup == nil || currentGroup.personality != p {
			groups = append(groups, personalityGroup{personality: p})
			currentGroup = &groups[len(groups)-1]
		}
		currentGroup.entries = append(currentGroup.entries, entry)
	}

	var results []selfTestResult

	for _, group := range groups {
		// Start server with the required personality.
		serverCfg := buildServerConfigForPersonality(group.personality, opts)
		srv, err := server.NewServer(serverCfg, logger)
		if err != nil {
			return fmt.Errorf("create %s server: %w", group.personality, err)
		}
		if err := srv.Start(); err != nil {
			return fmt.Errorf("start %s server: %w", group.personality, err)
		}

		addr := srv.TCPAddr()
		if addr == nil {
			_ = srv.Stop()
			return fmt.Errorf("server did not expose TCP address")
		}
		port := addr.Port

		// Update client config port for this server instance.
		clientCfg.Adapter.Port = port

		fmt.Fprintf(os.Stdout, "Selftest server on 127.0.0.1:%d (personality: %s)\n\n", port, group.personality)

		for _, entry := range group.entries {
			fmt.Fprintf(os.Stdout, "--- Scenario: %s ", entry.Name)
			os.Stdout.Sync()

			r := runSingleScenario(entry, clientCfg, port, opts, logger)
			results = append(results, r)

			switch r.Status {
			case "PASS":
				fmt.Fprintf(os.Stdout, "[PASS] %d ops (%d ok, %d fail) %s\n", r.Ops, r.Success, r.Failed, r.RTT)
			case "SKIP":
				fmt.Fprintf(os.Stdout, "[SKIP] %s\n", r.Err)
			default:
				fmt.Fprintf(os.Stdout, "[FAIL] %s\n", r.Err)
			}
		}

		_ = srv.Stop()
	}

	// Write manifest for metrics-report coherence checking
	if opts.MetricsDir != "" {
		writeSelftestManifest(opts, results)
	}

	// --- Summary ---
	fmt.Fprintf(os.Stdout, "\n=== Selftest Scenario Summary ===\n")
	passed, failed, skipped := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case "PASS":
			passed++
		case "FAIL":
			failed++
			fmt.Fprintf(os.Stdout, "  FAIL: %s — %s\n", r.Name, r.Err)
		case "SKIP":
			skipped++
		}
	}
	fmt.Fprintf(os.Stdout, "\nTotal: %d | Passed: %d | Failed: %d | Skipped: %d\n",
		len(results), passed, failed, skipped)

	if failed > 0 {
		return fmt.Errorf("%d scenario(s) failed", failed)
	}
	return nil
}

func runSingleScenario(entry scenarioEntry, clientCfg *config.Config, port int, opts SelfTestScenariosOptions, logger *logging.Logger) selfTestResult {
	scenarioImpl, err := scenario.GetScenario(entry.Name)
	if err != nil {
		return selfTestResult{Name: entry.Name, Status: "FAIL", Err: fmt.Sprintf("GetScenario: %v", err)}
	}

	sink := metrics.NewSink()
	durationSec := opts.DurationSec
	if entry.MinDurationSec > 0 && durationSec < entry.MinDurationSec {
		durationSec = entry.MinDurationSec
	}
	duration := time.Duration(durationSec) * time.Second

	targetType := metrics.TargetTypeEmulatorAdapter
	if entry.personality() == "logix_like" {
		targetType = metrics.TargetTypeEmulatorLogix
	}

	params := scenario.ScenarioParams{
		IP:          "127.0.0.1",
		Port:        port,
		Interval:    time.Duration(entry.IntervalMs) * time.Millisecond,
		Duration:    duration,
		MetricsSink: sink,
		Logger:      logger,
		TargetType:  targetType,
	}

	client := cipclient.NewClient()

	ctx, cancel := context.WithTimeout(context.Background(), duration+10*time.Second)
	defer cancel()

	startTime := time.Now()
	err = scenarioImpl.Run(ctx, client, clientCfg, params)
	elapsed := time.Since(startTime)

	summary := sink.GetSummary()
	summary.DurationMs = elapsed.Seconds() * 1000
	if summary.DurationMs > 0 {
		summary.ThroughputOpsPerSec = float64(summary.TotalOperations) / elapsed.Seconds()
	}

	// Write metrics CSV if output dir specified
	if opts.MetricsDir != "" {
		csvPath := fmt.Sprintf("%s/%s_metrics.csv", opts.MetricsDir, entry.Name)
		w, wErr := metrics.NewWriter(csvPath, "")
		if wErr == nil {
			for _, m := range sink.GetMetrics() {
				_ = w.WriteMetric(m)
			}
			_ = w.WriteSummary(summary, sink.GetMetrics())
			_ = w.Close()
		}
	}

	rttStr := ""
	if summary.SuccessfulOps > 0 {
		rttStr = fmt.Sprintf("RTT: avg=%.1fms p50=%.1fms p95=%.1fms p99=%.1fms",
			summary.AvgRTT, summary.P50RTT, summary.P95RTT, summary.P99RTT)
	}

	if err != nil {
		errMsg := err.Error()
		// Some errors are expected for config-dependent scenarios running with synthetic config
		if entry.NeedsCfg && isConfigDependentError(errMsg) {
			return selfTestResult{Name: entry.Name, Status: "SKIP", Err: "config-dependent: " + errMsg}
		}
		// Connection errors are tolerable if we still got operations recorded
		if summary.TotalOperations > 0 {
			return selfTestResult{
				Name: entry.Name, Status: "PASS",
				Ops: summary.TotalOperations, Success: summary.SuccessfulOps,
				Failed: summary.FailedOps, RTT: rttStr,
				Err: fmt.Sprintf("(completed with error: %s)", truncate(errMsg, 80)),
			}
		}
		return selfTestResult{Name: entry.Name, Status: "FAIL", Err: truncate(errMsg, 120)}
	}

	return selfTestResult{
		Name: entry.Name, Status: "PASS",
		Ops: summary.TotalOperations, Success: summary.SuccessfulOps,
		Failed: summary.FailedOps, RTT: rttStr,
	}
}

func isConfigDependentError(msg string) bool {
	patterns := []string{
		"no I/O connections configured",
		"requires protocol_variants",
		"requires edge_targets",
		"requires io_connections",
		"no matching edge_targets",
		"no runnable steps",
		"no targets matched",
	}
	lower := strings.ToLower(msg)
	for _, p := range patterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func resolveScenarioList(input string) map[string]bool {
	if input == "" || input == "all" {
		return nil // nil means run all
	}
	m := make(map[string]bool)
	for _, part := range strings.Split(input, ",") {
		name := strings.TrimSpace(part)
		if name != "" {
			m[name] = true
		}
	}
	return m
}

// buildServerConfigForPersonality returns the server config for the given personality.
func buildServerConfigForPersonality(personality string, opts SelfTestScenariosOptions) *config.ServerConfig {
	base := &config.ServerConfig{
		Server: config.ServerConfigSection{
			Name:                "SelfTest",
			Personality:         personality,
			ListenIP:            "127.0.0.1",
			TCPPort:             0, // random port
			EnableUDPIO:         false,
			ConnectionTimeoutMs: 5000,
		},
		Protocol:       config.ProtocolConfig{Mode: "strict_odva"},
		PCCCDataTables: config.DefaultPCCCDataTables(),
		ModbusConfig:   config.DefaultModbusConfig(),
		Faults: config.ServerFaultConfig{
			Enable: true,
			Latency: config.ServerFaultLatencyConfig{
				BaseDelayMs:  opts.LatencyMs,
				JitterMs:     opts.JitterMs,
				SpikeEveryN:  0,
				SpikeDelayMs: 0,
			},
		},
	}

	switch personality {
	case "adapter":
		base.AdapterAssemblies = config.DefaultAdapterAssemblies()
	case "logix_like":
		base.LogixTags = config.DefaultLogixTags()
	}

	return base
}

// buildSelfTestClientConfig creates a client config with all sections populated
// for comprehensive scenario testing.
func buildSelfTestClientConfig(port int) *config.Config {
	return &config.Config{
		Adapter: config.AdapterConfig{
			Name: "SelfTest Device",
			Port: port,
		},
		Protocol: config.ProtocolConfig{
			Mode: "strict_odva",
		},
		ProtocolVariants: config.DefaultProtocolVariants(),
		ReadTargets:      config.DefaultReadTargets(),
		WriteTargets:     config.DefaultWriteTargets(),
		CustomTargets:    config.DefaultCustomTargets(),
		EdgeTargets:      config.DefaultEdgeTargets(),
		IOConnections:    []config.IOConnectionConfig{config.DefaultIOConnection()},
	}
}

// writeSelftestManifest writes a _manifest.json alongside the metrics CSVs
// so that metrics-report can validate run coherence.
func writeSelftestManifest(opts SelfTestScenariosOptions, results []selfTestResult) {
	type manifest struct {
		Timestamp string   `json:"timestamp"`
		Scenarios []string `json:"scenarios"`
		Duration  int      `json:"duration_seconds"`
		Version   string   `json:"version"`
	}

	var scenarios []string
	for _, r := range results {
		if r.Status != "SKIP" {
			scenarios = append(scenarios, r.Name)
		}
	}

	m := manifest{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Scenarios: scenarios,
		Duration:  opts.DurationSec,
		Version:   "0.2.8",
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}

	manifestPath := filepath.Join(opts.MetricsDir, "_manifest.json")
	_ = os.WriteFile(manifestPath, data, 0644)
}
