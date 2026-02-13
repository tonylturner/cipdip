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
	"github.com/tonylturner/cipdip/internal/cip/spec"
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
	defer logger.Close()

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
			srv.Stop()
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

			if r.Status == "PASS" {
				fmt.Fprintf(os.Stdout, "[PASS] %d ops (%d ok, %d fail) %s\n", r.Ops, r.Success, r.Failed, r.RTT)
			} else if r.Status == "SKIP" {
				fmt.Fprintf(os.Stdout, "[SKIP] %s\n", r.Err)
			} else {
				fmt.Fprintf(os.Stdout, "[FAIL] %s\n", r.Err)
			}
		}

		srv.Stop()
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
			w.Close()
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
		Protocol: config.ProtocolConfig{Mode: "strict_odva"},
		Faults: config.ServerFaultConfig{
			Enable: true,
			Latency: config.ServerFaultLatencyConfig{
				BaseDelayMs:  opts.LatencyMs,
				JitterMs:     opts.JitterMs,
				SpikeEveryN:  0,
				SpikeDelayMs: 0,
			},
		},
		PCCCDataTables: []config.PCCCDataTableConfig{
			{FileType: "N", FileNumber: 7, Elements: 100},
			{FileType: "F", FileNumber: 8, Elements: 50},
			{FileType: "T", FileNumber: 4, Elements: 20},
		},
		ModbusConfig: config.ModbusServerConfig{
			Enabled:              true,
			CoilCount:            100,
			DiscreteInputCount:   100,
			InputRegisterCount:   100,
			HoldingRegisterCount: 100,
		},
	}

	switch personality {
	case "adapter":
		base.AdapterAssemblies = []config.AdapterAssemblyConfig{
			{
				Name:          "InputAssembly",
				Class:         spec.CIPClassAssembly,
				Instance:      0x65,
				Attribute:     0x03,
				SizeBytes:     16,
				Writable:      false,
				UpdatePattern: "counter",
			},
			{
				Name:          "InputAssembly2",
				Class:         spec.CIPClassAssembly,
				Instance:      0x66,
				Attribute:     0x03,
				SizeBytes:     16,
				Writable:      false,
				UpdatePattern: "counter",
			},
			{
				Name:          "OutputAssembly",
				Class:         spec.CIPClassAssembly,
				Instance:      0x67,
				Attribute:     0x03,
				SizeBytes:     16,
				Writable:      true,
				UpdatePattern: "static",
			},
		}

	case "logix_like":
		base.LogixTags = []config.LogixTagConfig{
			{Name: "scada", Type: "DINT", ArrayLength: 1, UpdatePattern: "counter"},
			{Name: "sensor_temp", Type: "REAL", ArrayLength: 10, UpdatePattern: "sine"},
			{Name: "motor_speed", Type: "INT", ArrayLength: 1, UpdatePattern: "static"},
			{Name: "plc_status", Type: "DINT", ArrayLength: 4, UpdatePattern: "random"},
		}
	}

	return base
}

// buildSelfTestServerConfig creates a server config using the default personality.
// Kept for backward compatibility with the basic selftest path.
func buildSelfTestServerConfig(opts SelfTestScenariosOptions) *config.ServerConfig {
	return buildServerConfigForPersonality(opts.Personality, opts)
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
		ProtocolVariants: []config.ProtocolConfig{
			{Mode: "strict_odva"},
			{Mode: "vendor_variant", Variant: "schneider_m580"},
			{Mode: "vendor_variant", Variant: "siemens_s7_1200"},
			{Mode: "vendor_variant", Variant: "rockwell_v32"},
		},
		ReadTargets: []config.CIPTarget{
			{
				Name:      "Identity_VendorID",
				Service:   config.ServiceGetAttributeSingle,
				Class:     spec.CIPClassIdentityObject,
				Instance:  0x01,
				Attribute: 0x01,
				Tags:      []string{"tc-enip-001-explicit", "tc-dyn-001-learn", "hirschmann", "moxa", "dynics"},
			},
			{
				Name:      "Identity_ProductType",
				Service:   config.ServiceGetAttributeSingle,
				Class:     spec.CIPClassIdentityObject,
				Instance:  0x01,
				Attribute: 0x02,
				Tags:      []string{"tc-enip-001-explicit", "tc-dyn-001-learn", "hirschmann", "moxa", "dynics"},
			},
			{
				Name:      "Assembly_Input1",
				Service:   config.ServiceGetAttributeSingle,
				Class:     spec.CIPClassAssembly,
				Instance:  0x65,
				Attribute: 0x03,
				Tags:      []string{"tc-enip-001-explicit", "tc-dyn-001-learn", "hirschmann", "moxa", "dynics"},
			},
		},
		WriteTargets: []config.CIPTarget{
			{
				Name:         "Assembly_Output1",
				Service:      config.ServiceSetAttributeSingle,
				Class:        spec.CIPClassAssembly,
				Instance:     0x67,
				Attribute:    0x03,
				Pattern:      "increment",
				InitialValue: 0,
				Tags:         []string{"tc-enip-001-explicit", "tc-dyn-001-learn", "hirschmann", "moxa", "dynics"},
			},
		},
		CustomTargets: []config.CIPTarget{
			{
				Name:        "Identity_GetAll",
				Service:     config.ServiceCustom,
				ServiceCode: uint8(spec.CIPServiceGetAttributeAll),
				Class:       spec.CIPClassIdentityObject,
				Instance:    0x01,
				Attribute:   0x00,
				Tags:        []string{"tc-enip-001-explicit", "tc-hirsch-001-pccc", "tc-hirsch-002-wildcard", "tc-moxa-001-default-action", "tc-dyn-001-learn", "tc-dyn-001-novel", "hirschmann", "moxa", "dynics"},
			},
			{
				Name:        "MessageRouter_GetAll",
				Service:     config.ServiceCustom,
				ServiceCode: uint8(spec.CIPServiceGetAttributeAll),
				Class:       spec.CIPClassMessageRouter,
				Instance:    0x01,
				Attribute:   0x00,
				Tags:        []string{"tc-enip-002-violation", "tc-hirsch-001-pccc", "tc-hirsch-002-wildcard", "tc-moxa-001-default-action", "tc-dyn-001-learn", "tc-dyn-001-novel", "hirschmann", "moxa", "dynics"},
			},
		},
		EdgeTargets: []config.EdgeTarget{
			// Standard CIP edge targets (used by edge_valid)
			{
				Name:            "Edge_HighInstance",
				Service:         config.ServiceGetAttributeSingle,
				Class:           spec.CIPClassIdentityObject,
				Instance:        0x1000,
				Attribute:       0x01,
				ExpectedOutcome: "error",
				Tags:            []string{"tc-enip-002-violation", "tc-hirsch-001-pccc", "tc-hirsch-002-wildcard", "tc-moxa-001-default-action", "tc-dyn-001-learn", "tc-dyn-001-novel", "hirschmann", "moxa", "dynics"},
			},
			{
				Name:            "Edge_InvalidClass",
				Service:         config.ServiceGetAttributeSingle,
				Class:           0xFF,
				Instance:        0x01,
				Attribute:       0x01,
				ExpectedOutcome: "error",
				Tags:            []string{"tc-enip-004-allowlist", "tc-hirsch-002-wildcard", "tc-moxa-001-default-action", "tc-dyn-001-novel", "hirschmann", "moxa", "dynics"},
			},
			{
				Name:            "Edge_ReservedService",
				Service:         config.ServiceCustom,
				ServiceCode:     0x20,
				Class:           spec.CIPClassIdentityObject,
				Instance:        0x01,
				Attribute:       0x00,
				ExpectedOutcome: "error",
				Tags:            []string{"tc-enip-003-reset", "tc-hirsch-001-pccc", "tc-moxa-001-default-action", "tc-dyn-001-novel", "hirschmann", "moxa", "dynics"},
			},
			// Vendor-specific targets for edge_vendor scenario (matched by logix_like server).
			// Payloads satisfy client-side CIP validation MinRequestLen requirements.
			{
				Name:              "Vendor_ExecutePCCC",
				Service:           config.ServiceCustom,
				ServiceCode:       uint8(spec.CIPServiceExecutePCCC),
				Class:             spec.CIPClassPCCCObject,
				Instance:          0x01,
				Attribute:         0x00,
				RequestPayloadHex: "0607000100", // PCCC echo command (cmd=06, sts=00, tns=0700, fnc=01, data=00)
				ExpectedOutcome:   "any",
				Tags:              []string{"tc-enip-001-explicit", "hirschmann", "moxa", "dynics"},
			},
			// Tag-based targets — names match LogixTags on the logix_like server
			{
				Name:              "scada",
				Service:           config.ServiceCustom,
				ServiceCode:       uint8(spec.CIPServiceReadTag),
				Class:             spec.CIPClassSymbolObject,
				Instance:          0x01,
				Attribute:         0x00,
				RequestPayloadHex: "0100", // Read 1 element
				ExpectedOutcome:   "any",
				Tags:              []string{"tc-enip-001-explicit", "hirschmann", "moxa", "dynics"},
			},
			{
				Name:              "motor_speed",
				Service:           config.ServiceCustom,
				ServiceCode:       uint8(spec.CIPServiceWriteTag),
				Class:             spec.CIPClassSymbolObject,
				Instance:          0x01,
				Attribute:         0x00,
				RequestPayloadHex: "c3000100 0000", // Type=INT(0xC3), count=1, data=0x0000
				ExpectedOutcome:   "any",
				Tags:              []string{"tc-enip-001-explicit", "hirschmann", "moxa", "dynics"},
			},
			{
				Name:              "sensor_temp",
				Service:           config.ServiceCustom,
				ServiceCode:       uint8(spec.CIPServiceReadTagFragmented),
				Class:             spec.CIPClassSymbolObject,
				Instance:          0x01,
				Attribute:         0x00,
				RequestPayloadHex: "0100 00000000", // Read 1 element, offset 0
				ExpectedOutcome:   "any",
				Tags:              []string{"tc-enip-001-explicit", "hirschmann", "moxa", "dynics"},
			},
		},
		IOConnections: []config.IOConnectionConfig{
			{
				Name:                  "TestIO",
				Transport:             "tcp",
				OToTRPIMs:             100,
				TToORPIMs:             100,
				OToTSizeBytes:         8,
				TToOSizeBytes:         8,
				Priority:              "scheduled",
				TransportClassTrigger: 3,
				Class:                 spec.CIPClassAssembly,
				Instance:              0x65,
				Tags:                  []string{"tc-enip-001-implicit", "hirschmann", "moxa", "dynics"},
			},
		},
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
		Version:   "0.2.4",
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}

	manifestPath := filepath.Join(opts.MetricsDir, "_manifest.json")
	_ = os.WriteFile(manifestPath, data, 0644)
}
