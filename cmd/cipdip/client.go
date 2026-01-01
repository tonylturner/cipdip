package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/capture"
	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	cipdipErrors "github.com/tturner/cipdip/internal/errors"
	"github.com/tturner/cipdip/internal/logging"
	"github.com/tturner/cipdip/internal/metrics"
	"github.com/tturner/cipdip/internal/scenario"
)

type clientFlags struct {
	ip          string
	port        int
	scenario    string
	intervalMs  int
	durationSec int
	config      string
	logFile     string
	metricsFile string
	verbose     bool
	debug       bool
	pcapFile    string
	quickStart  bool
}

func newClientCmd() *cobra.Command {
	flags := &clientFlags{}

	cmd := &cobra.Command{
		Use:   "client",
		Short: "Run in client/scanner mode",
		Long: `Connect to a CIP device and generate traffic using the specified scenario.

This is the primary mode for DPI (Deep Packet Inspection) testing. CIPDIP acts as a CIP
client that connects to a target device and generates repeatable, controllable traffic
patterns based on the selected scenario.

Available scenarios:
  baseline  - Low-frequency read-only polling (250ms default interval)
              Reads configured targets periodically
              
  mixed     - Medium-frequency mixed reads/writes (100ms default interval)
              Alternates between reading and writing configured targets
              
  stress    - High-frequency reads (20ms default interval)
              Rapid read requests to stress test DPI systems
              
  churn     - Connection setup/teardown cycles (100ms default interval)
              Repeatedly connects, performs operations, then disconnects
              
  io        - Connected Class 1 I/O-style behavior (10ms default interval)
              Uses ForwardOpen/ForwardClose and SendIOData/ReceiveIOData
              Requires io_connections configured in cipdip_client.yaml

  edge_valid - Protocol-valid edge cases for DPI falsification
               Uses edge_targets in cipdip_client.yaml

  vendor_variants - Replay traffic across protocol profile variants
                    Uses protocol_variants in cipdip_client.yaml

  mixed_state - Interleaves UCMM and connected I/O traffic
                Requires read_targets and io_connections

Configuration is loaded from cipdip_client.yaml (or --config). The config file defines
which CIP paths (class/instance/attribute) to read/write and any I/O connections.

Use --verbose or --debug for detailed logging, and --metrics-file to save metrics data.`,
		Example: `  # Run baseline scenario (low-frequency reads)
  cipdip client --ip 10.0.0.50 --scenario baseline

  # Run mixed scenario for 10 minutes
  cipdip client --ip 10.0.0.50 --scenario mixed --duration-seconds 600

  # Run stress test with custom interval
  cipdip client --ip 10.0.0.50 --scenario stress --interval-ms 10

  # Run I/O scenario with verbose logging
  cipdip client --ip 10.0.0.50 --scenario io --verbose

  # Save metrics to file
  cipdip client --ip 10.0.0.50 --scenario baseline --metrics-file metrics.csv

  # Capture packets to PCAP file
  cipdip client --ip 10.0.0.50 --scenario baseline --pcap capture.pcap`,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runClient(flags)
			if err != nil {
				// Runtime errors (after CLI validation) should exit with code 2
				// CLI errors (invalid flags, etc.) exit with code 1 via main
				os.Exit(2)
			}
			return nil
		},
	}

	// Required flags
	cmd.Flags().StringVar(&flags.ip, "ip", "", "Target CIP adapter IP address (required)")
	cmd.MarkFlagRequired("ip")

	cmd.Flags().StringVar(&flags.scenario, "scenario", "", "Scenario name: baseline|mixed|stress|churn|io|edge_valid|vendor_variants|mixed_state (required)")
	cmd.MarkFlagRequired("scenario")

	// Optional flags
	cmd.Flags().IntVar(&flags.port, "port", 44818, "CIP TCP port (default 44818)")
	cmd.Flags().IntVar(&flags.intervalMs, "interval-ms", 0, "Base polling interval in milliseconds (scenario-specific default if omitted)")
	cmd.Flags().IntVar(&flags.durationSec, "duration-seconds", 300, "Total run time in seconds (default 300)")
	cmd.Flags().StringVar(&flags.config, "config", "cipdip_client.yaml", "CIP targets config file (default \"cipdip_client.yaml\")")
	cmd.Flags().StringVar(&flags.logFile, "log-file", "", "Log file path (default: stdout/stderr only)")
	cmd.Flags().StringVar(&flags.metricsFile, "metrics-file", "", "Metrics output file path (default: print summary only)")
	cmd.Flags().BoolVar(&flags.verbose, "verbose", false, "Enable verbose output")
	cmd.Flags().BoolVar(&flags.debug, "debug", false, "Enable debug output")
	cmd.Flags().StringVar(&flags.pcapFile, "pcap", "", "Capture packets to PCAP file (e.g., capture.pcap)")
	cmd.Flags().BoolVar(&flags.quickStart, "quick-start", false, "Auto-generate default config if missing (zero-config usage)")

	return cmd
}

func runClient(flags *clientFlags) error {
	// Validate scenario (CLI error - exit code 1)
	validScenarios := map[string]bool{
		"baseline":        true,
		"mixed":           true,
		"stress":          true,
		"churn":           true,
		"io":              true,
		"edge_valid":      true,
		"vendor_variants": true,
		"mixed_state":     true,
	}
	if !validScenarios[flags.scenario] {
		return fmt.Errorf("invalid scenario '%s'; must be one of: baseline, mixed, stress, churn, io, edge_valid, vendor_variants, mixed_state", flags.scenario)
	}

	// Set default interval based on scenario if not provided
	if flags.intervalMs == 0 {
		switch flags.scenario {
		case "baseline":
			flags.intervalMs = 250
		case "mixed":
			flags.intervalMs = 100
		case "stress":
			flags.intervalMs = 20
		case "churn":
			flags.intervalMs = 100
		case "io":
			flags.intervalMs = 10
		case "edge_valid":
			flags.intervalMs = 100
		case "vendor_variants":
			flags.intervalMs = 100
		case "mixed_state":
			flags.intervalMs = 50
		}
	}

	// Determine log level
	logLevel := logging.LogLevelInfo
	if flags.debug {
		logLevel = logging.LogLevelDebug
	} else if flags.verbose {
		logLevel = logging.LogLevelVerbose
	}

	// Initialize logger (runtime error)
	logger, err := logging.NewLogger(logLevel, flags.logFile)
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}
	defer logger.Close()

	// Load config (runtime error if file issues, CLI error if validation fails)
	// If quick-start is enabled, auto-create default config if missing
	autoCreate := flags.quickStart
	cfg, err := config.LoadClientConfig(flags.config, autoCreate)
	if err != nil {
		// Check if it's a "file not found" error and we're not in quick-start mode
		var pathErr *os.PathError
		if !autoCreate && errors.As(err, &pathErr) && os.IsNotExist(pathErr.Err) {
			fmt.Fprintf(os.Stderr, "ERROR: Config file not found: %s\n", flags.config)
			fmt.Fprintf(os.Stderr, "Hint: Use --quick-start to auto-generate a default config file\n")
			fmt.Fprintf(os.Stderr, "      Or copy configs/cipdip_client.yaml.example to %s and customize it\n", flags.config)
			return fmt.Errorf("load config: %w", err)
		}
		// Wrap config error with user-friendly message
		userErr := cipdipErrors.WrapConfigError(err, flags.config)
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", userErr)
		return fmt.Errorf("load config: %w", err)
	}

	profile := cipclient.ResolveProtocolProfile(
		cfg.Protocol.Mode,
		cfg.Protocol.Variant,
		cfg.Protocol.Overrides.ENIPEndianness,
		cfg.Protocol.Overrides.CIPEndianness,
		cfg.Protocol.Overrides.CIPPathSize,
		cfg.Protocol.Overrides.CIPResponseReserved,
		cfg.Protocol.Overrides.UseCPF,
		cfg.Protocol.Overrides.IOSequenceMode,
	)
	cipclient.SetProtocolProfile(profile)

	// If we auto-created the config, inform the user
	if autoCreate {
		// Check if file was just created (stat the file to see if it's new)
		if info, err := os.Stat(flags.config); err == nil {
			// File exists, check if it's very new (created in last 2 seconds)
			if time.Since(info.ModTime()) < 2*time.Second {
				fmt.Fprintf(os.Stdout, "Created default config file: %s\n", flags.config)
				fmt.Fprintf(os.Stdout, "You can customize this file for your target device.\n\n")
			}
		}
	}

	// Initialize metrics (runtime error)
	metricsSink := metrics.NewSink()
	var metricsWriter *metrics.Writer
	if flags.metricsFile != "" {
		metricsWriter, err = metrics.NewWriter(flags.metricsFile, "")
		if err != nil {
			return fmt.Errorf("create metrics writer: %w", err)
		}
		defer metricsWriter.Close()
	}

	// Start packet capture if requested
	var pcapCapture *capture.Capture
	if flags.pcapFile != "" {
		fmt.Fprintf(os.Stdout, "Starting packet capture: %s\n", flags.pcapFile)
		pcapCapture, err = capture.StartCaptureLoopback(flags.pcapFile)
		if err != nil {
			return fmt.Errorf("start packet capture: %w", err)
		}
		defer pcapCapture.Stop()
	}

	// Print startup message to stdout FIRST (so user sees it immediately)
	fmt.Fprintf(os.Stdout, "CIPDIP Client starting...\n")
	fmt.Fprintf(os.Stdout, "  Scenario: %s\n", flags.scenario)
	fmt.Fprintf(os.Stdout, "  Target: %s:%d\n", flags.ip, flags.port)
	fmt.Fprintf(os.Stdout, "  Interval: %d ms\n", flags.intervalMs)
	fmt.Fprintf(os.Stdout, "  Duration: %d seconds\n", flags.durationSec)
	if flags.pcapFile != "" {
		fmt.Fprintf(os.Stdout, "  PCAP: %s\n", flags.pcapFile)
	}
	fmt.Fprintf(os.Stdout, "  Press Ctrl+C to stop\n\n")
	os.Stdout.Sync() // Flush output immediately

	// Log startup (for log file if specified)
	logger.LogStartup(flags.scenario, flags.ip, flags.port, flags.intervalMs, flags.durationSec, flags.config)

	// Create context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle SIGINT (Ctrl+C)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info("Received interrupt signal, shutting down gracefully...")
		cancel()
	}()

	// Create client
	client := cipclient.NewClient()

	// Get scenario (runtime error - should not happen if validation passed)
	scenarioImpl, err := scenario.GetScenario(flags.scenario)
	if err != nil {
		return fmt.Errorf("get scenario: %w", err)
	}

	// Prepare scenario parameters
	params := scenario.ScenarioParams{
		IP:          flags.ip,
		Port:        flags.port,
		Interval:    time.Duration(flags.intervalMs) * time.Millisecond,
		Duration:    time.Duration(flags.durationSec) * time.Second,
		MetricsSink: metricsSink,
		Logger:      logger,
		TargetType:  determineTargetType(cfg, flags.ip),
	}

	// Run scenario
	startTime := time.Now()
	err = scenarioImpl.Run(ctx, client, cfg, params)
	elapsed := time.Since(startTime)

	// Write metrics to file if specified
	if metricsWriter != nil {
		for _, m := range metricsSink.GetMetrics() {
			if err := metricsWriter.WriteMetric(m); err != nil {
				logger.Error("Failed to write metric: %v", err)
			}
		}
	}

	// Get and print summary
	summary := metricsSink.GetSummary()
	if flags.verbose || flags.debug {
		fmt.Fprintf(os.Stdout, "\n%s", metrics.FormatSummary(summary))
	} else {
		// Minimal output
		fmt.Fprintf(os.Stdout, "Completed scenario '%s' in %.1fs (%d operations, %d errors)\n",
			flags.scenario, elapsed.Seconds(), summary.TotalOperations, summary.FailedOps)
	}

	if err != nil {
		// Runtime error - exit code 2
		// Return error to be handled by main, which will exit with code 1
		// We'll handle exit code 2 in the error handling
		return fmt.Errorf("scenario failed: %w", err)
	}

	return nil
}

// determineTargetType determines the target type based on config and IP
func determineTargetType(cfg *config.Config, ip string) metrics.TargetType {
	// Check if IP is localhost/127.0.0.1 - likely emulator
	if ip == "127.0.0.1" || ip == "localhost" || ip == "::1" {
		// Could be emulator, but we don't know personality from client config
		// Default to click for now
		return metrics.TargetTypeClick
	}

	// Default to click (real device)
	// In the future, this could be determined from:
	// - Config file metadata
	// - Command-line flag
	// - Device discovery information
	return metrics.TargetTypeClick
}
