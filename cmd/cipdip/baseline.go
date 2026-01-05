package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/capture"
	cipclient "github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
	"github.com/tturner/cipdip/internal/metrics"
	"github.com/tturner/cipdip/internal/scenario"
	"github.com/tturner/cipdip/internal/server"
)

type baselineFlags struct {
	outputDir string
	duration  int
}

func newBaselineCmd() *cobra.Command {
	flags := &baselineFlags{}

	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Run baseline test suite (all scenarios + server modes)",
		Long: `Run a comprehensive baseline test suite that executes all scenarios against all server personalities.

This command:
  - Runs each scenario (baseline, mixed, stress, churn, io) for 10 seconds each
  - Tests against both server personalities (adapter, logix_like)
  - Captures all traffic to PCAP files (combined and per-scenario)
  - Assumes server and client are on the same machine (127.0.0.1)

This provides reference examples of all traffic patterns for documentation and analysis.

Output:
  - Combined PCAP: baseline_all.pcap (all scenarios combined)
  - Per-scenario PCAPs: baseline_<scenario>_<personality>.pcap
  - All files saved to --output-dir (default: ./baseline_captures)`,
		Example: `  # Run baseline suite with default settings
  cipdip baseline

  # Run with custom output directory
  cipdip baseline --output-dir ./my_captures

  # Run with custom duration per scenario
  cipdip baseline --duration 5`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBaseline(flags)
		},
	}

	cmd.Flags().StringVar(&flags.outputDir, "output-dir", "./baseline_captures", "Output directory for PCAP files (default \"./baseline_captures\")")
	cmd.Flags().IntVar(&flags.duration, "duration", 10, "Duration per scenario in seconds (default 10)")

	return cmd
}

func runBaseline(flags *baselineFlags) error {
	fmt.Fprintf(os.Stdout, "CIPDIP Baseline Test Suite\n")
	fmt.Fprintf(os.Stdout, "==========================\n\n")
	fmt.Fprintf(os.Stdout, "This will run all scenarios against all server personalities.\n")
	fmt.Fprintf(os.Stdout, "Duration per scenario: %d seconds\n", flags.duration)
	fmt.Fprintf(os.Stdout, "Output directory: %s\n\n", flags.outputDir)

	// Create output directory
	if err := os.MkdirAll(flags.outputDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	// Load configs
	clientCfg, err := config.LoadClientConfig("cipdip_client.yaml", false)
	if err != nil {
		return fmt.Errorf("load client config: %w", err)
	}

	serverCfg, err := config.LoadServerConfig("cipdip_server.yaml")
	if err != nil {
		return fmt.Errorf("load server config: %w", err)
	}

	// Create logger
	logger, err := logging.NewLogger(logging.LogLevelError, "")
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}

	// Scenarios to test
	scenarios := []string{"baseline", "mixed", "stress", "churn", "io"}
	personalities := []string{"adapter", "logix_like"}

	// Start combined capture
	combinedPcapPath := filepath.Join(flags.outputDir, "baseline_all.pcap")
	fmt.Fprintf(os.Stdout, "Starting combined capture: %s\n", combinedPcapPath)
	combinedCapture, err := capture.StartCaptureLoopback(combinedPcapPath)
	if err != nil {
		return fmt.Errorf("start combined capture: %w", err)
	}
	defer combinedCapture.Stop()

	// Run each scenario against each personality
	for _, personality := range personalities {
		fmt.Fprintf(os.Stdout, "\n=== Testing %s personality ===\n\n", personality)

		// Update server config personality
		serverCfg.Server.Personality = personality

		// Enable UDP I/O for I/O scenarios
		serverCfg.Server.EnableUDPIO = true

		// Start server
		srv, err := server.NewServer(serverCfg, logger)
		if err != nil {
			return fmt.Errorf("create server: %w", err)
		}

		if err := srv.Start(); err != nil {
			return fmt.Errorf("start server: %w", err)
		}

		// Wait for server to be ready
		time.Sleep(500 * time.Millisecond)

		// Get server port
		serverPort := serverCfg.Server.TCPPort
		if serverPort == 0 {
			serverPort = 44818
		}

		// Run each scenario
		for _, scenarioName := range scenarios {
			fmt.Fprintf(os.Stdout, "Running scenario: %s (personality: %s)\n", scenarioName, personality)

			// Skip io scenario if no I/O connections configured
			if scenarioName == "io" && len(clientCfg.IOConnections) == 0 {
				fmt.Fprintf(os.Stdout, "  Skipping io scenario (no I/O connections configured)\n")
				continue
			}

			// Start per-scenario capture
			scenarioPcapPath := filepath.Join(flags.outputDir, fmt.Sprintf("baseline_%s_%s.pcap", scenarioName, personality))
			scenarioCapture, err := capture.StartCaptureLoopback(scenarioPcapPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to start scenario capture: %v\n", err)
			}

			// Create client
			client := cipclient.NewClient()

			// Create scenario
			scenarioImpl, err := scenario.GetScenario(scenarioName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to get scenario %s: %v\n", scenarioName, err)
				if scenarioCapture != nil {
					scenarioCapture.Stop()
				}
				continue
			}

			// Create scenario params
			metricsSink := metrics.NewSink()
			params := scenario.ScenarioParams{
				IP:          "127.0.0.1",
				Port:        serverPort,
				Interval:    getDefaultInterval(scenarioName),
				Duration:    time.Duration(flags.duration) * time.Second,
				MetricsSink: metricsSink,
				Logger:      logger,
				TargetType:  metrics.TargetTypeEmulatorAdapter,
			}

			// Run scenario
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(flags.duration+5)*time.Second)
			err = scenarioImpl.Run(ctx, client, clientCfg, params)
			cancel()

			// Stop scenario capture
			if scenarioCapture != nil {
				scenarioCapture.Stop()
				packetCount := scenarioCapture.GetPacketCount()
				fmt.Fprintf(os.Stdout, "  Captured %d packets: %s\n", packetCount, scenarioPcapPath)
			}

			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: scenario %s failed: %v\n", scenarioName, err)
			} else {
				fmt.Fprintf(os.Stdout, "  ✓ Completed successfully\n")
			}

			// Clean disconnect
			client.Disconnect(ctx)
			time.Sleep(200 * time.Millisecond) // Brief pause between scenarios
		}

		// Stop server
		if err := srv.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: server stop error: %v\n", err)
		}
		time.Sleep(500 * time.Millisecond) // Brief pause between personalities
	}

	// Stop combined capture
	combinedCapture.Stop()
	combinedPacketCount := combinedCapture.GetPacketCount()
	fmt.Fprintf(os.Stdout, "\n=== Baseline Suite Complete ===\n")
	fmt.Fprintf(os.Stdout, "Combined capture: %d packets saved to %s\n", combinedPacketCount, combinedPcapPath)
	fmt.Fprintf(os.Stdout, "Individual captures saved to: %s\n", flags.outputDir)

	return nil
}

func getDefaultInterval(scenarioName string) time.Duration {
	switch scenarioName {
	case "baseline":
		return 250 * time.Millisecond
	case "mixed":
		return 100 * time.Millisecond
	case "stress":
		return 20 * time.Millisecond
	case "churn":
		return 100 * time.Millisecond
	case "io":
		return 10 * time.Millisecond
	default:
		return 100 * time.Millisecond
	}
}


