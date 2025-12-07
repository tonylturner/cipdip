package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type clientFlags struct {
	ip             string
	port           int
	scenario       string
	intervalMs     int
	durationSec    int
	config         string
	logFile        string
	metricsFile    string
	verbose        bool
	debug          bool
}

func newClientCmd() *cobra.Command {
	flags := &clientFlags{}

	cmd := &cobra.Command{
		Use:   "client",
		Short: "Run in client/scanner mode",
		Long: `Connect to a CIP target and generate traffic using the specified scenario.
This is the primary mode for DPI testing.`,
		Example: `  cipdip client --ip 10.0.0.50 --scenario baseline
  cipdip client --ip 10.0.0.50 --scenario mixed --duration-seconds 600
  cipdip client --ip 10.0.0.50 --scenario stress --interval-ms 10`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClient(flags)
		},
	}

	// Required flags
	cmd.Flags().StringVar(&flags.ip, "ip", "", "Target CIP adapter IP address (required)")
	cmd.MarkFlagRequired("ip")

	cmd.Flags().StringVar(&flags.scenario, "scenario", "", "Scenario name: baseline|mixed|stress|churn|io (required)")
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

	return cmd
}

func runClient(flags *clientFlags) error {
	// Validate scenario
	validScenarios := map[string]bool{
		"baseline": true,
		"mixed":    true,
		"stress":   true,
		"churn":    true,
		"io":       true,
	}
	if !validScenarios[flags.scenario] {
		return fmt.Errorf("invalid scenario '%s'; must be one of: baseline, mixed, stress, churn, io", flags.scenario)
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
		}
	}

	// TODO: Load config
	// TODO: Initialize logger
	// TODO: Initialize metrics
	// TODO: Create client
	// TODO: Run scenario

	// Placeholder output
	if flags.verbose {
		fmt.Fprintf(os.Stdout, "Connecting to %s:%d\n", flags.ip, flags.port)
		fmt.Fprintf(os.Stdout, "Scenario: %s\n", flags.scenario)
		fmt.Fprintf(os.Stdout, "Interval: %d ms\n", flags.intervalMs)
		fmt.Fprintf(os.Stdout, "Duration: %d seconds\n", flags.durationSec)
		fmt.Fprintf(os.Stdout, "Config: %s\n", flags.config)
	}

	fmt.Fprintf(os.Stderr, "error: client mode not yet fully implemented\n")
	return fmt.Errorf("client mode not yet fully implemented")
}

