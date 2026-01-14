package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/app"
)

type clientFlags struct {
	ip               string
	port             int
	scenario         string
	intervalMs       int
	durationSec      int
	config           string
	logFile          string
	metricsFile      string
	verbose          bool
	debug            bool
	pcapFile         string
	captureInterface string
	quickStart       bool
	cipProfile       string
	targetTags       string
	firewall         string
	tuiStats         bool
	profile          string
	role             string
	outputDir        string
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

  edge_vendor - Vendor-specific edge cases (tag and connection manager extras)
               Uses edge_targets with vendor service codes

  rockwell - Consolidated Rockwell (Logix + ENBT) edge pack
             Uses rockwell-specific edge targets or built-in defaults

  vendor_variants - Replay traffic across protocol profile variants
                    Uses protocol_variants in cipdip_client.yaml

  mixed_state - Interleaves UCMM and connected I/O traffic
                Requires read_targets and io_connections

  unconnected_send - UCMM Unconnected Send wrapper with embedded CIP requests
                     Uses edge_targets in cipdip_client.yaml

  firewall_hirschmann - Hirschmann ENIP Enforcer DPI test pack
  firewall_moxa       - Moxa MX-ROS DPI test pack
  firewall_dynics     - Dynics ICS-Defender DPI test pack
  firewall_pack       - Run all firewall vendor packs (hirschmann, moxa, dynics)

  dpi_explicit        - Generic DPI explicit messaging test (vendor-neutral)
                        6-phase test: baseline, read ambiguity, connection lifecycle,
                        large payloads, violations, allowlist precision
                        Focused on TCP 44818 explicit messaging only

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
			if handleHelpArg(cmd, args) {
				return nil
			}
			if flags.ip == "" {
				return missingFlagError(cmd, "--ip")
			}
			// Either --scenario or --profile is required
			if flags.scenario == "" && flags.profile == "" {
				return missingFlagError(cmd, "--scenario or --profile")
			}
			// If using profile, role is required
			if flags.profile != "" && flags.role == "" {
				return missingFlagError(cmd, "--role (required when using --profile)")
			}
			err := runClient(flags)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(2)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&flags.ip, "ip", "", "Target CIP adapter IP address (required)")
	cmd.Flags().StringVar(&flags.scenario, "scenario", "", "Scenario name: baseline|mixed|stress|churn|io|edge_valid|edge_vendor|rockwell|vendor_variants|mixed_state|unconnected_send|firewall_hirschmann|firewall_moxa|firewall_dynics|firewall_pack|dpi_explicit (required)")
	cmd.Flags().IntVar(&flags.port, "port", 44818, "CIP TCP port (default 44818)")
	cmd.Flags().IntVar(&flags.intervalMs, "interval-ms", 0, "Base polling interval in milliseconds (scenario-specific default if omitted)")
	cmd.Flags().IntVar(&flags.durationSec, "duration-seconds", 300, "Total run time in seconds (default 300)")
	cmd.Flags().StringVar(&flags.config, "config", "cipdip_client.yaml", "CIP targets config file (default \"cipdip_client.yaml\")")
	cmd.Flags().StringVar(&flags.logFile, "log-file", "", "Log file path (default: stdout/stderr only)")
	cmd.Flags().StringVar(&flags.metricsFile, "metrics-file", "", "Metrics output file path (default: print summary only)")
	cmd.Flags().BoolVar(&flags.verbose, "verbose", false, "Enable verbose output")
	cmd.Flags().BoolVar(&flags.debug, "debug", false, "Enable debug output")
	cmd.Flags().StringVar(&flags.pcapFile, "pcap", "", "Capture packets to PCAP file (e.g., capture.pcap)")
	cmd.Flags().StringVar(&flags.captureInterface, "capture-interface", "", "Network interface for PCAP capture (auto-detected if not specified)")
	cmd.Flags().BoolVar(&flags.quickStart, "quick-start", false, "Auto-generate default config if missing (zero-config usage)")
	cmd.Flags().StringVar(&flags.cipProfile, "cip-profile", "", "CIP application profile(s): energy|safety|motion|all (comma-separated)")
	cmd.Flags().StringVar(&flags.targetTags, "target-tags", "", "Filter targets by comma-separated tags (e.g., rockwell,tc-enip-001-explicit)")
	cmd.Flags().StringVar(&flags.firewall, "firewall-vendor", "", "Annotate metrics with firewall vendor (hirschmann|moxa|dynics)")
	cmd.Flags().BoolVar(&flags.tuiStats, "tui-stats", false, "Enable JSON stats output for TUI consumption")
	cmd.Flags().StringVar(&flags.profile, "profile", "", "Process profile name (e.g., water_pump_station, batch_mixing_tank)")
	cmd.Flags().StringVar(&flags.role, "role", "", "Role to emulate from profile (e.g., hmi, historian, ews)")
	cmd.Flags().StringVar(&flags.outputDir, "output-dir", "", "Output directory for artifacts (run.json, summary, metrics, pcap)")

	return cmd
}

func runClient(flags *clientFlags) error {
	return app.RunClient(app.ClientOptions{
		IP:               flags.ip,
		Port:             flags.port,
		Scenario:         flags.scenario,
		IntervalMs:       flags.intervalMs,
		DurationSec:      flags.durationSec,
		ConfigPath:       flags.config,
		LogFile:          flags.logFile,
		MetricsFile:      flags.metricsFile,
		Verbose:          flags.verbose,
		Debug:            flags.debug,
		PCAPFile:         flags.pcapFile,
		CaptureInterface: flags.captureInterface,
		QuickStart:       flags.quickStart,
		CIPProfile:       flags.cipProfile,
		TargetTags:       flags.targetTags,
		FirewallVendor:   flags.firewall,
		TUIStats:         flags.tuiStats,
		Profile:          flags.profile,
		Role:             flags.role,
		OutputDir:        flags.outputDir,
	})
}
