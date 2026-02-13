package main

import (
	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/app"
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
	return app.RunBaseline(app.BaselineOptions{
		OutputDir: flags.outputDir,
		Duration:  flags.duration,
	})
}
