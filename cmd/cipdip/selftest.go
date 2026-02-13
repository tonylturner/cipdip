package main

import (
	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/app"
)

type selfTestFlags struct {
	personality string
	latencyMs   int
	jitterMs    int
	scenarios   string
	durationSec int
	metricsDir  string
	verbose     bool
}

func newSelfTestCmd() *cobra.Command {
	flags := &selfTestFlags{
		personality: "adapter",
		latencyMs:   2,
		jitterMs:    1,
		durationSec: 5,
	}

	cmd := &cobra.Command{
		Use:   "selftest",
		Short: "Run a loopback client+server validation",
		Long: `Start an in-process CIP server on localhost and run client validation.

Without --scenarios, runs a quick CIP request/response check.
With --scenarios, runs full scenario-based testing against a local server,
verifying every DPI test batch command produces metrics.`,
		Example: `  # Quick loopback validation
  cipdip selftest

  # Run ALL scenarios from DPI test batches
  cipdip selftest --scenarios all

  # Run specific scenarios
  cipdip selftest --scenarios baseline,stress,dpi_explicit

  # Run scenarios with full server/client output
  cipdip selftest --scenarios all --verbose

  # Run scenarios with metrics output
  cipdip selftest --scenarios all --metrics-dir results/selftest

  # Longer duration per scenario
  cipdip selftest --scenarios all --duration-seconds 10`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSelfTest(flags)
		},
	}

	cmd.Flags().StringVar(&flags.personality, "personality", "adapter", "Server personality: adapter or logix_like")
	cmd.Flags().IntVar(&flags.latencyMs, "latency-ms", 2, "Base latency (ms) applied to server responses")
	cmd.Flags().IntVar(&flags.jitterMs, "jitter-ms", 1, "Latency jitter (ms) applied to server responses")
	cmd.Flags().StringVar(&flags.scenarios, "scenarios", "", "Run scenario-based testing: 'all' or comma-separated names")
	cmd.Flags().IntVar(&flags.durationSec, "duration-seconds", 5, "Duration per scenario in seconds (used with --scenarios)")
	cmd.Flags().StringVar(&flags.metricsDir, "metrics-dir", "", "Directory to write per-scenario metrics CSV files")
	cmd.Flags().BoolVar(&flags.verbose, "verbose", false, "Show full server/client log output during scenario runs")

	return cmd
}

func runSelfTest(flags *selfTestFlags) error {
	if flags.scenarios != "" {
		return app.RunSelfTestScenarios(app.SelfTestScenariosOptions{
			Personality: flags.personality,
			LatencyMs:   flags.latencyMs,
			JitterMs:    flags.jitterMs,
			DurationSec: flags.durationSec,
			Scenarios:   flags.scenarios,
			MetricsDir:  flags.metricsDir,
			Verbose:     flags.verbose,
		})
	}

	return app.RunSelfTest(app.SelfTestOptions{
		Personality: flags.personality,
		LatencyMs:   flags.latencyMs,
		JitterMs:    flags.jitterMs,
	})
}
