package main

import (
	"fmt"
	"os"

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
	records, firstTime, lastTime, err := metrics.ReadMetricsCSV(flags.inputFile)
	if err != nil {
		return err
	}

	sink := metrics.NewSink()
	for _, m := range records {
		sink.Record(m)
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

	fmt.Fprintf(os.Stdout, "Metrics analysis: %s (%d records)\n\n", flags.inputFile, len(records))
	fmt.Fprint(os.Stdout, metrics.FormatSummary(summary))

	return nil
}
