package main

import (
	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/app"
)

type selfTestFlags struct {
	personality string
	latencyMs   int
	jitterMs    int
}

func newSelfTestCmd() *cobra.Command {
	flags := &selfTestFlags{
		personality: "adapter",
		latencyMs:   2,
		jitterMs:    1,
	}

	cmd := &cobra.Command{
		Use:   "selftest",
		Short: "Run a loopback client+server validation",
		Long: `Start an in-process CIP server on localhost and run a small client
validation sequence to confirm request/response handling.`,
		Example: `  # Run loopback validation
  cipdip selftest

  # Use logix_like personality
  cipdip selftest --personality logix_like`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSelfTest(flags)
		},
	}

	cmd.Flags().StringVar(&flags.personality, "personality", "adapter", "Server personality: adapter or logix_like")
	cmd.Flags().IntVar(&flags.latencyMs, "latency-ms", 2, "Base latency (ms) applied to server responses")
	cmd.Flags().IntVar(&flags.jitterMs, "jitter-ms", 1, "Latency jitter (ms) applied to server responses")

	return cmd
}

func runSelfTest(flags *selfTestFlags) error {
	return app.RunSelfTest(app.SelfTestOptions{
		Personality: flags.personality,
		LatencyMs:   flags.latencyMs,
		JitterMs:    flags.jitterMs,
	})
}
