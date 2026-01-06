package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/pcap"
	"github.com/tturner/cipdip/internal/report"
)

type pcapSummaryFlags struct {
	inputFile string
}

func newPcapSummaryCmd() *cobra.Command {
	flags := &pcapSummaryFlags{}

	cmd := &cobra.Command{
		Use:   "pcap-summary",
		Short: "Summarize ENIP/CIP traffic in a PCAP file",
		Long: `Summarize ENIP/CIP traffic in a PCAP file, including command/service counts,
CPF usage, and common EPATHs.

If --input is omitted, the first positional argument is used.`,
		Example: `  # Summarize ENIP.pcap traffic
  cipdip pcap-summary --input pcaps/stress/ENIP.pcap`,
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
			return runPcapSummary(flags)
		},
	}

	cmd.Flags().StringVar(&flags.inputFile, "input", "", "Input PCAP file (required)")

	return cmd
}

func runPcapSummary(flags *pcapSummaryFlags) error {
	summary, err := pcap.SummarizeENIPFromPCAP(flags.inputFile)
	if err != nil {
		return fmt.Errorf("summarize pcap: %w", err)
	}

	report.WritePCAPSummary(os.Stdout, summary)

	return nil
}
