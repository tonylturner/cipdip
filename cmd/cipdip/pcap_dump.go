package main

import (
	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/app"
)

type pcapDumpFlags struct {
	inputFile   string
	serviceHex  string
	maxEntries  int
	showPayload bool
}

func newPcapDumpCmd() *cobra.Command {
	flags := &pcapDumpFlags{}

	cmd := &cobra.Command{
		Use:   "pcap-dump",
		Short: "Dump CIP service samples from a PCAP",
		Long: `Dump matching CIP packets from a PCAP by service code.

This is intended for targeted investigation of unknown services.`,
		Example: `  # Dump first 10 packets with service 0x51
  cipdip pcap-dump --input pcaps/stress/ENIP.pcap --service 0x51 --max 10`,
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
			if flags.serviceHex == "" {
				return missingFlagError(cmd, "--service")
			}
			return runPcapDump(flags)
		},
	}

	cmd.Flags().StringVar(&flags.inputFile, "input", "", "Input PCAP file (required)")
	cmd.Flags().StringVar(&flags.serviceHex, "service", "", "CIP service code (hex, e.g. 0x51)")
	cmd.Flags().IntVar(&flags.maxEntries, "max", 10, "Maximum number of entries to dump")
	cmd.Flags().BoolVar(&flags.showPayload, "payload", false, "Include a hex dump of the CIP payload")

	return cmd
}

func runPcapDump(flags *pcapDumpFlags) error {
	return app.RunPCAPDump(app.PCAPDumpOptions{
		InputFile:   flags.inputFile,
		ServiceHex:  flags.serviceHex,
		MaxEntries:  flags.maxEntries,
		ShowPayload: flags.showPayload,
	})
}
