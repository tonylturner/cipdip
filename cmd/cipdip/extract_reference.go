package main

import (
	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/app"
)

type extractFlags struct {
	pcapDir      string
	outputFile   string
	baselineDir  string
	realWorldDir string
}

func newExtractReferenceCmd() *cobra.Command {
	flags := &extractFlags{}

	cmd := &cobra.Command{
		Use:   "extract-reference",
		Short: "Extract reference packets from PCAP files",
		Long: `Extract reference packets from PCAP files and populate the reference library.

This command scans PCAP files for key CIP/ENIP packets (RegisterSession, GetAttributeSingle,
ForwardOpen, etc.) and extracts them as reference packets for validation.

It will look for PCAP files in:
  - baseline_captures/ (cipdip-generated captures)
  - pcaps/ (real-world captures, including normal/stress)
  - Or specify custom directories with --baseline-dir and --real-world-dir

The extracted packets are normalized (session IDs zeroed) so they can be used for comparison
across different sessions.`,
		Example: `  # Extract from default locations
  cipdip extract-reference

  # Extract from custom directories
  cipdip extract-reference --baseline-dir ./my_captures --real-world-dir ./real_pcaps

  # Extract and write to Go source file
  cipdip extract-reference --output internal/reference/reference_packets_gen.go`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExtractReference(flags)
		},
	}

	cmd.Flags().StringVar(&flags.baselineDir, "baseline-dir", "baseline_captures", "Directory containing baseline PCAP files")
	cmd.Flags().StringVar(&flags.realWorldDir, "real-world-dir", "pcaps", "Directory containing real-world PCAP files")
	cmd.Flags().StringVar(&flags.outputFile, "output", "", "Output Go source file (default: update reference.go directly)")

	return cmd
}

func runExtractReference(flags *extractFlags) error {
	return app.RunExtractReference(app.ExtractReferenceOptions{
		BaselineDir:  flags.baselineDir,
		RealWorldDir: flags.realWorldDir,
		OutputFile:   flags.outputFile,
	})
}
