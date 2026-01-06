package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/pcap"
	"github.com/tturner/cipdip/internal/report"
)

type pcapCoverageFlags struct {
	pcapDir    string
	outputFile string
}

func newPcapCoverageCmd() *cobra.Command {
	flags := &pcapCoverageFlags{}

	cmd := &cobra.Command{
		Use:   "pcap-coverage",
		Short: "Generate a CIP service/object coverage report from PCAPs",
		Long: `Summarize CIP request coverage (service + class/instance/attribute)
across all PCAPs under the specified directory.`,
		Example: `  # Build a coverage report from all pcaps
  cipdip pcap-coverage --pcap-dir pcaps --output notes/pcap/pcap_coverage.md`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPcapCoverage(flags)
		},
	}

	cmd.Flags().StringVar(&flags.pcapDir, "pcap-dir", "pcaps", "Directory containing PCAP files")
	cmd.Flags().StringVar(&flags.outputFile, "output", "notes/pcap/pcap_coverage.md", "Output Markdown report path")

	return cmd
}

func runPcapCoverage(flags *pcapCoverageFlags) error {
	aggregate, fileErrors, err := pcap.AggregateCoverageReport(flags.pcapDir)
	if err != nil {
		return err
	}
	if aggregate == nil {
		return fmt.Errorf("no .pcap/.pcapng files found under %s", flags.pcapDir)
	}
	if len(aggregate.RequestEntries) == 0 && len(fileErrors) == 0 {
		return fmt.Errorf("no .pcap/.pcapng files found under %s", flags.pcapDir)
	}

	if err := os.MkdirAll(filepath.Dir(flags.outputFile), 0o755); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}
	f, err := os.Create(flags.outputFile)
	if err != nil {
		return fmt.Errorf("create report file: %w", err)
	}
	defer f.Close()

	report.WritePCAPCoverageReport(f, flags.pcapDir, aggregate, fileErrors)
	fmt.Fprintf(os.Stdout, "PCAP coverage report written: %s\n", flags.outputFile)
	return nil
}
