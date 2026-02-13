package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/pcap"
	"github.com/tonylturner/cipdip/internal/report"
)

type pcapReportFlags struct {
	pcapDir    string
	outputFile string
}

func newPcapReportCmd() *cobra.Command {
	flags := &pcapReportFlags{}

	cmd := &cobra.Command{
		Use:   "pcap-report",
		Short: "Generate a multi-PCAP summary report",
		Long: `Generate a Markdown report by running the ENIP/CIP summary
for every PCAP under the specified directory.`,
		Example: `  # Build a summary report from all pcaps
  cipdip pcap-report --pcap-dir pcaps --output notes/pcap/pcap_summary_report.md`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPcapReport(flags)
		},
	}

	cmd.Flags().StringVar(&flags.pcapDir, "pcap-dir", "pcaps", "Directory containing PCAP files")
	cmd.Flags().StringVar(&flags.outputFile, "output", "notes/pcap/pcap_summary_report.md", "Output Markdown report path")

	return cmd
}

func runPcapReport(flags *pcapReportFlags) error {
	entries, err := pcap.BuildSummaryEntries(flags.pcapDir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
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

	if _, err := fmt.Fprintf(f, "# PCAP Summary Report\n\nGenerated: %s\n\n", report.FormatTimestamp()); err != nil {
		return fmt.Errorf("write report header: %w", err)
	}

	for _, entry := range entries {
		if _, err := fmt.Fprintf(f, "## %s\n\nSource: %s\n\n```text\n", entry.Name, entry.Path); err != nil {
			return fmt.Errorf("write report header for %s: %w", entry.Name, err)
		}

		if entry.Err != nil {
			if _, err := fmt.Fprintf(f, "Error: %v\n", entry.Err); err != nil {
				return fmt.Errorf("write error for %s: %w", entry.Name, err)
			}
		} else {
			report.WritePCAPSummary(f, entry.Summary)
		}

		if _, err := fmt.Fprintf(f, "```\n\n"); err != nil {
			return fmt.Errorf("close report block for %s: %w", entry.Name, err)
		}
	}

	fmt.Fprintf(os.Stdout, "PCAP summary report written: %s\n", flags.outputFile)
	return nil
}
