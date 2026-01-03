package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/cipclient"
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
  cipdip pcap-report --pcap-dir pcaps --output notes/pcap_summary_report.md`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPcapReport(flags)
		},
	}

	cmd.Flags().StringVar(&flags.pcapDir, "pcap-dir", "pcaps", "Directory containing PCAP files")
	cmd.Flags().StringVar(&flags.outputFile, "output", "notes/pcap_summary_report.md", "Output Markdown report path")

	return cmd
}

func runPcapReport(flags *pcapReportFlags) error {
	pcaps, err := collectPcapFiles(flags.pcapDir)
	if err != nil {
		return err
	}
	if len(pcaps) == 0 {
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

	if _, err := fmt.Fprintf(f, "# PCAP Summary Report\n\nGenerated: %s\n\n", formatTimestamp()); err != nil {
		return fmt.Errorf("write report header: %w", err)
	}

	for _, pcapPath := range pcaps {
		name := filepath.Base(pcapPath)
		if _, err := fmt.Fprintf(f, "## %s\n\nSource: %s\n\n```text\n", name, pcapPath); err != nil {
			return fmt.Errorf("write report header for %s: %w", name, err)
		}

		summary, err := cipclient.SummarizeENIPFromPCAP(pcapPath)
		if err != nil {
			if _, err := fmt.Fprintf(f, "Error: %v\n", err); err != nil {
				return fmt.Errorf("write error for %s: %w", name, err)
			}
		} else {
			writePcapSummary(f, summary)
		}

		if _, err := fmt.Fprintf(f, "```\n\n"); err != nil {
			return fmt.Errorf("close report block for %s: %w", name, err)
		}
	}

	fmt.Fprintf(os.Stdout, "PCAP summary report written: %s\n", flags.outputFile)
	return nil
}

func collectPcapFiles(root string) ([]string, error) {
	var pcaps []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".pcap" || ext == ".pcapng" {
			pcaps = append(pcaps, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk pcaps: %w", err)
	}

	sort.Strings(pcaps)
	return pcaps, nil
}

func formatTimestamp() string {
	return time.Now().Format(time.RFC3339)
}
