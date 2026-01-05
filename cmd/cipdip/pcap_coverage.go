package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
	legacy "github.com/tturner/cipdip/internal/cipclient"
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
  cipdip pcap-coverage --pcap-dir pcaps --output notes/pcap_coverage.md`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPcapCoverage(flags)
		},
	}

	cmd.Flags().StringVar(&flags.pcapDir, "pcap-dir", "pcaps", "Directory containing PCAP files")
	cmd.Flags().StringVar(&flags.outputFile, "output", "notes/pcap_coverage.md", "Output Markdown report path")

	return cmd
}

func runPcapCoverage(flags *pcapCoverageFlags) error {
	pcaps, err := collectCoveragePcapFiles(flags.pcapDir)
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

	fmt.Fprintf(f, "# PCAP Coverage Report\n\nGenerated: %s\n\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(f, "PCAP root: %s\n\n", flags.pcapDir)

	aggregate := &legacy.PCAPCoverageReport{
		ServiceCounts:       make(map[uint8]int),
		ServiceResponseCt:   make(map[uint8]int),
		RequestEntries:      make(map[string]*legacy.CIPCoverageEntry),
		EmbeddedEntries:     make(map[string]*legacy.CIPCoverageEntry),
		UnknownServicePairs: make(map[string]int),
	}

	for _, pcapPath := range pcaps {
		report, err := legacy.SummarizeCoverageFromPCAP(pcapPath)
		if err != nil {
			fmt.Fprintf(f, "## %s\n\nError: %v\n\n", filepath.Base(pcapPath), err)
			continue
		}

		mergeCoverage(aggregate, report)
	}

	writeCoverageSummary(f, aggregate)
	fmt.Fprintf(os.Stdout, "PCAP coverage report written: %s\n", flags.outputFile)
	return nil
}

func collectCoveragePcapFiles(root string) ([]string, error) {
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

func mergeCoverage(dst, src *legacy.PCAPCoverageReport) {
	for svc, count := range src.ServiceCounts {
		dst.ServiceCounts[svc] += count
	}
	for svc, count := range src.ServiceResponseCt {
		dst.ServiceResponseCt[svc] += count
	}
	for key, entry := range src.RequestEntries {
		dstEntry := dst.RequestEntries[key]
		if dstEntry == nil {
			clone := *entry
			dst.RequestEntries[key] = &clone
			continue
		}
		dstEntry.Count += entry.Count
	}
	for key, entry := range src.EmbeddedEntries {
		dstEntry := dst.EmbeddedEntries[key]
		if dstEntry == nil {
			clone := *entry
			dst.EmbeddedEntries[key] = &clone
			continue
		}
		dstEntry.Count += entry.Count
	}
	for key, count := range src.UnknownServicePairs {
		dst.UnknownServicePairs[key] += count
	}
}

func writeCoverageSummary(f *os.File, report *legacy.PCAPCoverageReport) {
	fmt.Fprintf(f, "## CIP Service Counts\n\n```text\n")
	for _, svc := range sortedServiceKeys(report.ServiceCounts) {
		name := spec.ServiceName(protocol.CIPServiceCode(svc))
		fmt.Fprintf(f, "0x%02X %s: %d requests, %d responses\n", svc, name, report.ServiceCounts[svc]-report.ServiceResponseCt[svc], report.ServiceResponseCt[svc])
	}
	fmt.Fprintf(f, "```\n\n")

	fmt.Fprintf(f, "## CIP Request Coverage (Service/Class/Instance/Attribute)\n\n```text\n")
	for _, key := range legacy.SortedCoverageEntries(report.RequestEntries) {
		entry := report.RequestEntries[key]
		fmt.Fprintf(f, "%s (%d)\n", key, entry.Count)
	}
	fmt.Fprintf(f, "```\n\n")

	if len(report.EmbeddedEntries) > 0 {
		fmt.Fprintf(f, "## Embedded CIP Request Coverage (Unconnected Send)\n\n```text\n")
		for _, key := range legacy.SortedCoverageEntries(report.EmbeddedEntries) {
			entry := report.EmbeddedEntries[key]
			fmt.Fprintf(f, "%s (%d)\n", key, entry.Count)
		}
		fmt.Fprintf(f, "```\n\n")
	}
}

func sortedServiceKeys(values map[uint8]int) []uint8 {
	keys := make([]uint8, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	return keys
}



