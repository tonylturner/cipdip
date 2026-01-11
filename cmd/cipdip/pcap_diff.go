package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/pcap"
)

func newPCAPDiffCmd() *cobra.Command {
	var flags struct {
		baseline        string
		compare         string
		outputFormat    string
		expectedRPI     float64
		rpiTolerance    float64
		skipTiming      bool
		skipRPI         bool
		outputFile      string
	}

	cmd := &cobra.Command{
		Use:   "pcap-diff",
		Short: "Compare two PCAP files for CIP service and timing differences",
		Long: `Compare two PCAP files to identify:
- Added/removed CIP service codes
- Added/removed object classes
- Latency differences (request/response timing)
- RPI jitter analysis for I/O traffic

Examples:
  cipdip pcap-diff --baseline before.pcap --compare after.pcap
  cipdip pcap-diff --baseline baseline.pcap --compare test.pcap --expected-rpi 20
  cipdip pcap-diff --baseline a.pcap --compare b.pcap --format json -o diff.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if flags.baseline == "" || flags.compare == "" {
				return fmt.Errorf("both --baseline and --compare are required")
			}

			opts := pcap.DefaultDiffOptions()
			opts.ExpectedRPIMs = flags.expectedRPI
			opts.RPITolerancePct = flags.rpiTolerance
			opts.IncludeTiming = !flags.skipTiming
			opts.IncludeRPI = !flags.skipRPI

			result, err := pcap.DiffPCAPs(flags.baseline, flags.compare, opts)
			if err != nil {
				return fmt.Errorf("diff failed: %w", err)
			}

			var output string
			switch flags.outputFormat {
			case "json":
				data, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return fmt.Errorf("marshal json: %w", err)
				}
				output = string(data)
			case "markdown", "md":
				output = formatDiffMarkdown(result)
			default:
				output = pcap.FormatDiffReport(result)
			}

			if flags.outputFile != "" {
				if err := os.WriteFile(flags.outputFile, []byte(output), 0644); err != nil {
					return fmt.Errorf("write output: %w", err)
				}
				fmt.Fprintf(os.Stdout, "Diff report written to: %s\n", flags.outputFile)
			} else {
				fmt.Fprint(os.Stdout, output)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&flags.baseline, "baseline", "", "Baseline PCAP file (required)")
	cmd.Flags().StringVar(&flags.compare, "compare", "", "PCAP file to compare against baseline (required)")
	cmd.Flags().StringVarP(&flags.outputFormat, "format", "f", "text", "Output format: text, json, markdown")
	cmd.Flags().Float64Var(&flags.expectedRPI, "expected-rpi", 20.0, "Expected RPI in milliseconds for jitter analysis")
	cmd.Flags().Float64Var(&flags.rpiTolerance, "rpi-tolerance", 10.0, "RPI tolerance percentage for violation detection")
	cmd.Flags().BoolVar(&flags.skipTiming, "skip-timing", false, "Skip latency analysis")
	cmd.Flags().BoolVar(&flags.skipRPI, "skip-rpi", false, "Skip RPI jitter analysis")
	cmd.Flags().StringVarP(&flags.outputFile, "output", "o", "", "Write output to file instead of stdout")

	return cmd
}

func formatDiffMarkdown(result *pcap.DiffResult) string {
	var b strings.Builder

	b.WriteString("# PCAP Diff Report\n\n")
	b.WriteString(fmt.Sprintf("**Baseline:** `%s`\n\n", result.BaselinePath))
	b.WriteString(fmt.Sprintf("**Compare:** `%s`\n\n", result.ComparePath))

	b.WriteString("## Packet Counts\n\n")
	b.WriteString("| Metric | Baseline | Compare |\n")
	b.WriteString("|--------|----------|--------|\n")
	b.WriteString(fmt.Sprintf("| Total Packets | %d | %d |\n",
		result.BaselinePacketCount, result.ComparePacketCount))
	b.WriteString(fmt.Sprintf("| CIP Messages | %d | %d |\n\n",
		result.BaselineCIPCount, result.CompareCIPCount))

	b.WriteString("## Service Code Differences\n\n")

	if len(result.AddedServices) > 0 {
		b.WriteString("### Added Services\n\n")
		b.WriteString("| Service | Name | Class | Count |\n")
		b.WriteString("|---------|------|-------|-------|\n")
		for _, s := range result.AddedServices {
			b.WriteString(fmt.Sprintf("| 0x%02X | %s | 0x%04X | %d |\n",
				s.ServiceCode, s.ServiceName, s.Class, s.Count))
		}
		b.WriteString("\n")
	}

	if len(result.RemovedServices) > 0 {
		b.WriteString("### Removed Services\n\n")
		b.WriteString("| Service | Name | Class | Count |\n")
		b.WriteString("|---------|------|-------|-------|\n")
		for _, s := range result.RemovedServices {
			b.WriteString(fmt.Sprintf("| 0x%02X | %s | 0x%04X | %d |\n",
				s.ServiceCode, s.ServiceName, s.Class, s.Count))
		}
		b.WriteString("\n")
	}

	if len(result.AddedServices) == 0 && len(result.RemovedServices) == 0 {
		b.WriteString("No service differences found.\n\n")
	}

	b.WriteString(fmt.Sprintf("**Common services:** %d\n\n", len(result.CommonServices)))

	// Timing
	if result.BaselineTiming != nil && result.CompareTiming != nil {
		b.WriteString("## Latency Analysis\n\n")
		b.WriteString("| Metric | Baseline | Compare | Delta |\n")
		b.WriteString("|--------|----------|---------|-------|\n")
		b.WriteString(fmt.Sprintf("| Samples | %d | %d | - |\n",
			result.BaselineTiming.PacketCount, result.CompareTiming.PacketCount))
		b.WriteString(fmt.Sprintf("| Min (ms) | %.3f | %.3f | %+.3f |\n",
			result.BaselineTiming.MinLatencyMs, result.CompareTiming.MinLatencyMs,
			result.CompareTiming.MinLatencyMs-result.BaselineTiming.MinLatencyMs))
		b.WriteString(fmt.Sprintf("| Avg (ms) | %.3f | %.3f | %+.3f |\n",
			result.BaselineTiming.AvgLatencyMs, result.CompareTiming.AvgLatencyMs,
			result.CompareTiming.AvgLatencyMs-result.BaselineTiming.AvgLatencyMs))
		b.WriteString(fmt.Sprintf("| P95 (ms) | %.3f | %.3f | %+.3f |\n",
			result.BaselineTiming.P95LatencyMs, result.CompareTiming.P95LatencyMs,
			result.CompareTiming.P95LatencyMs-result.BaselineTiming.P95LatencyMs))
		b.WriteString(fmt.Sprintf("| P99 (ms) | %.3f | %.3f | %+.3f |\n",
			result.BaselineTiming.P99LatencyMs, result.CompareTiming.P99LatencyMs,
			result.CompareTiming.P99LatencyMs-result.BaselineTiming.P99LatencyMs))
		b.WriteString("\n")
	}

	// RPI
	if result.BaselineRPI != nil && result.CompareRPI != nil &&
		(len(result.BaselineRPI.Intervals) > 0 || len(result.CompareRPI.Intervals) > 0) {
		b.WriteString("## RPI/Jitter Analysis\n\n")
		b.WriteString(fmt.Sprintf("**Expected RPI:** %.1f ms\n\n", result.BaselineRPI.ExpectedRPIMs))
		b.WriteString("| Metric | Baseline | Compare | Delta |\n")
		b.WriteString("|--------|----------|---------|-------|\n")
		b.WriteString(fmt.Sprintf("| I/O Packets | %d | %d | - |\n",
			result.BaselineRPI.PacketCount, result.CompareRPI.PacketCount))
		b.WriteString(fmt.Sprintf("| Avg Interval (ms) | %.3f | %.3f | %+.3f |\n",
			result.BaselineRPI.AvgIntervalMs, result.CompareRPI.AvgIntervalMs,
			result.CompareRPI.AvgIntervalMs-result.BaselineRPI.AvgIntervalMs))
		b.WriteString(fmt.Sprintf("| Jitter (ms) | %.3f | %.3f | %+.3f |\n",
			result.BaselineRPI.JitterMs, result.CompareRPI.JitterMs,
			result.CompareRPI.JitterMs-result.BaselineRPI.JitterMs))
		b.WriteString(fmt.Sprintf("| Std Dev (ms) | %.3f | %.3f | %+.3f |\n",
			result.BaselineRPI.StdDevMs, result.CompareRPI.StdDevMs,
			result.CompareRPI.StdDevMs-result.BaselineRPI.StdDevMs))
		b.WriteString(fmt.Sprintf("| RPI Violations | %d | %d | - |\n",
			result.BaselineRPI.RPIViolations, result.CompareRPI.RPIViolations))
		b.WriteString("\n")
	}

	return b.String()
}
