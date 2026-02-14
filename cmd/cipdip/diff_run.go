package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/orch/bundle"
	"github.com/tonylturner/cipdip/internal/pcap"
)

func newDiffRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare runs and bundles",
		Long: `Commands for comparing run bundles and generating diff reports.

The diff command provides tools for comparing orchestrated runs,
analyzing differences in CIP traffic, latency, and behavior.`,
	}

	cmd.AddCommand(newDiffRunBundleCmd())

	return cmd
}

func newDiffRunBundleCmd() *cobra.Command {
	var flags struct {
		role         string
		outputFormat string
		outputFile   string
		expectedRPI  float64
		rpiTolerance float64
		skipTiming   bool
		skipRPI      bool
		raw          bool
	}

	cmd := &cobra.Command{
		Use:   "run <baseline-bundle> <compare-bundle>",
		Short: "Compare two run bundles",
		Long: `Compare two run bundles to identify differences in CIP traffic.

This command auto-selects comparable PCAP files from each bundle based
on the role (default: client). It provides context from bundle metadata
and generates a comprehensive diff report.

The diff includes:
- CIP service code differences (added/removed)
- Object class differences
- Latency analysis (request/response timing)
- RPI jitter analysis (for I/O traffic)
- Bundle metadata context (run IDs, timestamps, status)

Examples:
  cipdip diff run runs/baseline-run runs/test-run
  cipdip diff run --role server runs/run1 runs/run2
  cipdip diff run --format json runs/baseline runs/compare -o diff.json
  cipdip diff run --format markdown runs/before runs/after -o report.md
  cipdip diff run --raw runs/run1 runs/run2   # Use raw pcap-diff output`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			baselinePath := args[0]
			comparePath := args[1]

			// Open bundles
			baselineBundle, err := bundle.Open(baselinePath)
			if err != nil {
				return fmt.Errorf("open baseline bundle: %w", err)
			}

			compareBundle, err := bundle.Open(comparePath)
			if err != nil {
				return fmt.Errorf("open compare bundle: %w", err)
			}

			// Find PCAP files for the specified role
			baselinePcap, err := findRolePcap(baselineBundle, flags.role)
			if err != nil {
				return fmt.Errorf("find baseline PCAP: %w", err)
			}

			comparePcap, err := findRolePcap(compareBundle, flags.role)
			if err != nil {
				return fmt.Errorf("find compare PCAP: %w", err)
			}

			// If raw mode, just use the basic pcap diff
			if flags.raw {
				opts := pcap.DefaultDiffOptions()
				opts.ExpectedRPIMs = flags.expectedRPI
				opts.RPITolerancePct = flags.rpiTolerance
				opts.IncludeTiming = !flags.skipTiming
				opts.IncludeRPI = !flags.skipRPI

				result, err := pcap.DiffPCAPs(baselinePcap, comparePcap, opts)
				if err != nil {
					return fmt.Errorf("diff failed: %w", err)
				}

				output := pcap.FormatDiffReport(result)
				fmt.Print(output)
				return nil
			}

			// Load bundle metadata for context
			baselineMeta, _ := baselineBundle.ReadRunMeta()
			compareMeta, _ := compareBundle.ReadRunMeta()
			baselineRoleMeta, _ := baselineBundle.ReadRoleMeta(flags.role)
			compareRoleMeta, _ := compareBundle.ReadRoleMeta(flags.role)

			// Run the diff
			opts := pcap.DefaultDiffOptions()
			opts.ExpectedRPIMs = flags.expectedRPI
			opts.RPITolerancePct = flags.rpiTolerance
			opts.IncludeTiming = !flags.skipTiming
			opts.IncludeRPI = !flags.skipRPI

			pcapResult, err := pcap.DiffPCAPs(baselinePcap, comparePcap, opts)
			if err != nil {
				return fmt.Errorf("diff failed: %w", err)
			}

			// Create enhanced result with bundle context
			result := &BundleDiffResult{
				Role:             flags.role,
				BaselineBundle:   baselineBundle.Path,
				CompareBundle:    compareBundle.Path,
				BaselinePcap:     baselinePcap,
				ComparePcap:      comparePcap,
				BaselineRunMeta:  baselineMeta,
				CompareRunMeta:   compareMeta,
				BaselineRoleMeta: baselineRoleMeta,
				CompareRoleMeta:  compareRoleMeta,
				PcapDiff:         pcapResult,
			}

			// Generate summary
			result.Summary = generateDiffSummary(result)

			// Format output
			var output string
			switch flags.outputFormat {
			case "json":
				data, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return fmt.Errorf("marshal json: %w", err)
				}
				output = string(data)
			case "markdown", "md":
				output = formatBundleDiffMarkdown(result)
			default:
				output = formatBundleDiffText(result)
			}

			if flags.outputFile != "" {
				if err := os.WriteFile(flags.outputFile, []byte(output), 0644); err != nil {
					return fmt.Errorf("write output: %w", err)
				}
				fmt.Fprintf(os.Stdout, "Diff report written to: %s\n", flags.outputFile)
			} else {
				fmt.Print(output)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&flags.role, "role", "client", "Role to compare (client or server)")
	cmd.Flags().StringVarP(&flags.outputFormat, "format", "f", "text", "Output format: text, json, markdown")
	cmd.Flags().StringVarP(&flags.outputFile, "output", "o", "", "Write output to file")
	cmd.Flags().Float64Var(&flags.expectedRPI, "expected-rpi", 20.0, "Expected RPI in milliseconds")
	cmd.Flags().Float64Var(&flags.rpiTolerance, "rpi-tolerance", 10.0, "RPI tolerance percentage")
	cmd.Flags().BoolVar(&flags.skipTiming, "skip-timing", false, "Skip latency analysis")
	cmd.Flags().BoolVar(&flags.skipRPI, "skip-rpi", false, "Skip RPI jitter analysis")
	cmd.Flags().BoolVar(&flags.raw, "raw", false, "Use raw pcap-diff output (no bundle context)")

	return cmd
}

// BundleDiffResult contains the complete diff result with bundle context.
type BundleDiffResult struct {
	Role             string            `json:"role"`
	BaselineBundle   string            `json:"baseline_bundle"`
	CompareBundle    string            `json:"compare_bundle"`
	BaselinePcap     string            `json:"baseline_pcap"`
	ComparePcap      string            `json:"compare_pcap"`
	BaselineRunMeta  *bundle.RunMeta   `json:"baseline_run_meta,omitempty"`
	CompareRunMeta   *bundle.RunMeta   `json:"compare_run_meta,omitempty"`
	BaselineRoleMeta *bundle.RoleMeta  `json:"baseline_role_meta,omitempty"`
	CompareRoleMeta  *bundle.RoleMeta  `json:"compare_role_meta,omitempty"`
	PcapDiff         *pcap.DiffResult  `json:"pcap_diff"`
	Summary          *DiffSummary      `json:"summary"`
}

// DiffSummary provides a high-level summary of differences.
type DiffSummary struct {
	ServicesAdded      int     `json:"services_added"`
	ServicesRemoved    int     `json:"services_removed"`
	ServicesCommon     int     `json:"services_common"`
	ClassesAdded       int     `json:"classes_added"`
	ClassesRemoved     int     `json:"classes_removed"`
	ClassesCommon      int     `json:"classes_common"`
	PacketCountDelta   int     `json:"packet_count_delta"`
	CIPCountDelta      int     `json:"cip_count_delta"`
	LatencyDeltaMs     float64 `json:"latency_delta_ms,omitempty"`     // P95 delta
	JitterDeltaMs      float64 `json:"jitter_delta_ms,omitempty"`
	HasSignificantDiff bool    `json:"has_significant_diff"`
	DiffScore          int     `json:"diff_score"` // 0-100, higher = more different
}

// findRolePcap finds the PCAP file for a role in a bundle.
func findRolePcap(b *bundle.Bundle, role string) (string, error) {
	pcaps, err := b.ListRolePcaps(role)
	if err != nil {
		return "", err
	}

	if len(pcaps) == 0 {
		return "", fmt.Errorf("no PCAP files found for role %s in bundle %s", role, b.Path)
	}

	// Prefer the standard naming convention
	standardNames := []string{
		role + ".pcap",
		role + ".pcapng",
	}

	for _, name := range standardNames {
		for _, pcap := range pcaps {
			if pcap == name {
				return filepath.Join(b.RoleDir(role), pcap), nil
			}
		}
	}

	// Fall back to first PCAP found
	return filepath.Join(b.RoleDir(role), pcaps[0]), nil
}

// generateDiffSummary creates a high-level summary of differences.
func generateDiffSummary(result *BundleDiffResult) *DiffSummary {
	summary := &DiffSummary{
		ServicesAdded:    len(result.PcapDiff.AddedServices),
		ServicesRemoved:  len(result.PcapDiff.RemovedServices),
		ServicesCommon:   len(result.PcapDiff.CommonServices),
		ClassesAdded:     len(result.PcapDiff.AddedClasses),
		ClassesRemoved:   len(result.PcapDiff.RemovedClasses),
		ClassesCommon:    len(result.PcapDiff.CommonClasses),
		PacketCountDelta: result.PcapDiff.ComparePacketCount - result.PcapDiff.BaselinePacketCount,
		CIPCountDelta:    result.PcapDiff.CompareCIPCount - result.PcapDiff.BaselineCIPCount,
	}

	// Calculate latency delta
	if result.PcapDiff.BaselineTiming != nil && result.PcapDiff.CompareTiming != nil {
		summary.LatencyDeltaMs = result.PcapDiff.CompareTiming.P95LatencyMs - result.PcapDiff.BaselineTiming.P95LatencyMs
	}

	// Calculate jitter delta
	if result.PcapDiff.BaselineRPI != nil && result.PcapDiff.CompareRPI != nil {
		summary.JitterDeltaMs = result.PcapDiff.CompareRPI.JitterMs - result.PcapDiff.BaselineRPI.JitterMs
	}

	// Determine if there's a significant difference
	summary.HasSignificantDiff = summary.ServicesAdded > 0 ||
		summary.ServicesRemoved > 0 ||
		summary.ClassesAdded > 0 ||
		summary.ClassesRemoved > 0

	// Calculate a diff score (0-100)
	score := 0
	if summary.ServicesAdded > 0 {
		score += min(summary.ServicesAdded*10, 30)
	}
	if summary.ServicesRemoved > 0 {
		score += min(summary.ServicesRemoved*10, 30)
	}
	if summary.ClassesAdded > 0 {
		score += min(summary.ClassesAdded*5, 15)
	}
	if summary.ClassesRemoved > 0 {
		score += min(summary.ClassesRemoved*5, 15)
	}
	// Add score for significant timing changes (>10% P95 change)
	if result.PcapDiff.BaselineTiming != nil && result.PcapDiff.CompareTiming != nil {
		if result.PcapDiff.BaselineTiming.P95LatencyMs > 0 {
			pctChange := (summary.LatencyDeltaMs / result.PcapDiff.BaselineTiming.P95LatencyMs) * 100
			if pctChange > 10 || pctChange < -10 {
				score += 10
			}
		}
	}
	summary.DiffScore = min(score, 100)

	return summary
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// formatBundleDiffText formats the diff result as plain text.
func formatBundleDiffText(result *BundleDiffResult) string {
	var b strings.Builder

	b.WriteString("Bundle Diff Report\n")
	b.WriteString(strings.Repeat("=", 70) + "\n\n")

	// Bundle context
	b.WriteString("Bundles:\n")
	b.WriteString(fmt.Sprintf("  Baseline: %s\n", result.BaselineBundle))
	b.WriteString(fmt.Sprintf("  Compare:  %s\n", result.CompareBundle))
	b.WriteString(fmt.Sprintf("  Role:     %s\n\n", result.Role))

	// Run metadata context
	if result.BaselineRunMeta != nil || result.CompareRunMeta != nil {
		b.WriteString("Run Information:\n")
		b.WriteString(strings.Repeat("-", 70) + "\n")
		if result.BaselineRunMeta != nil {
			b.WriteString(fmt.Sprintf("  Baseline Run ID: %s\n", result.BaselineRunMeta.RunID))
			b.WriteString(fmt.Sprintf("  Baseline Status: %s\n", result.BaselineRunMeta.Status))
			b.WriteString(fmt.Sprintf("  Baseline Time:   %s\n", result.BaselineRunMeta.StartedAt.Format(time.RFC3339)))
		}
		if result.CompareRunMeta != nil {
			b.WriteString(fmt.Sprintf("  Compare Run ID:  %s\n", result.CompareRunMeta.RunID))
			b.WriteString(fmt.Sprintf("  Compare Status:  %s\n", result.CompareRunMeta.Status))
			b.WriteString(fmt.Sprintf("  Compare Time:    %s\n", result.CompareRunMeta.StartedAt.Format(time.RFC3339)))
		}
		b.WriteString("\n")
	}

	// Summary
	b.WriteString("Summary:\n")
	b.WriteString(strings.Repeat("-", 70) + "\n")
	b.WriteString(fmt.Sprintf("  Diff Score:        %d/100", result.Summary.DiffScore))
	if result.Summary.HasSignificantDiff {
		b.WriteString(" (significant differences found)")
	} else {
		b.WriteString(" (no significant differences)")
	}
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  Services Added:    %d\n", result.Summary.ServicesAdded))
	b.WriteString(fmt.Sprintf("  Services Removed:  %d\n", result.Summary.ServicesRemoved))
	b.WriteString(fmt.Sprintf("  Services Common:   %d\n", result.Summary.ServicesCommon))
	b.WriteString(fmt.Sprintf("  Classes Added:     %d\n", result.Summary.ClassesAdded))
	b.WriteString(fmt.Sprintf("  Classes Removed:   %d\n", result.Summary.ClassesRemoved))
	b.WriteString(fmt.Sprintf("  Packet Delta:      %+d\n", result.Summary.PacketCountDelta))
	b.WriteString(fmt.Sprintf("  CIP Msg Delta:     %+d\n", result.Summary.CIPCountDelta))
	if result.Summary.LatencyDeltaMs != 0 {
		b.WriteString(fmt.Sprintf("  P95 Latency Delta: %+.3fms\n", result.Summary.LatencyDeltaMs))
	}
	if result.Summary.JitterDeltaMs != 0 {
		b.WriteString(fmt.Sprintf("  Jitter Delta:      %+.3fms\n", result.Summary.JitterDeltaMs))
	}
	b.WriteString("\n")

	// Include the detailed PCAP diff report
	b.WriteString("Detailed PCAP Analysis:\n")
	b.WriteString(strings.Repeat("-", 70) + "\n")
	b.WriteString(pcap.FormatDiffReport(result.PcapDiff))

	return b.String()
}

// formatBundleDiffMarkdown formats the diff result as markdown.
func formatBundleDiffMarkdown(result *BundleDiffResult) string {
	var b strings.Builder

	b.WriteString("# Bundle Diff Report\n\n")

	// Bundle context
	b.WriteString("## Bundles\n\n")
	b.WriteString("| | Path |\n")
	b.WriteString("|---|------|\n")
	b.WriteString(fmt.Sprintf("| **Baseline** | `%s` |\n", result.BaselineBundle))
	b.WriteString(fmt.Sprintf("| **Compare** | `%s` |\n", result.CompareBundle))
	b.WriteString(fmt.Sprintf("| **Role** | %s |\n\n", result.Role))

	// Run metadata
	if result.BaselineRunMeta != nil && result.CompareRunMeta != nil {
		b.WriteString("## Run Information\n\n")
		b.WriteString("| Metric | Baseline | Compare |\n")
		b.WriteString("|--------|----------|--------|\n")
		b.WriteString(fmt.Sprintf("| Run ID | %s | %s |\n",
			result.BaselineRunMeta.RunID, result.CompareRunMeta.RunID))
		b.WriteString(fmt.Sprintf("| Status | %s | %s |\n",
			result.BaselineRunMeta.Status, result.CompareRunMeta.Status))
		b.WriteString(fmt.Sprintf("| Time | %s | %s |\n\n",
			result.BaselineRunMeta.StartedAt.Format("2006-01-02 15:04:05"),
			result.CompareRunMeta.StartedAt.Format("2006-01-02 15:04:05")))
	}

	// Summary
	b.WriteString("## Summary\n\n")
	diffStatus := "No significant differences"
	if result.Summary.HasSignificantDiff {
		diffStatus = "**Significant differences found**"
	}
	b.WriteString(fmt.Sprintf("**Diff Score:** %d/100 - %s\n\n", result.Summary.DiffScore, diffStatus))

	b.WriteString("| Metric | Value |\n")
	b.WriteString("|--------|-------|\n")
	b.WriteString(fmt.Sprintf("| Services Added | %d |\n", result.Summary.ServicesAdded))
	b.WriteString(fmt.Sprintf("| Services Removed | %d |\n", result.Summary.ServicesRemoved))
	b.WriteString(fmt.Sprintf("| Services Common | %d |\n", result.Summary.ServicesCommon))
	b.WriteString(fmt.Sprintf("| Classes Added | %d |\n", result.Summary.ClassesAdded))
	b.WriteString(fmt.Sprintf("| Classes Removed | %d |\n", result.Summary.ClassesRemoved))
	b.WriteString(fmt.Sprintf("| Packet Count Delta | %+d |\n", result.Summary.PacketCountDelta))
	b.WriteString(fmt.Sprintf("| CIP Message Delta | %+d |\n", result.Summary.CIPCountDelta))
	if result.Summary.LatencyDeltaMs != 0 {
		b.WriteString(fmt.Sprintf("| P95 Latency Delta | %+.3f ms |\n", result.Summary.LatencyDeltaMs))
	}
	if result.Summary.JitterDeltaMs != 0 {
		b.WriteString(fmt.Sprintf("| Jitter Delta | %+.3f ms |\n", result.Summary.JitterDeltaMs))
	}
	b.WriteString("\n")

	// Packet counts
	b.WriteString("## Packet Counts\n\n")
	b.WriteString("| Metric | Baseline | Compare | Delta |\n")
	b.WriteString("|--------|----------|---------|-------|\n")
	b.WriteString(fmt.Sprintf("| Total Packets | %d | %d | %+d |\n",
		result.PcapDiff.BaselinePacketCount, result.PcapDiff.ComparePacketCount,
		result.PcapDiff.ComparePacketCount-result.PcapDiff.BaselinePacketCount))
	b.WriteString(fmt.Sprintf("| CIP Messages | %d | %d | %+d |\n\n",
		result.PcapDiff.BaselineCIPCount, result.PcapDiff.CompareCIPCount,
		result.PcapDiff.CompareCIPCount-result.PcapDiff.BaselineCIPCount))

	// Service differences
	b.WriteString("## Service Code Differences\n\n")

	if len(result.PcapDiff.AddedServices) > 0 {
		b.WriteString("### Added Services\n\n")
		b.WriteString("| Service | Name | Class | Count |\n")
		b.WriteString("|---------|------|-------|-------|\n")
		for _, s := range result.PcapDiff.AddedServices {
			b.WriteString(fmt.Sprintf("| 0x%02X | %s | 0x%04X | %d |\n",
				s.ServiceCode, s.ServiceName, s.Class, s.Count))
		}
		b.WriteString("\n")
	}

	if len(result.PcapDiff.RemovedServices) > 0 {
		b.WriteString("### Removed Services\n\n")
		b.WriteString("| Service | Name | Class | Count |\n")
		b.WriteString("|---------|------|-------|-------|\n")
		for _, s := range result.PcapDiff.RemovedServices {
			b.WriteString(fmt.Sprintf("| 0x%02X | %s | 0x%04X | %d |\n",
				s.ServiceCode, s.ServiceName, s.Class, s.Count))
		}
		b.WriteString("\n")
	}

	if len(result.PcapDiff.AddedServices) == 0 && len(result.PcapDiff.RemovedServices) == 0 {
		b.WriteString("No service differences found.\n\n")
	}

	// Timing analysis
	if result.PcapDiff.BaselineTiming != nil && result.PcapDiff.CompareTiming != nil {
		b.WriteString("## Latency Analysis\n\n")
		b.WriteString("| Metric | Baseline | Compare | Delta |\n")
		b.WriteString("|--------|----------|---------|-------|\n")
		b.WriteString(fmt.Sprintf("| Samples | %d | %d | - |\n",
			result.PcapDiff.BaselineTiming.PacketCount, result.PcapDiff.CompareTiming.PacketCount))
		b.WriteString(fmt.Sprintf("| Min (ms) | %.3f | %.3f | %+.3f |\n",
			result.PcapDiff.BaselineTiming.MinLatencyMs, result.PcapDiff.CompareTiming.MinLatencyMs,
			result.PcapDiff.CompareTiming.MinLatencyMs-result.PcapDiff.BaselineTiming.MinLatencyMs))
		b.WriteString(fmt.Sprintf("| Avg (ms) | %.3f | %.3f | %+.3f |\n",
			result.PcapDiff.BaselineTiming.AvgLatencyMs, result.PcapDiff.CompareTiming.AvgLatencyMs,
			result.PcapDiff.CompareTiming.AvgLatencyMs-result.PcapDiff.BaselineTiming.AvgLatencyMs))
		b.WriteString(fmt.Sprintf("| P50 (ms) | %.3f | %.3f | %+.3f |\n",
			result.PcapDiff.BaselineTiming.P50LatencyMs, result.PcapDiff.CompareTiming.P50LatencyMs,
			result.PcapDiff.CompareTiming.P50LatencyMs-result.PcapDiff.BaselineTiming.P50LatencyMs))
		b.WriteString(fmt.Sprintf("| P95 (ms) | %.3f | %.3f | %+.3f |\n",
			result.PcapDiff.BaselineTiming.P95LatencyMs, result.PcapDiff.CompareTiming.P95LatencyMs,
			result.PcapDiff.CompareTiming.P95LatencyMs-result.PcapDiff.BaselineTiming.P95LatencyMs))
		b.WriteString(fmt.Sprintf("| P99 (ms) | %.3f | %.3f | %+.3f |\n",
			result.PcapDiff.BaselineTiming.P99LatencyMs, result.PcapDiff.CompareTiming.P99LatencyMs,
			result.PcapDiff.CompareTiming.P99LatencyMs-result.PcapDiff.BaselineTiming.P99LatencyMs))
		b.WriteString("\n")
	}

	// RPI analysis
	if result.PcapDiff.BaselineRPI != nil && result.PcapDiff.CompareRPI != nil &&
		(len(result.PcapDiff.BaselineRPI.Intervals) > 0 || len(result.PcapDiff.CompareRPI.Intervals) > 0) {
		b.WriteString("## RPI/Jitter Analysis\n\n")
		b.WriteString(fmt.Sprintf("**Expected RPI:** %.1f ms\n\n", result.PcapDiff.BaselineRPI.ExpectedRPIMs))
		b.WriteString("| Metric | Baseline | Compare | Delta |\n")
		b.WriteString("|--------|----------|---------|-------|\n")
		b.WriteString(fmt.Sprintf("| I/O Packets | %d | %d | - |\n",
			result.PcapDiff.BaselineRPI.PacketCount, result.PcapDiff.CompareRPI.PacketCount))
		b.WriteString(fmt.Sprintf("| Avg Interval (ms) | %.3f | %.3f | %+.3f |\n",
			result.PcapDiff.BaselineRPI.AvgIntervalMs, result.PcapDiff.CompareRPI.AvgIntervalMs,
			result.PcapDiff.CompareRPI.AvgIntervalMs-result.PcapDiff.BaselineRPI.AvgIntervalMs))
		b.WriteString(fmt.Sprintf("| Jitter (ms) | %.3f | %.3f | %+.3f |\n",
			result.PcapDiff.BaselineRPI.JitterMs, result.PcapDiff.CompareRPI.JitterMs,
			result.PcapDiff.CompareRPI.JitterMs-result.PcapDiff.BaselineRPI.JitterMs))
		b.WriteString(fmt.Sprintf("| Std Dev (ms) | %.3f | %.3f | %+.3f |\n",
			result.PcapDiff.BaselineRPI.StdDevMs, result.PcapDiff.CompareRPI.StdDevMs,
			result.PcapDiff.CompareRPI.StdDevMs-result.PcapDiff.BaselineRPI.StdDevMs))
		b.WriteString(fmt.Sprintf("| RPI Violations | %d | %d | - |\n",
			result.PcapDiff.BaselineRPI.RPIViolations, result.PcapDiff.CompareRPI.RPIViolations))
		b.WriteString("\n")
	}

	return b.String()
}
