// Package controller analysis provides PCAP analysis and diff for orchestrated runs.
package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tturner/cipdip/internal/pcap"
)

// phaseAnalyze runs post-run PCAP analysis.
func (c *Controller) phaseAnalyze(ctx context.Context, result *Result) error {
	c.reportPhase(PhaseAnalyze, "Running PCAP analysis")

	// Find PCAPs in server and client role directories
	var serverPcaps, clientPcaps []string
	var err error

	if c.manifest.Roles.Server != nil {
		serverPcaps, err = c.bundle.ListRolePcaps("server")
		if err != nil {
			c.reportPhase(PhaseAnalyze, fmt.Sprintf("Warning: could not list server pcaps: %v", err))
		}
	}

	if c.manifest.Roles.Client != nil {
		clientPcaps, err = c.bundle.ListRolePcaps("client")
		if err != nil {
			c.reportPhase(PhaseAnalyze, fmt.Sprintf("Warning: could not list client pcaps: %v", err))
		}
	}

	// Generate analysis report for each PCAP
	var reports []string

	for _, pcapFile := range serverPcaps {
		pcapPath := filepath.Join(c.bundle.RoleDir("server"), pcapFile)
		report, err := c.analyzePCAP(ctx, "server", pcapPath)
		if err != nil {
			c.reportPhase(PhaseAnalyze, fmt.Sprintf("Warning: server PCAP analysis failed: %v", err))
			continue
		}
		reports = append(reports, report)
	}

	for _, pcapFile := range clientPcaps {
		pcapPath := filepath.Join(c.bundle.RoleDir("client"), pcapFile)
		report, err := c.analyzePCAP(ctx, "client", pcapPath)
		if err != nil {
			c.reportPhase(PhaseAnalyze, fmt.Sprintf("Warning: client PCAP analysis failed: %v", err))
			continue
		}
		reports = append(reports, report)
	}

	// Check if this was a DPI scenario - generate DPI-specific analysis
	if c.isDPIScenario() {
		dpiReport := c.generateDPIAnalysis(ctx, serverPcaps, clientPcaps)
		reports = append(reports, dpiReport)

		// Write DPI analysis report
		if err := c.bundle.WriteAnalysis("dpi_analysis.txt", []byte(dpiReport)); err != nil {
			c.reportPhase(PhaseAnalyze, fmt.Sprintf("Warning: could not write DPI analysis: %v", err))
		} else {
			c.reportPhase(PhaseAnalyze, "DPI analysis report written to analysis/dpi_analysis.txt")
		}
	}

	// Write combined analysis report
	if len(reports) > 0 {
		combined := strings.Join(reports, "\n\n" + strings.Repeat("=", 80) + "\n\n")
		if err := c.bundle.WriteAnalysis("pcap_analysis.txt", []byte(combined)); err != nil {
			return fmt.Errorf("write analysis report: %w", err)
		}
		c.reportPhase(PhaseAnalyze, "Analysis report written to analysis/pcap_analysis.txt")
	}

	return nil
}

// analyzePCAP generates an analysis report for a single PCAP file.
func (c *Controller) analyzePCAP(ctx context.Context, role, pcapPath string) (string, error) {
	// Check file exists
	info, err := os.Stat(pcapPath)
	if err != nil {
		return "", fmt.Errorf("stat pcap: %w", err)
	}

	var b strings.Builder

	b.WriteString(fmt.Sprintf("PCAP Analysis: %s (%s)\n", filepath.Base(pcapPath), role))
	b.WriteString(strings.Repeat("=", 60) + "\n\n")
	b.WriteString(fmt.Sprintf("File Size: %d bytes\n", info.Size()))
	b.WriteString(fmt.Sprintf("Analysis Time: %s\n\n", time.Now().Format(time.RFC3339)))

	// Get PCAP summary using existing functionality
	summary, err := pcap.SummarizeENIPFromPCAP(pcapPath)
	if err != nil {
		b.WriteString(fmt.Sprintf("Error analyzing PCAP: %v\n", err))
		return b.String(), nil
	}

	// Format the summary
	b.WriteString("Packet Statistics:\n")
	b.WriteString(strings.Repeat("-", 40) + "\n")
	b.WriteString(fmt.Sprintf("  Total Packets:    %d\n", summary.TotalPackets))
	b.WriteString(fmt.Sprintf("  ENIP Packets:     %d\n", summary.ENIPPackets))
	b.WriteString(fmt.Sprintf("  Requests:         %d\n", summary.Requests))
	b.WriteString(fmt.Sprintf("  Responses:        %d\n", summary.Responses))
	b.WriteString(fmt.Sprintf("  CIP Requests:     %d\n", summary.CIPRequests))
	b.WriteString(fmt.Sprintf("  CIP Responses:    %d\n", summary.CIPResponses))

	if summary.VendorID > 0 {
		b.WriteString(fmt.Sprintf("\nDevice Identity:\n"))
		b.WriteString(strings.Repeat("-", 40) + "\n")
		b.WriteString(fmt.Sprintf("  Vendor ID:    0x%04X\n", summary.VendorID))
		if summary.ProductName != "" {
			b.WriteString(fmt.Sprintf("  Product Name: %s\n", summary.ProductName))
		}
	}

	if len(summary.Commands) > 0 {
		b.WriteString(fmt.Sprintf("\nENIP Commands:\n"))
		b.WriteString(strings.Repeat("-", 40) + "\n")
		for cmd, count := range summary.Commands {
			b.WriteString(fmt.Sprintf("  %s: %d\n", cmd, count))
		}
	}

	if len(summary.CIPServices) > 0 {
		b.WriteString(fmt.Sprintf("\nCIP Services:\n"))
		b.WriteString(strings.Repeat("-", 40) + "\n")
		for svc, count := range summary.CIPServices {
			b.WriteString(fmt.Sprintf("  %s: %d\n", svc, count))
		}
	}

	return b.String(), nil
}

// isDPIScenario checks if the current run is a DPI-related scenario.
func (c *Controller) isDPIScenario() bool {
	if c.manifest.Roles.Client == nil {
		return false
	}
	scenario := c.manifest.Roles.Client.Scenario
	return strings.HasPrefix(scenario, "dpi") || scenario == "firewall_hirschmann" ||
		scenario == "firewall_moxa" || scenario == "firewall_dynics" || scenario == "firewall_pack"
}

// generateDPIAnalysis creates a DPI-specific analysis report.
func (c *Controller) generateDPIAnalysis(ctx context.Context, serverPcaps, clientPcaps []string) string {
	var b strings.Builder

	b.WriteString("DPI Analysis Report\n")
	b.WriteString(strings.Repeat("=", 60) + "\n\n")
	b.WriteString(fmt.Sprintf("Scenario: %s\n", c.manifest.Roles.Client.Scenario))
	b.WriteString(fmt.Sprintf("Analysis Time: %s\n\n", time.Now().Format(time.RFC3339)))

	// Compare client-sent vs server-received if both have PCAPs
	if len(clientPcaps) > 0 && len(serverPcaps) > 0 {
		clientPcapPath := filepath.Join(c.bundle.RoleDir("client"), clientPcaps[0])
		serverPcapPath := filepath.Join(c.bundle.RoleDir("server"), serverPcaps[0])

		b.WriteString("Traffic Comparison (Client → Server):\n")
		b.WriteString(strings.Repeat("-", 60) + "\n")

		// Use diff to compare
		opts := pcap.DefaultDiffOptions()
		result, err := pcap.DiffPCAPs(clientPcapPath, serverPcapPath, opts)
		if err != nil {
			b.WriteString(fmt.Sprintf("Error comparing PCAPs: %v\n", err))
		} else {
			// Analyze for DPI indicators
			b.WriteString(c.interpretDPIDiff(result))
		}
	}

	// Summary and recommendations
	b.WriteString("\nDPI Assessment:\n")
	b.WriteString(strings.Repeat("-", 60) + "\n")
	b.WriteString(c.generateDPIAssessment())

	return b.String()
}

// interpretDPIDiff interprets diff results for DPI behavior.
func (c *Controller) interpretDPIDiff(result *pcap.DiffResult) string {
	var b strings.Builder

	// Check packet counts
	clientCount := result.BaselinePacketCount
	serverCount := result.ComparePacketCount
	dropRate := 0.0
	if clientCount > 0 {
		dropRate = float64(clientCount-serverCount) / float64(clientCount) * 100
	}

	b.WriteString(fmt.Sprintf("  Client sent:     %d CIP messages\n", result.BaselineCIPCount))
	b.WriteString(fmt.Sprintf("  Server received: %d CIP messages\n", result.CompareCIPCount))

	if dropRate > 0 {
		b.WriteString(fmt.Sprintf("  Apparent drop rate: %.1f%%\n", dropRate))
	}

	// Check for missing services (potential blocking)
	if len(result.RemovedServices) > 0 {
		b.WriteString("\n  POTENTIAL DPI BLOCKING DETECTED:\n")
		b.WriteString("  Services sent by client but not seen at server:\n")
		for _, svc := range result.RemovedServices {
			b.WriteString(fmt.Sprintf("    - 0x%02X %s (Class 0x%04X) - %d requests dropped\n",
				svc.ServiceCode, svc.ServiceName, svc.Class, svc.Count))
		}
	}

	// Check latency for DPI inspection overhead
	if result.BaselineTiming != nil && result.CompareTiming != nil {
		if result.CompareTiming.AvgLatencyMs > result.BaselineTiming.AvgLatencyMs*1.5 {
			b.WriteString(fmt.Sprintf("\n  LATENCY ANOMALY:\n"))
			b.WriteString(fmt.Sprintf("    Client-side avg: %.2fms\n", result.BaselineTiming.AvgLatencyMs))
			b.WriteString(fmt.Sprintf("    Server-side avg: %.2fms\n", result.CompareTiming.AvgLatencyMs))
			b.WriteString("    This may indicate DPI inspection overhead\n")
		}
	}

	return b.String()
}

// generateDPIAssessment generates an overall DPI assessment.
func (c *Controller) generateDPIAssessment() string {
	var b strings.Builder

	b.WriteString("Check the following indicators for DPI issues:\n\n")

	b.WriteString("1. PACKET DROPS:\n")
	b.WriteString("   - Compare client sent vs server received packet counts\n")
	b.WriteString("   - Significant drops indicate active blocking\n\n")

	b.WriteString("2. TCP RESETS:\n")
	b.WriteString("   - Unexpected RST packets indicate DPI termination\n")
	b.WriteString("   - Check for resets after ForwardOpen or specific services\n\n")

	b.WriteString("3. SERVICE BLOCKING:\n")
	b.WriteString("   - Services present in client PCAP but missing in server PCAP\n")
	b.WriteString("   - May indicate service-based filtering\n\n")

	b.WriteString("4. LATENCY ANOMALIES:\n")
	b.WriteString("   - Increased latency suggests inline inspection\n")
	b.WriteString("   - Variable latency may indicate selective inspection\n\n")

	b.WriteString("5. CONNECTION STATE:\n")
	b.WriteString("   - ForwardOpen/Close failures may indicate stateful DPI issues\n")
	b.WriteString("   - Rapid connection churn often triggers DPI bugs\n")

	return b.String()
}

// phaseDiff runs diff against a baseline bundle.
func (c *Controller) phaseDiff(ctx context.Context, result *Result) error {
	c.reportPhase(PhaseDiff, "Running diff against baseline")

	baselinePath := c.manifest.PostRun.DiffBaseline
	if baselinePath == "" {
		return fmt.Errorf("no baseline specified")
	}

	// Check baseline exists
	if _, err := os.Stat(baselinePath); err != nil {
		return fmt.Errorf("baseline not found: %w", err)
	}

	c.reportPhase(PhaseDiff, fmt.Sprintf("Baseline: %s", baselinePath))

	// Find matching PCAPs to diff
	var diffReports []string

	// Try to diff client PCAPs
	baselineClientPcaps := findPcapsInRole(baselinePath, "client")
	currentClientPcaps, _ := c.bundle.ListRolePcaps("client")

	if len(baselineClientPcaps) > 0 && len(currentClientPcaps) > 0 {
		baselinePcap := filepath.Join(baselinePath, "roles", "client", baselineClientPcaps[0])
		currentPcap := filepath.Join(c.bundle.RoleDir("client"), currentClientPcaps[0])

		report, err := c.diffPcaps(baselinePcap, currentPcap, "client")
		if err != nil {
			c.reportPhase(PhaseDiff, fmt.Sprintf("Warning: client PCAP diff failed: %v", err))
		} else {
			diffReports = append(diffReports, report)
		}
	}

	// Try to diff server PCAPs
	baselineServerPcaps := findPcapsInRole(baselinePath, "server")
	currentServerPcaps, _ := c.bundle.ListRolePcaps("server")

	if len(baselineServerPcaps) > 0 && len(currentServerPcaps) > 0 {
		baselinePcap := filepath.Join(baselinePath, "roles", "server", baselineServerPcaps[0])
		currentPcap := filepath.Join(c.bundle.RoleDir("server"), currentServerPcaps[0])

		report, err := c.diffPcaps(baselinePcap, currentPcap, "server")
		if err != nil {
			c.reportPhase(PhaseDiff, fmt.Sprintf("Warning: server PCAP diff failed: %v", err))
		} else {
			diffReports = append(diffReports, report)
		}
	}

	// Write diff report
	if len(diffReports) > 0 {
		combined := strings.Join(diffReports, "\n\n" + strings.Repeat("=", 80) + "\n\n")
		if err := c.bundle.WriteAnalysis("pcap_diff.txt", []byte(combined)); err != nil {
			return fmt.Errorf("write diff report: %w", err)
		}
		c.reportPhase(PhaseDiff, "Diff report written to analysis/pcap_diff.txt")
	} else {
		c.reportPhase(PhaseDiff, "No PCAPs available for diff")
	}

	return nil
}

// diffPcaps generates a diff report between two PCAP files.
func (c *Controller) diffPcaps(baselinePath, comparePath, role string) (string, error) {
	opts := pcap.DefaultDiffOptions()
	result, err := pcap.DiffPCAPs(baselinePath, comparePath, opts)
	if err != nil {
		return "", err
	}

	// Use the existing FormatDiffReport function
	report := pcap.FormatDiffReport(result)

	// Add header with role info
	var b strings.Builder
	b.WriteString(fmt.Sprintf("PCAP Diff Report (%s role)\n", role))
	b.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339)))
	b.WriteString(report)

	return b.String(), nil
}

// findPcapsInRole finds PCAP files in a bundle's role directory.
func findPcapsInRole(bundlePath, role string) []string {
	roleDir := filepath.Join(bundlePath, "roles", role)
	entries, err := os.ReadDir(roleDir)
	if err != nil {
		return nil
	}

	var pcaps []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".pcap") || strings.HasSuffix(name, ".pcapng") {
			pcaps = append(pcaps, name)
		}
	}
	return pcaps
}
