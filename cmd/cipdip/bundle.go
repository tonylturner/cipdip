package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/manifest"
	"github.com/tonylturner/cipdip/internal/orch/bundle"
)

func newBundleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Manage run bundles",
		Long: `Commands for managing run bundles from orchestrated runs.

Run bundles are self-describing directories containing all artifacts from
a distributed test run, including manifests, pcaps, logs, and metadata.`,
	}

	cmd.AddCommand(newBundleVerifyCmd())
	cmd.AddCommand(newBundleInfoCmd())
	cmd.AddCommand(newBundleReportCmd())
	cmd.AddCommand(newBundleLastCmd())
	cmd.AddCommand(newBundleOpenCmd())

	return cmd
}

func newBundleVerifyCmd() *cobra.Command {
	var flags struct {
		skipHashes     bool
		skipPcaps      bool
		strictSchema   bool
		jsonOutput     bool
	}

	cmd := &cobra.Command{
		Use:   "verify <bundle-path>",
		Short: "Verify a run bundle for completeness and integrity",
		Long: `Verify that a run bundle is complete and all file hashes match.

Checks performed:
- Required files exist (manifest.yaml, run_meta.json, versions.json)
- All file hashes match hashes.txt
- PCAP files referenced in role metadata exist and are non-empty
- JSON metadata files are valid

Examples:
  cipdip bundle verify runs/2026-01-13_14-30-00
  cipdip bundle verify --skip-hashes runs/my-run
  cipdip bundle verify --json runs/my-run`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			bundlePath := args[0]

			b, err := bundle.Open(bundlePath)
			if err != nil {
				return fmt.Errorf("open bundle: %w", err)
			}

			opts := bundle.DefaultVerifyOptions()
			opts.CheckHashes = !flags.skipHashes
			opts.CheckPcaps = !flags.skipPcaps
			opts.StrictSchema = flags.strictSchema

			result, err := b.Verify(opts)
			if err != nil {
				return fmt.Errorf("verify bundle: %w", err)
			}

			if flags.jsonOutput {
				data, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return fmt.Errorf("marshal result: %w", err)
				}
				fmt.Fprintln(os.Stdout, string(data))
			} else {
				fmt.Fprint(os.Stdout, result.FormatResult())
			}

			if !result.Valid {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&flags.skipHashes, "skip-hashes", false, "Skip hash verification")
	cmd.Flags().BoolVar(&flags.skipPcaps, "skip-pcaps", false, "Skip PCAP file checks")
	cmd.Flags().BoolVar(&flags.strictSchema, "strict", true, "Require all expected files (manifest_resolved.yaml)")
	cmd.Flags().BoolVar(&flags.jsonOutput, "json", false, "Output results as JSON")

	return cmd
}

func newBundleInfoCmd() *cobra.Command {
	var flags struct {
		jsonOutput bool
	}

	cmd := &cobra.Command{
		Use:   "info <bundle-path>",
		Short: "Display information about a run bundle",
		Long: `Display summary information about a run bundle.

Shows run metadata, tool versions, and role information.

Examples:
  cipdip bundle info runs/2026-01-13_14-30-00
  cipdip bundle info --json runs/my-run`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			bundlePath := args[0]

			b, err := bundle.Open(bundlePath)
			if err != nil {
				return fmt.Errorf("open bundle: %w", err)
			}

			// Read metadata
			runMeta, err := b.ReadRunMeta()
			if err != nil {
				return fmt.Errorf("read run metadata: %w", err)
			}

			versions, err := b.ReadVersions()
			if err != nil {
				return fmt.Errorf("read versions: %w", err)
			}

			if flags.jsonOutput {
				info := map[string]interface{}{
					"path":     b.Path,
					"run_id":   b.RunID,
					"run_meta": runMeta,
					"versions": versions,
				}

				// Try to read role meta
				roles := make(map[string]interface{})
				if serverMeta, err := b.ReadRoleMeta("server"); err == nil {
					roles["server"] = serverMeta
				}
				if clientMeta, err := b.ReadRoleMeta("client"); err == nil {
					roles["client"] = clientMeta
				}
				if len(roles) > 0 {
					info["roles"] = roles
				}

				data, err := json.MarshalIndent(info, "", "  ")
				if err != nil {
					return fmt.Errorf("marshal info: %w", err)
				}
				fmt.Fprintln(os.Stdout, string(data))
			} else {
				fmt.Fprintf(os.Stdout, "Bundle: %s\n", b.Path)
				fmt.Fprintf(os.Stdout, "Run ID: %s\n", b.RunID)
				fmt.Fprintln(os.Stdout, "")
				fmt.Fprintln(os.Stdout, "Run Metadata:")
				fmt.Fprintf(os.Stdout, "  Status: %s\n", runMeta.Status)
				fmt.Fprintf(os.Stdout, "  Started: %s\n", runMeta.StartedAt.Format("2006-01-02 15:04:05"))
				fmt.Fprintf(os.Stdout, "  Finished: %s\n", runMeta.FinishedAt.Format("2006-01-02 15:04:05"))
				fmt.Fprintf(os.Stdout, "  Duration: %.1f seconds\n", runMeta.DurationSeconds)
				if runMeta.Error != "" {
					fmt.Fprintf(os.Stdout, "  Error: %s\n", runMeta.Error)
				}
				if len(runMeta.PhasesCompleted) > 0 {
					fmt.Fprintf(os.Stdout, "  Phases: %v\n", runMeta.PhasesCompleted)
				}
				fmt.Fprintln(os.Stdout, "")
				fmt.Fprintln(os.Stdout, "Versions:")
				fmt.Fprintf(os.Stdout, "  cipdip: %s\n", versions.CipdipVersion)
				if versions.GitCommit != "" {
					fmt.Fprintf(os.Stdout, "  git commit: %s\n", versions.GitCommit)
				}
				fmt.Fprintf(os.Stdout, "  controller: %s/%s\n", versions.ControllerOS, versions.ControllerArch)

				// Show roles
				if serverMeta, err := b.ReadRoleMeta("server"); err == nil {
					fmt.Fprintln(os.Stdout, "")
					fmt.Fprintln(os.Stdout, "Server Role:")
					fmt.Fprintf(os.Stdout, "  Agent: %s\n", serverMeta.AgentID)
					fmt.Fprintf(os.Stdout, "  Exit Code: %d\n", serverMeta.ExitCode)
					if len(serverMeta.PcapFiles) > 0 {
						fmt.Fprintf(os.Stdout, "  PCAPs: %v\n", serverMeta.PcapFiles)
					}
				}

				if clientMeta, err := b.ReadRoleMeta("client"); err == nil {
					fmt.Fprintln(os.Stdout, "")
					fmt.Fprintln(os.Stdout, "Client Role:")
					fmt.Fprintf(os.Stdout, "  Agent: %s\n", clientMeta.AgentID)
					fmt.Fprintf(os.Stdout, "  Target: %s\n", clientMeta.TargetIP)
					fmt.Fprintf(os.Stdout, "  Exit Code: %d\n", clientMeta.ExitCode)
					if len(clientMeta.PcapFiles) > 0 {
						fmt.Fprintf(os.Stdout, "  PCAPs: %v\n", clientMeta.PcapFiles)
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&flags.jsonOutput, "json", false, "Output as JSON")

	return cmd
}

// Report styling colors (Tokyo Night theme)
var (
	colorSuccess = lipgloss.Color("#9ece6a")
	colorError   = lipgloss.Color("#f7768e")
	colorWarning = lipgloss.Color("#e0af68")
	colorInfo    = lipgloss.Color("#7aa2f7")
	colorCyan    = lipgloss.Color("#7dcfff")
	colorMagenta = lipgloss.Color("#bb9af7")
	colorDim     = lipgloss.Color("#565f89")
	colorText    = lipgloss.Color("#c0caf5")
	colorBorder  = lipgloss.Color("#3b4261")
)

func newBundleReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report <bundle-path>",
		Short: "Display a styled run report",
		Long: `Display a styled terminal report for a completed run.

Shows run summary, traffic statistics, and DPI analysis results
in a formatted display suitable for screenshots.

Examples:
  cipdip bundle report runs/auto
  cipdip bundle report workspaces/workspace/runs/2026-01-13_14-30-00`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			bundlePath := args[0]
			return printStyledReport(bundlePath)
		},
	}

	return cmd
}

func printStyledReport(bundlePath string) error {
	b, err := bundle.Open(bundlePath)
	if err != nil {
		return fmt.Errorf("open bundle: %w", err)
	}

	runMeta, err := b.ReadRunMeta()
	if err != nil {
		return fmt.Errorf("read run metadata: %w", err)
	}

	// Styles
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(colorInfo)
	labelStyle := lipgloss.NewStyle().Foreground(colorDim)
	valueStyle := lipgloss.NewStyle().Foreground(colorText)
	successStyle := lipgloss.NewStyle().Bold(true).Foreground(colorSuccess)
	errorStyle := lipgloss.NewStyle().Bold(true).Foreground(colorError)
	borderStyle := lipgloss.NewStyle().Foreground(colorBorder)

	var out strings.Builder

	// Title bar
	statusIcon := "✓"
	statusColor := colorSuccess
	if runMeta.Status != "success" {
		statusIcon = "✗"
		statusColor = colorError
	}
	titleText := fmt.Sprintf(" CIPDIP RUN REPORT %s ", statusIcon)
	title := lipgloss.NewStyle().Bold(true).Foreground(statusColor).Render(titleText)
	out.WriteString("\n" + borderStyle.Render("╭─────────────────────────────────────────────────────────────────────╮") + "\n")
	out.WriteString(borderStyle.Render("│") + "  " + title + strings.Repeat(" ", 45-len(titleText)) + borderStyle.Render("│") + "\n")
	out.WriteString(borderStyle.Render("╰─────────────────────────────────────────────────────────────────────╯") + "\n\n")

	// Run Summary section
	out.WriteString(headerStyle.Render("  ▸ Run Summary") + "\n")
	out.WriteString(borderStyle.Render("  ─────────────────────────────────────────────────────────────────") + "\n")
	out.WriteString(labelStyle.Render("    Run ID:      ") + valueStyle.Render(b.RunID) + "\n")
	out.WriteString(labelStyle.Render("    Started:     ") + valueStyle.Render(runMeta.StartedAt.Format("2006-01-02 15:04:05")) + "\n")
	out.WriteString(labelStyle.Render("    Duration:    ") + lipgloss.NewStyle().Foreground(colorCyan).Render(fmt.Sprintf("%.1fs", runMeta.DurationSeconds)) + "\n")

	if runMeta.Status == "success" {
		out.WriteString(labelStyle.Render("    Status:      ") + successStyle.Render("SUCCESS") + "\n")
	} else {
		out.WriteString(labelStyle.Render("    Status:      ") + errorStyle.Render(strings.ToUpper(runMeta.Status)) + "\n")
		if runMeta.Error != "" {
			out.WriteString(labelStyle.Render("    Error:       ") + errorStyle.Render(runMeta.Error) + "\n")
		}
	}
	out.WriteString("\n")

	// Read manifest for scenario info
	manifestData, _ := manifest.Load(filepath.Join(bundlePath, "manifest.yaml"))
	if manifestData != nil {
		out.WriteString(headerStyle.Render("  ▸ Test Configuration") + "\n")
		out.WriteString(borderStyle.Render("  ─────────────────────────────────────────────────────────────────") + "\n")
		if manifestData.Roles.Client.Scenario != "" {
			out.WriteString(labelStyle.Render("    Scenario:    ") + lipgloss.NewStyle().Bold(true).Foreground(colorMagenta).Render(manifestData.Roles.Client.Scenario) + "\n")
		}
		if manifestData.Profile.Path != "" {
			out.WriteString(labelStyle.Render("    Profile:     ") + valueStyle.Render(filepath.Base(manifestData.Profile.Path)) + "\n")
		}
		out.WriteString(labelStyle.Render("    Target:      ") + valueStyle.Render(fmt.Sprintf("%s:%d", manifestData.Network.DataPlane.TargetIP, manifestData.Network.DataPlane.TargetPort)) + "\n")
		out.WriteString(labelStyle.Render("    Duration:    ") + valueStyle.Render(fmt.Sprintf("%ds", manifestData.Roles.Client.DurationSeconds)) + "\n")
		out.WriteString("\n")
	}

	// Phases
	if len(runMeta.PhasesCompleted) > 0 {
		out.WriteString(headerStyle.Render("  ▸ Execution Phases") + "\n")
		out.WriteString(borderStyle.Render("  ─────────────────────────────────────────────────────────────────") + "\n")
		out.WriteString("    ")
		for i, phase := range runMeta.PhasesCompleted {
			phaseStyle := lipgloss.NewStyle().Foreground(colorSuccess)
			out.WriteString(phaseStyle.Render("✓ " + phase))
			if i < len(runMeta.PhasesCompleted)-1 {
				out.WriteString(labelStyle.Render(" → "))
			}
		}
		out.WriteString("\n\n")
	}

	// Read and display analysis if available
	dpiPath := filepath.Join(bundlePath, "analysis", "dpi_analysis.txt")
	pcapPath := filepath.Join(bundlePath, "analysis", "pcap_analysis.txt")

	if data, err := os.ReadFile(pcapPath); err == nil {
		stats := parsePcapStats(string(data))
		if stats != nil {
			out.WriteString(headerStyle.Render("  ▸ Traffic Statistics") + "\n")
			out.WriteString(borderStyle.Render("  ─────────────────────────────────────────────────────────────────") + "\n")

			// Table header
			colWidth := 18
			out.WriteString(labelStyle.Render("    "))
			out.WriteString(lipgloss.NewStyle().Bold(true).Foreground(colorText).Width(colWidth).Render("Metric"))
			out.WriteString(lipgloss.NewStyle().Bold(true).Foreground(colorCyan).Width(colWidth).Align(lipgloss.Right).Render("Client"))
			out.WriteString(lipgloss.NewStyle().Bold(true).Foreground(colorMagenta).Width(colWidth).Align(lipgloss.Right).Render("Server"))
			out.WriteString("\n")
			out.WriteString(labelStyle.Render("    " + strings.Repeat("─", colWidth*3)) + "\n")

			// Stats rows
			printStatRow(&out, "Total Packets", stats.clientTotal, stats.serverTotal, colWidth)
			printStatRow(&out, "ENIP Packets", stats.clientENIP, stats.serverENIP, colWidth)
			printStatRow(&out, "CIP Requests", stats.clientCIP, stats.serverCIP, colWidth)
			out.WriteString("\n")

			// DPI assessment
			if stats.clientCIP > 0 && stats.serverCIP > 0 {
				dropRate := float64(stats.clientCIP-stats.serverCIP) / float64(stats.clientCIP) * 100
				out.WriteString(headerStyle.Render("  ▸ DPI Assessment") + "\n")
				out.WriteString(borderStyle.Render("  ─────────────────────────────────────────────────────────────────") + "\n")

				if stats.clientCIP == stats.serverCIP {
					out.WriteString("    " + successStyle.Render("✓ No packet drops detected") + "\n")
					out.WriteString(labelStyle.Render("      All ") + valueStyle.Render(fmt.Sprintf("%d", stats.clientCIP)) + labelStyle.Render(" CIP messages delivered successfully") + "\n")
				} else if dropRate < 1 {
					out.WriteString("    " + lipgloss.NewStyle().Foreground(colorWarning).Render("⚠ Minor packet loss detected") + "\n")
					out.WriteString(labelStyle.Render("      Drop rate: ") + lipgloss.NewStyle().Foreground(colorWarning).Render(fmt.Sprintf("%.2f%%", dropRate)) + "\n")
				} else {
					out.WriteString("    " + errorStyle.Render("✗ Significant packet loss detected") + "\n")
					out.WriteString(labelStyle.Render("      Drop rate: ") + errorStyle.Render(fmt.Sprintf("%.2f%%", dropRate)) + "\n")
				}
				out.WriteString("\n")
			}

			// CIP Services
			if len(stats.services) > 0 {
				out.WriteString(headerStyle.Render("  ▸ CIP Services Exercised") + "\n")
				out.WriteString(borderStyle.Render("  ─────────────────────────────────────────────────────────────────") + "\n")
				for _, svc := range stats.services {
					countStr := lipgloss.NewStyle().Foreground(colorCyan).Width(8).Align(lipgloss.Right).Render(fmt.Sprintf("%d", svc.count))
					out.WriteString("    " + countStr + "  " + valueStyle.Render(svc.name) + "\n")
				}
				out.WriteString("\n")
			}
		}
	} else if _, err := os.ReadFile(dpiPath); err == nil {
		// Fallback to showing raw dpi analysis exists
		out.WriteString(labelStyle.Render("    Analysis files available in: ") + valueStyle.Render(filepath.Join(bundlePath, "analysis")) + "\n\n")
	}

	// Bundle contents
	out.WriteString(headerStyle.Render("  ▸ Bundle Contents") + "\n")
	out.WriteString(borderStyle.Render("  ─────────────────────────────────────────────────────────────────") + "\n")
	out.WriteString(labelStyle.Render("    Path: ") + valueStyle.Render(bundlePath) + "\n")

	// List key files
	files := []string{"manifest.yaml", "run_meta.json", "profile.yaml"}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(bundlePath, f)); err == nil {
			out.WriteString(labelStyle.Render("      • ") + valueStyle.Render(f) + "\n")
		}
	}

	// List role artifacts
	for _, role := range []string{"client", "server"} {
		roleDir := filepath.Join(bundlePath, "roles", role)
		if entries, err := os.ReadDir(roleDir); err == nil && len(entries) > 0 {
			out.WriteString(labelStyle.Render("      • roles/"+role+"/") + "\n")
			for _, e := range entries {
				if !e.IsDir() {
					out.WriteString(labelStyle.Render("          ") + lipgloss.NewStyle().Foreground(colorDim).Render(e.Name()) + "\n")
				}
			}
		}
	}

	// Analysis files
	analysisDir := filepath.Join(bundlePath, "analysis")
	if entries, err := os.ReadDir(analysisDir); err == nil && len(entries) > 0 {
		out.WriteString(labelStyle.Render("      • analysis/") + "\n")
		for _, e := range entries {
			out.WriteString(labelStyle.Render("          ") + lipgloss.NewStyle().Foreground(colorDim).Render(e.Name()) + "\n")
		}
	}

	out.WriteString("\n")
	out.WriteString(borderStyle.Render("╰─────────────────────────────────────────────────────────────────────╯") + "\n")

	fmt.Print(out.String())
	return nil
}

type pcapStats struct {
	clientTotal, serverTotal int
	clientENIP, serverENIP   int
	clientCIP, serverCIP     int
	services                 []serviceCount
}

type serviceCount struct {
	name  string
	count int
}

func parsePcapStats(content string) *pcapStats {
	stats := &pcapStats{}
	lines := strings.Split(content, "\n")

	inServer := false
	inClient := false
	inServices := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "(server)") {
			inServer = true
			inClient = false
			inServices = false
		} else if strings.Contains(line, "(client)") {
			inClient = true
			inServer = false
			inServices = false
		} else if strings.Contains(line, "CIP Services:") {
			inServices = true
		} else if strings.HasPrefix(line, "ENIP Commands:") || strings.HasPrefix(line, "Packet Statistics:") {
			inServices = false
		}

		if strings.HasPrefix(line, "Total Packets:") {
			var val int
			fmt.Sscanf(line, "Total Packets: %d", &val)
			if inServer {
				stats.serverTotal = val
			} else if inClient {
				stats.clientTotal = val
			}
		} else if strings.HasPrefix(line, "ENIP Packets:") {
			var val int
			fmt.Sscanf(line, "ENIP Packets: %d", &val)
			if inServer {
				stats.serverENIP = val
			} else if inClient {
				stats.clientENIP = val
			}
		} else if strings.HasPrefix(line, "CIP Requests:") {
			var val int
			fmt.Sscanf(line, "CIP Requests: %d", &val)
			if inServer {
				stats.serverCIP = val
			} else if inClient {
				stats.clientCIP = val
			}
		} else if inServices && inClient && strings.Contains(line, ":") && !strings.Contains(line, "sent") && !strings.Contains(line, "received") {
			// Parse service line like "Get_Attribute_Single: 1080"
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				var count int
				fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &count)
				if count > 0 && name != "" && !strings.HasPrefix(name, "Client") && !strings.HasPrefix(name, "Server") {
					stats.services = append(stats.services, serviceCount{name: name, count: count})
				}
			}
		}
	}

	return stats
}

func printStatRow(out *strings.Builder, label string, client, server, width int) {
	labelStyle := lipgloss.NewStyle().Foreground(colorText).Width(width)
	clientStyle := lipgloss.NewStyle().Foreground(colorCyan).Width(width).Align(lipgloss.Right)
	serverStyle := lipgloss.NewStyle().Foreground(colorMagenta).Width(width).Align(lipgloss.Right)

	match := ""
	if client == server {
		match = lipgloss.NewStyle().Foreground(colorSuccess).Render(" ✓")
	} else {
		match = lipgloss.NewStyle().Foreground(colorError).Render(" ✗")
	}

	out.WriteString("    ")
	out.WriteString(labelStyle.Render(label))
	out.WriteString(clientStyle.Render(fmt.Sprintf("%d", client)))
	out.WriteString(serverStyle.Render(fmt.Sprintf("%d", server)))
	out.WriteString(match)
	out.WriteString("\n")
}

func newBundleLastCmd() *cobra.Command {
	var flags struct {
		open bool
	}

	cmd := &cobra.Command{
		Use:   "last",
		Short: "Show report for the most recent run",
		Long: `Display a styled report for the most recent run in the workspace.

Automatically finds and displays the latest completed run.

Examples:
  cipdip bundle last          # Show report
  cipdip bundle last --open   # Open bundle in Finder`,
		RunE: func(cmd *cobra.Command, args []string) error {
			bundlePath := findLatestRun()
			if bundlePath == "" {
				return fmt.Errorf("no runs found in workspaces/workspace/runs/")
			}

			if flags.open {
				return openBundleDir(bundlePath)
			}

			return printStyledReport(bundlePath)
		},
	}

	cmd.Flags().BoolVar(&flags.open, "open", false, "Open bundle directory in Finder instead of showing report")

	return cmd
}

func newBundleOpenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "open [bundle-path]",
		Short: "Open a bundle directory in Finder",
		Long: `Open a run bundle directory in Finder/Explorer.

If no path is provided, opens the most recent run.

Examples:
  cipdip bundle open                              # Open latest run
  cipdip bundle open workspaces/workspace/runs/auto`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var bundlePath string
			if len(args) > 0 {
				bundlePath = args[0]
			} else {
				bundlePath = findLatestRun()
				if bundlePath == "" {
					return fmt.Errorf("no runs found")
				}
			}

			return openBundleDir(bundlePath)
		},
	}

	return cmd
}

func findLatestRun() string {
	runsDir := "workspaces/workspace/runs"

	// Check for "auto" first (most common)
	autoPath := filepath.Join(runsDir, "auto")
	if _, err := os.Stat(filepath.Join(autoPath, "run_meta.json")); err == nil {
		return autoPath
	}

	// Find most recent by modification time
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		return ""
	}

	var latest string
	var latestTime int64

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		runPath := filepath.Join(runsDir, entry.Name())
		metaPath := filepath.Join(runPath, "run_meta.json")
		info, err := os.Stat(metaPath)
		if err != nil {
			continue
		}
		if info.ModTime().Unix() > latestTime {
			latestTime = info.ModTime().Unix()
			latest = runPath
		}
	}

	return latest
}

func openBundleDir(path string) error {
	fmt.Printf("Opening: %s\n", path)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "windows":
		cmd = exec.Command("explorer", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}

	return cmd.Run()
}
