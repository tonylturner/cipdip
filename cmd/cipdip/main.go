package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/tui"
)

var (
	version = "0.2.7"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	// Set version for internal packages that need it
	tui.SetVersion(version)

	rootCmd := &cobra.Command{
		Use:   "cipdip",
		Short: "CIP/EtherNet-IP Scanner for DPI Testing",
		Long: `CIPDIP is a command-line tool to generate repeatable, controllable
CIP/EtherNet-IP traffic for firewall DPI research testing.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Add subcommands
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newClientCmd())
	rootCmd.AddCommand(newServerCmd())
	rootCmd.AddCommand(newDiscoverCmd())
	rootCmd.AddCommand(newInstallCmd())
	rootCmd.AddCommand(newPcapCmd())
	rootCmd.AddCommand(newPcapSummaryCmd())
	rootCmd.AddCommand(newPcapReportCmd())
	rootCmd.AddCommand(newPcapCoverageCmd())
	rootCmd.AddCommand(newPcapClassifyCmd())
	rootCmd.AddCommand(newPcapDumpCmd())
	rootCmd.AddCommand(newPcapReplayCmd())
	rootCmd.AddCommand(newPcapRewriteCmd())
	rootCmd.AddCommand(newPcapValidateCmd())
	rootCmd.AddCommand(newPCAPDiffCmd())
	rootCmd.AddCommand(newPcapMultiCmd())
	rootCmd.AddCommand(newArpCmd())
	rootCmd.AddCommand(newTestCmd())
	rootCmd.AddCommand(newSelfTestCmd())
	rootCmd.AddCommand(newSingleCmd())
	rootCmd.AddCommand(newCatalogCmd())
	rootCmd.AddCommand(newEmitBytesCmd())
	rootCmd.AddCommand(newValidateBytesCmd())
	rootCmd.AddCommand(newBaselineCmd())
	rootCmd.AddCommand(newExtractReferenceCmd())
	rootCmd.AddCommand(newUICmd())
	rootCmd.AddCommand(newProfileCmd())
	rootCmd.AddCommand(newBundleCmd())
	rootCmd.AddCommand(newRunCmd())
	rootCmd.AddCommand(newAgentCmd())
	rootCmd.AddCommand(newDiffRunCmd())
	rootCmd.AddCommand(newMetricsAnalyzeCmd())
	rootCmd.AddCommand(newMetricsReportCmd())

	// Let Cobra handle help automatically - it will show flags and detailed descriptions

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		// Exit code 1 for CLI/usage errors (invalid flags, missing args, etc.)
		// Exit code 2 is handled by individual commands for runtime errors
		os.Exit(1)
	}
}
