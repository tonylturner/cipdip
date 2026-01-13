package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/orch/bundle"
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
