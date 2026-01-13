package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/manifest"
	"github.com/tturner/cipdip/internal/orch/controller"
)

func newRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run orchestrated tests",
		Long: `Commands for running orchestrated tests.

The run command allows executing test scenarios defined in manifests,
coordinating server and client roles either locally or on remote hosts.`,
	}

	cmd.AddCommand(newRunManifestCmd())

	return cmd
}

func newRunManifestCmd() *cobra.Command {
	var flags struct {
		bundleDir  string
		timeout    time.Duration
		dryRun     bool
		printPlan  bool
		noAnalyze  bool
		noDiff     bool
		verbose    bool
		agents     []string
	}

	cmd := &cobra.Command{
		Use:   "manifest <manifest-file>",
		Short: "Execute a run from a manifest file",
		Long: `Execute an orchestrated run defined in a YAML manifest file.

The manifest defines the server and client roles, profiles to use, network
configuration, and post-run actions.

By default, roles execute locally. Use --agent to specify remote execution
via SSH for specific roles.

Examples:
  cipdip run manifest examples/baseline.yaml
  cipdip run manifest --dry-run manifest.yaml
  cipdip run manifest --bundle-dir ./runs manifest.yaml
  cipdip run manifest --verbose --timeout 5m manifest.yaml

  # Remote execution
  cipdip run manifest --agent server=ssh://user@192.168.1.10 manifest.yaml
  cipdip run manifest --agent server=user@server1 --agent client=user@client1 manifest.yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			manifestPath := args[0]

			// Load manifest
			m, err := manifest.Load(manifestPath)
			if err != nil {
				return fmt.Errorf("load manifest: %w", err)
			}

			// Validate manifest
			if err := m.Validate(); err != nil {
				fmt.Fprintf(os.Stderr, "Manifest validation failed:\n%v\n", err)
				return fmt.Errorf("manifest validation failed")
			}

			// Handle --print-plan: just show the execution plan
			if flags.printPlan {
				return printExecutionPlan(m)
			}

			// Parse agent mappings
			agents := make(map[string]string)
			for _, a := range flags.agents {
				parts := strings.SplitN(a, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid agent spec %q: expected role=transport", a)
				}
				role := parts[0]
				if role != "server" && role != "client" {
					return fmt.Errorf("invalid agent role %q: must be 'server' or 'client'", role)
				}
				agents[role] = parts[1]
			}

			// Set up controller options
			opts := controller.Options{
				BundleDir:    flags.bundleDir,
				BundleFormat: "dir",
				Timeout:      flags.timeout,
				DryRun:       flags.dryRun,
				NoAnalyze:    flags.noAnalyze,
				NoDiff:       flags.noDiff,
				Verbose:      flags.verbose,
				Agents:       agents,
			}

			// Create controller
			ctrl, err := controller.New(m, opts)
			if err != nil {
				return fmt.Errorf("create controller: %w", err)
			}
			defer ctrl.Close()

			// Validate remote agents if any
			if ctrl.HasRemoteAgents() {
				fmt.Fprintln(os.Stdout, "Validating remote agent connectivity...")
				validationCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				results := ctrl.ValidateAgents(validationCtx)
				cancel()

				anyFailed := false
				for role, err := range results {
					if err != nil {
						fmt.Fprintf(os.Stderr, "  %s agent: FAILED (%v)\n", role, err)
						anyFailed = true
					} else if flags.verbose {
						fmt.Fprintf(os.Stdout, "  %s agent: OK\n", role)
					}
				}
				if anyFailed {
					return fmt.Errorf("one or more remote agents failed connectivity check")
				}
				fmt.Fprintln(os.Stdout, "All remote agents validated successfully")
				fmt.Fprintln(os.Stdout)
			}

			// Set up phase reporting
			ctrl.SetPhaseCallback(func(phase controller.Phase, msg string) {
				if flags.verbose {
					fmt.Fprintf(os.Stdout, "[%s] %s\n", phase, msg)
				}
			})

			// Set up context with cancellation
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Handle signals
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
			go func() {
				<-sigChan
				fmt.Fprintf(os.Stderr, "\nReceived interrupt, stopping run...\n")
				cancel()
			}()

			// Run
			fmt.Fprintf(os.Stdout, "Starting orchestrated run from %s\n", manifestPath)
			if flags.dryRun {
				fmt.Fprintf(os.Stdout, "Mode: DRY RUN (no processes will be started)\n")
			}
			fmt.Fprintln(os.Stdout)

			result, err := ctrl.Run(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "\nRun failed: %v\n", err)
				return err
			}

			// Print summary
			fmt.Fprintln(os.Stdout)
			fmt.Fprintf(os.Stdout, "Run completed\n")
			fmt.Fprintf(os.Stdout, "  Run ID:   %s\n", result.RunID)
			fmt.Fprintf(os.Stdout, "  Status:   %s\n", result.Status)
			fmt.Fprintf(os.Stdout, "  Duration: %.1fs\n", result.EndTime.Sub(result.StartTime).Seconds())
			if result.BundlePath != "" {
				fmt.Fprintf(os.Stdout, "  Bundle:   %s\n", result.BundlePath)
			}

			if result.Status != "success" {
				os.Exit(2)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&flags.bundleDir, "bundle-dir", "runs", "Directory for run bundles")
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 30*time.Minute, "Overall run timeout")
	cmd.Flags().BoolVar(&flags.dryRun, "dry-run", false, "Validate and plan only, don't execute")
	cmd.Flags().BoolVar(&flags.printPlan, "print-plan", false, "Print execution plan and exit")
	cmd.Flags().BoolVar(&flags.noAnalyze, "no-analyze", false, "Skip post-run analysis")
	cmd.Flags().BoolVar(&flags.noDiff, "no-diff", false, "Skip diff against baseline")
	cmd.Flags().BoolVar(&flags.verbose, "verbose", false, "Verbose output")
	cmd.Flags().StringArrayVar(&flags.agents, "agent", nil, "Agent mapping (role=transport), e.g., --agent server=ssh://user@host")

	return cmd
}

// printExecutionPlan prints the resolved execution plan.
func printExecutionPlan(m *manifest.Manifest) error {
	resolved, err := m.Resolve()
	if err != nil {
		return fmt.Errorf("resolve manifest: %w", err)
	}

	fmt.Fprintln(os.Stdout, "Execution Plan")
	fmt.Fprintln(os.Stdout, "==============")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "Run ID: %s\n", resolved.RunID)
	fmt.Fprintf(os.Stdout, "Profile: %s\n", resolved.ProfilePath)
	if resolved.ProfileChecksum != "" {
		fmt.Fprintf(os.Stdout, "Profile Checksum: %s\n", resolved.ProfileChecksum)
	}
	fmt.Fprintln(os.Stdout)

	fmt.Fprintln(os.Stdout, "Network:")
	fmt.Fprintf(os.Stdout, "  Target IP: %s\n", m.Network.DataPlane.TargetIP)
	fmt.Fprintf(os.Stdout, "  Target Port: %d\n", m.Network.DataPlane.TargetPort)
	if m.Network.DataPlane.ServerListenIP != "" {
		fmt.Fprintf(os.Stdout, "  Server Listen IP: %s\n", m.Network.DataPlane.ServerListenIP)
	}
	if m.Network.DataPlane.ClientBindIP != "" {
		fmt.Fprintf(os.Stdout, "  Client Bind IP: %s\n", m.Network.DataPlane.ClientBindIP)
	}
	fmt.Fprintln(os.Stdout)

	if m.Roles.Server != nil {
		fmt.Fprintln(os.Stdout, "Server Role:")
		fmt.Fprintf(os.Stdout, "  Agent: %s\n", m.Roles.Server.Agent)
		fmt.Fprintf(os.Stdout, "  Personality: %s\n", m.Roles.Server.Personality)
		if m.Roles.Server.Mode != "" {
			fmt.Fprintf(os.Stdout, "  Mode: %s\n", m.Roles.Server.Mode)
		}
		if len(resolved.ServerArgs) > 0 {
			fmt.Fprintf(os.Stdout, "  Command: cipdip %s\n", formatArgs(resolved.ServerArgs))
		}
		fmt.Fprintln(os.Stdout)
	}

	if m.Roles.Client != nil {
		fmt.Fprintln(os.Stdout, "Client Role:")
		fmt.Fprintf(os.Stdout, "  Agent: %s\n", m.Roles.Client.Agent)
		fmt.Fprintf(os.Stdout, "  Scenario: %s\n", m.Roles.Client.Scenario)
		fmt.Fprintf(os.Stdout, "  Duration: %ds\n", m.Roles.Client.DurationSeconds)
		if m.Roles.Client.IntervalMs > 0 {
			fmt.Fprintf(os.Stdout, "  Interval: %dms\n", m.Roles.Client.IntervalMs)
		}
		if len(resolved.ClientArgs) > 0 {
			fmt.Fprintf(os.Stdout, "  Command: cipdip %s\n", formatArgs(resolved.ClientArgs))
		}
		fmt.Fprintln(os.Stdout)
	}

	fmt.Fprintln(os.Stdout, "Readiness:")
	fmt.Fprintf(os.Stdout, "  Method: %s\n", m.Readiness.Method)
	fmt.Fprintf(os.Stdout, "  Timeout: %ds\n", m.Readiness.TimeoutSeconds)
	fmt.Fprintln(os.Stdout)

	fmt.Fprintln(os.Stdout, "Post-Run:")
	fmt.Fprintf(os.Stdout, "  Analyze: %v\n", m.PostRun.Analyze)
	if m.PostRun.DiffBaseline != "" {
		fmt.Fprintf(os.Stdout, "  Diff Baseline: %s\n", m.PostRun.DiffBaseline)
	}

	return nil
}

// formatArgs formats a slice of args as a shell-like command string.
func formatArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	result := args[0]
	for _, arg := range args[1:] {
		// Simple quoting for args with spaces
		if containsSpace(arg) {
			result += fmt.Sprintf(" %q", arg)
		} else {
			result += " " + arg
		}
	}
	return result
}

func containsSpace(s string) bool {
	for _, c := range s {
		if c == ' ' || c == '\t' {
			return true
		}
	}
	return false
}
