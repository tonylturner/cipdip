package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/tui"
	"github.com/tonylturner/cipdip/internal/ui"
)

type uiFlags struct {
	workspace         string
	newWorkspace      string
	profile           string
	wizard            string
	wizardInput       string
	wizardPreset      string
	wizardMode        string
	wizardName        string
	wizardOutput      string
	wizardDuration    int
	wizardTarget      string
	wizardPersonality string
	wizardServerIP    string
	wizardServerPort  int
	wizardCatalogKey  string
	wizardIP          string
	wizardPort        int
	wizardService     string
	wizardClass       string
	wizardInstance    string
	wizardAttribute   string
	wizardPayloadHex  string
	catalogQuery      string
	showCatalog       bool
	paletteQuery      string
	showPalette       bool
	showHome          bool
	startTUI          bool
	cliMode           bool
	noRun             bool
	printCommand      bool
}

func newUICmd() *cobra.Command {
	flags := &uiFlags{}
	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Open the CIPDIP dashboard",
		Long: `Launch the CIPDIP TUI dashboard for workspace-based runs.

The dashboard provides a unified interface for client, server, PCAP analysis,
and catalog browsing. All operations run from the same screen with live stats.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUI(flags)
		},
	}

	cmd.Flags().StringVar(&flags.workspace, "workspace", "", "Workspace path to open")
	cmd.Flags().StringVar(&flags.newWorkspace, "new-workspace", "", "Create a new workspace at this path")
	cmd.Flags().StringVar(&flags.profile, "profile", "", "Profile name or filename to use (non-interactive)")
	cmd.Flags().StringVar(&flags.wizard, "wizard", "", "Generate a wizard profile: pcap-replay|baseline|server")
	cmd.Flags().StringVar(&flags.wizardInput, "wizard-input", "", "Wizard input (pcap path)")
	cmd.Flags().StringVar(&flags.wizardPreset, "wizard-preset", "", "Wizard preset name")
	cmd.Flags().StringVar(&flags.wizardMode, "wizard-mode", "", "Wizard mode override")
	cmd.Flags().StringVar(&flags.wizardName, "wizard-name", "", "Wizard profile name")
	cmd.Flags().StringVar(&flags.wizardOutput, "wizard-output-dir", "", "Wizard output directory")
	cmd.Flags().IntVar(&flags.wizardDuration, "wizard-duration", 0, "Wizard duration (seconds)")
	cmd.Flags().StringVar(&flags.wizardTarget, "wizard-target", "", "Wizard target preset")
	cmd.Flags().StringVar(&flags.wizardPersonality, "wizard-personality", "", "Wizard server personality")
	cmd.Flags().StringVar(&flags.wizardServerIP, "wizard-server-ip", "", "Wizard server IP")
	cmd.Flags().IntVar(&flags.wizardServerPort, "wizard-server-port", 0, "Wizard server port")
	cmd.Flags().StringVar(&flags.wizardCatalogKey, "wizard-catalog-key", "", "Wizard catalog key for single requests")
	cmd.Flags().StringVar(&flags.wizardIP, "wizard-ip", "", "Wizard target IP for single requests")
	cmd.Flags().IntVar(&flags.wizardPort, "wizard-port", 0, "Wizard target port for single requests")
	cmd.Flags().StringVar(&flags.wizardService, "wizard-service", "", "Wizard service code for single requests")
	cmd.Flags().StringVar(&flags.wizardClass, "wizard-class", "", "Wizard class ID for single requests")
	cmd.Flags().StringVar(&flags.wizardInstance, "wizard-instance", "", "Wizard instance ID for single requests")
	cmd.Flags().StringVar(&flags.wizardAttribute, "wizard-attribute", "", "Wizard attribute ID for single requests")
	cmd.Flags().StringVar(&flags.wizardPayloadHex, "wizard-payload-hex", "", "Wizard payload hex for single requests")
	cmd.Flags().BoolVar(&flags.showCatalog, "catalog", false, "Show catalog entries and exit")
	cmd.Flags().StringVar(&flags.catalogQuery, "catalog-query", "", "Filter catalog entries by search term")
	cmd.Flags().BoolVar(&flags.showPalette, "palette", false, "Show command palette results and exit")
	cmd.Flags().StringVar(&flags.paletteQuery, "palette-query", "", "Filter palette results by search term")
	cmd.Flags().BoolVar(&flags.showHome, "home", false, "Show the home screen preview and exit")
	cmd.Flags().BoolVar(&flags.startTUI, "tui", false, "Start the interactive TUI (Bubble Tea)")
	cmd.Flags().BoolVar(&flags.cliMode, "cli", false, "Force non-interactive output (no TUI)")
	cmd.Flags().BoolVar(&flags.noRun, "no-run", false, "Do not execute commands, only prepare workspace")
	cmd.Flags().BoolVar(&flags.printCommand, "print-command", false, "Print generated command and exit")

	return cmd
}

func runUI(flags *uiFlags) error {
	if flags.newWorkspace != "" && flags.workspace != "" {
		return fmt.Errorf("use either --workspace or --new-workspace, not both")
	}
	if flags.workspace == "" && flags.newWorkspace == "" {
		flags.workspace = filepath.Join("workspaces", "workspace")
	}
	if flags.newWorkspace != "" {
		_, err := ui.CreateWorkspace(flags.newWorkspace, "")
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "Workspace created: %s\n", flags.newWorkspace)
		return nil
	}

	if flags.workspace == "" {
		return fmt.Errorf("workspace path is required (use --workspace or --new-workspace)")
	}
	ws, err := ui.EnsureWorkspace(flags.workspace)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			ws, err = ui.CreateWorkspace(flags.workspace, "")
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "Workspace created: %s\n", ws.Root)
		} else {
			return err
		}
	}

	fmt.Fprintf(os.Stdout, "Workspace loaded: %s\n", ws.Root)
	if flags.startTUI {
		return tui.Run(ws.Root)
	}
	previewOnly := flags.cliMode || flags.noRun || flags.printCommand || flags.showCatalog || flags.showPalette || flags.showHome || flags.wizard != "" || flags.profile != ""
	if flags.showCatalog {
		entries, err := ui.ListCatalogEntries(ws.Root)
		if err != nil {
			return err
		}
		sources, _ := ui.ListCatalogSources(ws.Root)
		fmt.Fprintln(os.Stdout, ui.RenderCatalogExplorer(entries, flags.catalogQuery, sources))
		return nil
	}
	if flags.showPalette {
		items, err := ui.BuildPaletteIndex(ws.Root)
		if err != nil {
			return err
		}
		filtered := ui.FilterPalette(items, flags.paletteQuery)
		for _, item := range filtered {
			fmt.Fprintln(os.Stdout, item.String())
		}
		return nil
	}
	if flags.showHome {
		profiles, _ := ui.ListProfiles(ws.Root)
		items, _ := ui.BuildPaletteIndex(ws.Root)
		runs, _ := ui.ListRuns(ws.Root, 5)
		fmt.Fprintln(os.Stdout, ui.RenderHomeScreen(ws.Config.Name, profiles, runs, items))
		return nil
	}
	if flags.cliMode && flags.wizard == "" && flags.profile == "" && !flags.noRun && !flags.printCommand {
		profiles, _ := ui.ListProfiles(ws.Root)
		items, _ := ui.BuildPaletteIndex(ws.Root)
		runs, _ := ui.ListRuns(ws.Root, 5)
		fmt.Fprintln(os.Stdout, ui.RenderHomeScreen(ws.Config.Name, profiles, runs, items))
		return nil
	}
	if !previewOnly {
		return tui.Run(ws.Root)
	}
	var profiles []ui.ProfileInfo
	if flags.wizard == "" {
		profiles, err = ui.ListProfiles(ws.Root)
		if err != nil {
			return err
		}
	}
	if flags.wizard == "" && len(profiles) == 0 {
		fmt.Fprintln(os.Stdout, "No profiles found under workspace/profiles.")
		palette, _ := ui.BuildPaletteIndex(ws.Root)
		runs, _ := ui.ListRuns(ws.Root, 5)
		fmt.Fprintln(os.Stdout, ui.RenderHomeScreen(ws.Config.Name, profiles, runs, palette))
		if flags.noRun {
			fmt.Fprintln(os.Stdout, "TUI run disabled (--no-run).")
		}
		return nil
	}
	if flags.wizard == "" && len(profiles) > 1 {
		if flags.profile == "" {
			fmt.Fprintln(os.Stdout, "Multiple profiles found. Use --profile to select one or start the TUI.")
			palette, _ := ui.BuildPaletteIndex(ws.Root)
			runs, _ := ui.ListRuns(ws.Root, 5)
			fmt.Fprintln(os.Stdout, ui.RenderHomeScreen(ws.Config.Name, profiles, runs, palette))
			if flags.noRun {
				fmt.Fprintln(os.Stdout, "TUI run disabled (--no-run).")
			}
			return nil
		}
		selected := selectProfile(profiles, flags.profile)
		if selected == nil {
			return fmt.Errorf("profile %q not found in workspace", flags.profile)
		}
		profiles = []ui.ProfileInfo{*selected}
	}

	var profile *ui.Profile
	if flags.wizard != "" {
		if strings.EqualFold(flags.wizard, "single") && flags.wizardCatalogKey != "" {
			entries, err := ui.ListCatalogEntries(ws.Root)
			if err != nil {
				return err
			}
			entry := ui.FindCatalogEntry(entries, flags.wizardCatalogKey)
			if entry == nil {
				return fmt.Errorf("catalog key %q not found", flags.wizardCatalogKey)
			}
			if flags.wizardService == "" {
				flags.wizardService = entry.Service
			}
			if flags.wizardClass == "" {
				flags.wizardClass = entry.Class
			}
			if flags.wizardInstance == "" {
				flags.wizardInstance = entry.Instance
			}
			if flags.wizardAttribute == "" {
				flags.wizardAttribute = entry.Attribute
			}
			if flags.wizardPayloadHex == "" {
				flags.wizardPayloadHex = entry.PayloadHex
			}
		}
		wizardProfile, err := ui.BuildWizardProfile(ui.WizardOptions{
			Kind:        flags.wizard,
			Name:        flags.wizardName,
			Input:       flags.wizardInput,
			Preset:      flags.wizardPreset,
			Mode:        flags.wizardMode,
			OutputDir:   flags.wizardOutput,
			Duration:    flags.wizardDuration,
			ServerIP:    flags.wizardServerIP,
			ServerPort:  flags.wizardServerPort,
			Personality: flags.wizardPersonality,
			Target:      flags.wizardTarget,
			IP:          flags.wizardIP,
			Port:        flags.wizardPort,
			Service:     flags.wizardService,
			Class:       flags.wizardClass,
			Instance:    flags.wizardInstance,
			Attribute:   flags.wizardAttribute,
			PayloadHex:  flags.wizardPayloadHex,
		})
		if err != nil {
			return err
		}
		profile = &wizardProfile
	} else {
		loaded, err := ui.LoadProfile(profiles[0].Path)
		if err != nil {
			return err
		}
		profile = loaded
	}
	command, err := ui.BuildCommandWithWorkspace(*profile, ws.Root)
	if err != nil {
		return err
	}

	if flags.printCommand {
		fmt.Fprintln(os.Stdout, ui.RenderReviewScreen(*profile, command))
		return nil
	}
	if flags.noRun {
		runDir, err := ui.CreateRunDir(ws.Root, profile.Name)
		if err != nil {
			return err
		}
		summary := ui.RunSummary{
			Status:     "no-run",
			Command:    command.Args,
			StartedAt:  time.Now().UTC().Format(time.RFC3339),
			FinishedAt: time.Now().UTC().Format(time.RFC3339),
			ExitCode:   0,
		}
		resolved := map[string]interface{}{
			"profile": profile,
			"command": command.Args,
		}
		if err := ui.WriteRunArtifacts(runDir, resolved, command.Args, "", summary); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "Run artifacts written: %s\n", runDir)
		fmt.Fprintln(os.Stdout, "TUI run disabled (--no-run).")
		return nil
	}
	runDir, err := ui.CreateRunDir(ws.Root, profile.Name)
	if err != nil {
		return err
	}
	started := time.Now().UTC()
	stdout, exitCode, runErr := ui.ExecuteCommand(context.Background(), command)
	finished := time.Now().UTC()
	status := "success"
	if runErr != nil {
		status = "failed"
	}
	summary := ui.RunSummary{
		Status:     status,
		Command:    command.Args,
		StartedAt:  started.Format(time.RFC3339),
		FinishedAt: finished.Format(time.RFC3339),
		ExitCode:   exitCode,
	}
	resolved := map[string]interface{}{
		"profile": profile,
		"command": command.Args,
	}
	if err := ui.WriteRunArtifacts(runDir, resolved, command.Args, stdout, summary); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Run complete (%s). Artifacts: %s\n", status, runDir)
	return runErr
}

func selectProfile(profiles []ui.ProfileInfo, value string) *ui.ProfileInfo {
	valueLower := strings.ToLower(strings.TrimSpace(value))
	for _, profile := range profiles {
		if strings.ToLower(profile.Name) == valueLower {
			return &profile
		}
		if strings.ToLower(filepath.Base(profile.Path)) == valueLower {
			return &profile
		}
	}
	return nil
}
