package ui

import "github.com/charmbracelet/huh"

func buildWorkspaceForm(currentRoot string) *huh.Form {
	action := "open"
	path := currentRoot
	name := ""
	targetIPs := ""
	defaultTargetIP := ""

	actionGroup := huh.NewGroup(
		huh.NewSelect[string]().
			Title("Workspace action").
			Description("Open an existing workspace or create a new one.").
			Key("workspace_action").
			Options(
				huh.NewOption("Open", "open"),
				huh.NewOption("Create", "create"),
			).
			Value(&action),
	)

	pathGroup := huh.NewGroup(
		huh.NewInput().
			Title("Workspace path").
			Description("Absolute or relative path to workspace.").
			Key("workspace_path").
			Value(&path),
	)

	nameGroup := huh.NewGroup(
		huh.NewInput().
			Title("Workspace name (create only)").
			Description("Optional display name for new workspace.").
			Key("workspace_name").
			Value(&name),
	).WithHideFunc(func() bool { return action != "create" })

	targetGroup := huh.NewGroup(
		huh.NewInput().
			Title("Target IPs (optional)").
			Description("Comma-separated list of targets for this workspace.").
			Key("workspace_target_ips").
			Value(&targetIPs),
		huh.NewInput().
			Title("Default target IP (optional)").
			Description("Used to prefill single-request wizards.").
			Key("workspace_default_target_ip").
			Value(&defaultTargetIP),
	)

	return huh.NewForm(actionGroup, pathGroup, nameGroup, targetGroup)
}
