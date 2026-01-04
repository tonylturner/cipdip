package ui

import "github.com/charmbracelet/huh"

func buildWorkspaceForm(currentRoot string) *huh.Form {
	action := "open"
	path := currentRoot
	name := ""

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

	return huh.NewForm(actionGroup, pathGroup, nameGroup)
}
