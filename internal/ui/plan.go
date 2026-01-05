package ui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Plan represents a multi-step test plan.
type Plan struct {
	Version int                 `yaml:"version"`
	Name    string              `yaml:"name"`
	Steps   []map[string]string `yaml:"steps"`
}

// BuildPlanFromText parses a plan definition from newline-delimited steps.
func BuildPlanFromText(name, text string) (Plan, error) {
	if strings.TrimSpace(name) == "" {
		return Plan{}, fmt.Errorf("plan name is required")
	}
	steps := make([]map[string]string, 0)
	validationErrors := make([]string, 0)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return Plan{}, fmt.Errorf("invalid step: %q (expected kind:value)", line)
		}
		kind := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if kind == "" || value == "" {
			return Plan{}, fmt.Errorf("invalid step: %q (empty kind or value)", line)
		}
		if err := validatePlanStep(kind, value); err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("%s: %v", line, err))
		}
		steps = append(steps, map[string]string{kind: value})
	}
	if len(steps) == 0 {
		return Plan{}, fmt.Errorf("plan requires at least one step")
	}
	if len(validationErrors) > 0 {
		return Plan{}, fmt.Errorf("plan validation failed:\n%s", strings.Join(validationErrors, "\n"))
	}
	return Plan{
		Version: 1,
		Name:    name,
		Steps:   steps,
	}, nil
}

// SavePlan writes the plan YAML to disk.
func SavePlan(path string, plan Plan) error {
	data, err := yaml.Marshal(plan)
	if err != nil {
		return fmt.Errorf("marshal plan: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write plan: %w", err)
	}
	return nil
}

// LoadPlan reads a plan YAML file.
func LoadPlan(path string) (*Plan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read plan: %w", err)
	}
	var plan Plan
	if err := yaml.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("parse plan: %w", err)
	}
	return &plan, nil
}

// PlanPath returns a new plan path under workspace/plans.
func PlanPath(workspaceRoot, name string) string {
	base := sanitizeRunName(name)
	if base == "" {
		base = "plan"
	}
	return filepath.Join(workspaceRoot, "plans", base+".yaml")
}

// ExecutePlan runs a plan sequentially and returns combined stdout.
func ExecutePlan(ctx context.Context, workspaceRoot string, plan Plan) (string, error) {
	var output strings.Builder
	for idx, step := range plan.Steps {
		for kind, value := range step {
			kind = strings.ToLower(strings.TrimSpace(kind))
			value = strings.TrimSpace(value)
			if value == "" {
				return output.String(), fmt.Errorf("step %d: empty value", idx+1)
			}
			switch kind {
			case "sleep":
				dur, err := time.ParseDuration(value)
				if err != nil {
					return output.String(), fmt.Errorf("step %d: invalid sleep duration: %w", idx+1, err)
				}
				output.WriteString(fmt.Sprintf("Step %d: sleep %s\n", idx+1, dur))
				time.Sleep(dur)
			case "single":
				cmd, err := buildSingleCommandFromPlan(workspaceRoot, value)
				if err != nil {
					return output.String(), fmt.Errorf("step %d: %w", idx+1, err)
				}
				output.WriteString(fmt.Sprintf("Step %d: %s\n", idx+1, FormatCommand(cmd.Args)))
				stdout, _, err := ExecuteCommand(ctx, cmd)
				if err != nil {
					output.WriteString(stdout + "\n")
					return output.String(), fmt.Errorf("step %d: %w", idx+1, err)
				}
				if stdout != "" {
					output.WriteString(stdout + "\n")
				}
			case "replay":
				cmd, err := buildReplayCommandFromPlan(workspaceRoot, value)
				if err != nil {
					return output.String(), fmt.Errorf("step %d: %w", idx+1, err)
				}
				output.WriteString(fmt.Sprintf("Step %d: %s\n", idx+1, FormatCommand(cmd.Args)))
				stdout, _, err := ExecuteCommand(ctx, cmd)
				if err != nil {
					output.WriteString(stdout + "\n")
					return output.String(), fmt.Errorf("step %d: %w", idx+1, err)
				}
				if stdout != "" {
					output.WriteString(stdout + "\n")
				}
			default:
				return output.String(), fmt.Errorf("step %d: unsupported kind %q", idx+1, kind)
			}
		}
	}
	return output.String(), nil
}

func buildSingleCommandFromPlan(workspaceRoot, value string) (CommandSpec, error) {
	catalogKey, ip, port, err := parseSingleStep(value)
	if err != nil {
		return CommandSpec{}, err
	}
	entries, _ := ListCatalogEntries(workspaceRoot)
	entry := FindCatalogEntry(entries, catalogKey)
	if entry == nil {
		return CommandSpec{}, fmt.Errorf("catalog entry %q not found", catalogKey)
	}
	spec := map[string]interface{}{
		"ip":       ip,
		"port":     port,
		"service":  entry.Service,
		"class":    entry.Class,
		"instance": entry.Instance,
	}
	if entry.Attribute != "" {
		spec["attribute"] = entry.Attribute
	}
	profile := Profile{
		Version: 1,
		Kind:    "single",
		Name:    entry.Key,
		Spec:    spec,
	}
	return BuildCommandWithWorkspace(profile, workspaceRoot)
}

func buildReplayCommandFromPlan(workspaceRoot, value string) (CommandSpec, error) {
	profile, err := loadProfileByName(workspaceRoot, value)
	if err != nil {
		return CommandSpec{}, err
	}
	return BuildCommandWithWorkspace(*profile, workspaceRoot)
}

func loadProfileByName(workspaceRoot, name string) (*Profile, error) {
	profiles, err := ListProfiles(workspaceRoot)
	if err != nil {
		return nil, err
	}
	for _, profile := range profiles {
		if profile.Name == name || filepath.Base(profile.Path) == name {
			return LoadProfile(profile.Path)
		}
	}
	return nil, fmt.Errorf("profile %q not found", name)
}

func parseSingleStep(value string) (string, string, int, error) {
	parts := strings.Split(value, "@")
	if len(parts) != 2 {
		return "", "", 0, fmt.Errorf("single step must be <catalog_key>@<ip[:port]>")
	}
	key := strings.TrimSpace(parts[0])
	target := strings.TrimSpace(parts[1])
	if key == "" || target == "" {
		return "", "", 0, fmt.Errorf("single step must be <catalog_key>@<ip[:port]>")
	}
	ip := target
	port := 44818
	if strings.Contains(target, ":") {
		hostParts := strings.Split(target, ":")
		if len(hostParts) != 2 {
			return "", "", 0, fmt.Errorf("invalid target format %q", target)
		}
		ip = hostParts[0]
		if ip == "" {
			return "", "", 0, fmt.Errorf("invalid target format %q", target)
		}
		parsed, err := strconv.Atoi(hostParts[1])
		if err != nil {
			return "", "", 0, fmt.Errorf("invalid port %q", hostParts[1])
		}
		port = parsed
	}
	return key, ip, port, nil
}

func validatePlanStep(kind, value string) error {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "sleep":
		if _, err := time.ParseDuration(value); err != nil {
			return fmt.Errorf("invalid sleep duration")
		}
		return nil
	case "single":
		_, _, _, err := parseSingleStep(value)
		if err != nil {
			return err
		}
		return nil
	case "replay":
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("replay requires profile name")
		}
		return nil
	default:
		return fmt.Errorf("unsupported step kind")
	}
}
