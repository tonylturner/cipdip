package ui

import "fmt"

// ResolveProfile applies workspace defaults and advanced overrides to a profile.
func ResolveProfile(profile Profile, workspaceRoot string) (Profile, error) {
	resolved := profile
	spec := copyMap(profile.Spec)
	if spec == nil {
		spec = make(map[string]interface{})
	}
	if workspaceRoot != "" {
		ws, err := LoadWorkspace(workspaceRoot)
		if err != nil {
			return Profile{}, fmt.Errorf("load workspace: %w", err)
		}
		applyWorkspaceDefaults(&resolved, spec, ws.Config.Defaults)
	}
	if len(profile.Advanced) > 0 {
		mergeMap(spec, profile.Advanced)
	}
	resolved.Spec = spec
	return resolved, nil
}

func applyWorkspaceDefaults(profile *Profile, spec map[string]interface{}, defaults WorkspaceDefaults) {
	switch profile.Kind {
	case "single":
		if getString(spec, "ip") == "" {
			if defaults.DefaultTargetIP != "" {
				spec["ip"] = defaults.DefaultTargetIP
			} else if len(defaults.TargetIPs) > 0 {
				spec["ip"] = defaults.TargetIPs[0]
			}
		}
	}
}

func copyMap(input map[string]interface{}) map[string]interface{} {
	if input == nil {
		return nil
	}
	out := make(map[string]interface{}, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func mergeMap(dst, src map[string]interface{}) {
	for key, value := range src {
		dst[key] = value
	}
}
