package ui

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Profile is a workspace profile YAML (spec + advanced).
type Profile struct {
	Version  int                    `yaml:"version"`
	Kind     string                 `yaml:"kind"`
	Name     string                 `yaml:"name"`
	Spec     map[string]interface{} `yaml:"spec"`
	Advanced map[string]interface{} `yaml:"advanced"`
}

// ProfileInfo is lightweight metadata for palette listings.
type ProfileInfo struct {
	Path string
	Name string
	Kind string
}

// LoadProfile reads a profile YAML file.
func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	var profile Profile
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}
	if profile.Name == "" {
		profile.Name = filepath.Base(path)
	}
	return &profile, nil
}

// SaveProfile writes a profile YAML file.
func SaveProfile(path string, profile Profile) error {
	data, err := yaml.Marshal(profile)
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write profile: %w", err)
	}
	return nil
}

// ListProfiles returns profile metadata under the workspace profiles directory.
// Returns nil, nil if the profiles directory does not exist.
func ListProfiles(workspaceRoot string) ([]ProfileInfo, error) {
	profilesDir := filepath.Join(workspaceRoot, "profiles")
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read profiles dir: %w", err)
	}
	profiles := make([]ProfileInfo, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		path := filepath.Join(profilesDir, entry.Name())
		profile, err := LoadProfile(path)
		if err != nil {
			continue
		}
		profiles = append(profiles, ProfileInfo{
			Path: path,
			Name: profile.Name,
			Kind: profile.Kind,
		})
	}
	return profiles, nil
}
