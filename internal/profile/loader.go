package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultProfilesDir is the default directory for profile YAML files.
const DefaultProfilesDir = "profiles"

// LoadProfile reads and parses a profile YAML file.
func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile file: %w", err)
	}

	var profile Profile
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("parse profile YAML: %w", err)
	}

	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("validate profile: %w", err)
	}

	return &profile, nil
}

// LoadProfileByName loads a profile by name from the default profiles directory.
// The name can be with or without the .yaml extension.
func LoadProfileByName(name string) (*Profile, error) {
	return LoadProfileByNameFromDir(name, DefaultProfilesDir)
}

// LoadProfileByNameFromDir loads a profile by name from a specific directory.
// It matches by filename first, then by metadata name (case-insensitive).
func LoadProfileByNameFromDir(name, dir string) (*Profile, error) {
	// Normalize name
	name = strings.TrimSuffix(name, ".yaml")
	name = strings.TrimSuffix(name, ".yml")

	// Try exact filename match first
	for _, ext := range []string{".yaml", ".yml"} {
		path := filepath.Join(dir, name+ext)
		if _, err := os.Stat(path); err == nil {
			return LoadProfile(path)
		}
	}

	// Read directory entries
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read profiles directory: %w", err)
	}

	nameLower := strings.ToLower(name)

	// Try case-insensitive filename match
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		entryName := entry.Name()
		ext := filepath.Ext(entryName)
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		baseName := strings.TrimSuffix(entryName, ext)
		if strings.ToLower(baseName) == nameLower {
			return LoadProfile(filepath.Join(dir, entryName))
		}
	}

	// Try matching by metadata name (supports display names like "Batch Mixing Tank")
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		entryName := entry.Name()
		ext := filepath.Ext(entryName)
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		path := filepath.Join(dir, entryName)
		profile, err := LoadProfile(path)
		if err != nil {
			continue // Skip invalid profiles
		}
		if strings.EqualFold(profile.Metadata.Name, name) {
			return profile, nil
		}
	}

	return nil, fmt.Errorf("profile %q not found in %s", name, dir)
}

// ListProfiles returns information about all available profiles in a directory.
func ListProfiles(dir string) ([]ProfileInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Empty list if directory doesn't exist
		}
		return nil, fmt.Errorf("read profiles directory: %w", err)
	}

	var profiles []ProfileInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		profile, err := LoadProfile(path)
		if err != nil {
			// Skip invalid profiles but log the error
			continue
		}

		profiles = append(profiles, profile.ToInfo(path))
	}

	// Sort by name
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Name < profiles[j].Name
	})

	return profiles, nil
}

// ListProfilesDefault lists profiles from the default profiles directory.
func ListProfilesDefault() ([]ProfileInfo, error) {
	return ListProfiles(DefaultProfilesDir)
}

// ProfileExists checks if a profile exists by name.
func ProfileExists(name string) bool {
	return ProfileExistsInDir(name, DefaultProfilesDir)
}

// ProfileExistsInDir checks if a profile exists by name in a specific directory.
func ProfileExistsInDir(name, dir string) bool {
	name = strings.TrimSuffix(name, ".yaml")
	name = strings.TrimSuffix(name, ".yml")

	for _, ext := range []string{".yaml", ".yml"} {
		path := filepath.Join(dir, name+ext)
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

// SaveProfile writes a profile to a YAML file.
func SaveProfile(path string, profile *Profile) error {
	if err := profile.Validate(); err != nil {
		return fmt.Errorf("validate profile before save: %w", err)
	}

	data, err := yaml.Marshal(profile)
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create profile directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write profile file: %w", err)
	}

	return nil
}

// GetBuiltinProfileNames returns names of the three standard profiles.
func GetBuiltinProfileNames() []string {
	return []string{
		"water_pump_station",
		"batch_mixing_tank",
		"paint_shop_conveyor",
	}
}
