package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProfile(t *testing.T) {
	// Get the project root (two levels up from internal/profile)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	// Navigate to project root
	projectRoot := filepath.Join(wd, "..", "..")
	profilesDir := filepath.Join(projectRoot, "profiles")

	// Check if profiles directory exists
	if _, err := os.Stat(profilesDir); os.IsNotExist(err) {
		t.Skip("profiles directory not found, skipping integration test")
	}

	tests := []struct {
		name         string
		wantTags     int
		wantStates   int
		wantRoles    int
		personality  string
	}{
		{
			name:        "water_pump_station",
			wantTags:    12,
			wantStates:  4,
			wantRoles:   3,
			personality: "logix_like",
		},
		{
			name:        "batch_mixing_tank",
			wantTags:    21,
			wantStates:  7,
			wantRoles:   3,
			personality: "logix_like",
		},
		{
			name:        "paint_shop_conveyor",
			wantTags:    17,
			wantStates:  5,
			wantRoles:   3,
			personality: "adapter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(profilesDir, tt.name+".yaml")
			profile, err := LoadProfile(path)
			if err != nil {
				t.Fatalf("LoadProfile(%s) error: %v", tt.name, err)
			}

			if profile.Metadata.Personality != tt.personality {
				t.Errorf("personality = %q, want %q", profile.Metadata.Personality, tt.personality)
			}

			if len(profile.DataModel.Tags) != tt.wantTags {
				t.Errorf("tag count = %d, want %d", len(profile.DataModel.Tags), tt.wantTags)
			}

			if len(profile.StateMachine.States) != tt.wantStates {
				t.Errorf("state count = %d, want %d", len(profile.StateMachine.States), tt.wantStates)
			}

			if len(profile.Roles) != tt.wantRoles {
				t.Errorf("role count = %d, want %d", len(profile.Roles), tt.wantRoles)
			}

			// Verify validation passes
			if err := profile.Validate(); err != nil {
				t.Errorf("profile validation failed: %v", err)
			}
		})
	}
}

func TestLoadProfileByName(t *testing.T) {
	// Get the project root
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	projectRoot := filepath.Join(wd, "..", "..")
	profilesDir := filepath.Join(projectRoot, "profiles")

	if _, err := os.Stat(profilesDir); os.IsNotExist(err) {
		t.Skip("profiles directory not found, skipping integration test")
	}

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"exact name", "water_pump_station", false},
		{"with extension", "water_pump_station.yaml", false},
		{"non-existent", "does_not_exist", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadProfileByNameFromDir(tt.input, profilesDir)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestListProfiles(t *testing.T) {
	// Get the project root
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	projectRoot := filepath.Join(wd, "..", "..")
	profilesDir := filepath.Join(projectRoot, "profiles")

	if _, err := os.Stat(profilesDir); os.IsNotExist(err) {
		t.Skip("profiles directory not found, skipping integration test")
	}

	profiles, err := ListProfiles(profilesDir)
	if err != nil {
		t.Fatalf("ListProfiles error: %v", err)
	}

	if len(profiles) < 3 {
		t.Errorf("expected at least 3 profiles, got %d", len(profiles))
	}

	// Check that all expected profiles are present
	expectedNames := map[string]bool{
		"Water Pump Station":     false,
		"Batch Mixing Tank":      false,
		"Paint Shop Conveyor Cell": false,
	}

	for _, p := range profiles {
		if _, ok := expectedNames[p.Name]; ok {
			expectedNames[p.Name] = true
		}
	}

	for name, found := range expectedNames {
		if !found {
			t.Errorf("expected profile %q not found", name)
		}
	}
}

func TestListProfilesNonExistent(t *testing.T) {
	profiles, err := ListProfiles("/nonexistent/directory")
	if err != nil {
		t.Errorf("expected nil error for non-existent directory, got: %v", err)
	}
	if profiles != nil && len(profiles) != 0 {
		t.Errorf("expected empty slice for non-existent directory, got %d profiles", len(profiles))
	}
}

func TestProfileExistsInDir(t *testing.T) {
	// Get the project root
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	projectRoot := filepath.Join(wd, "..", "..")
	profilesDir := filepath.Join(projectRoot, "profiles")

	if _, err := os.Stat(profilesDir); os.IsNotExist(err) {
		t.Skip("profiles directory not found, skipping integration test")
	}

	if !ProfileExistsInDir("water_pump_station", profilesDir) {
		t.Error("water_pump_station should exist")
	}

	if ProfileExistsInDir("nonexistent_profile", profilesDir) {
		t.Error("nonexistent_profile should not exist")
	}
}
