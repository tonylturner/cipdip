package profile

import (
	"testing"
	"time"
)

func TestDurationParse(t *testing.T) {
	tests := []struct {
		input    Duration
		expected time.Duration
		wantErr  bool
	}{
		{"30s", 30 * time.Second, false},
		{"5m", 5 * time.Minute, false},
		{"100ms", 100 * time.Millisecond, false},
		{"1h30m", 90 * time.Minute, false},
		{"", 0, false},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			got, err := tt.input.Parse()
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for %q", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error for %q: %v", tt.input, err)
				return
			}
			if got != tt.expected {
				t.Errorf("Parse(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestProfileValidate(t *testing.T) {
	tests := []struct {
		name    string
		profile Profile
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid logix_like profile",
			profile: Profile{
				Metadata: Metadata{
					Name:        "Test Profile",
					Personality: "logix_like",
				},
				DataModel: DataModel{
					Tags: []TagDefinition{
						{Name: "TestTag", Type: "DINT", UpdateRule: "static"},
					},
				},
				StateMachine: StateMachine{
					InitialState: "idle",
					States: map[string]State{
						"idle": {Description: "Idle state"},
					},
				},
				Roles: map[string]Role{
					"hmi": {
						ReadTags:     []string{"TestTag"},
						PollInterval: "500ms",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			profile: Profile{
				Metadata: Metadata{
					Personality: "logix_like",
				},
			},
			wantErr: true,
			errMsg:  "metadata.name is required",
		},
		{
			name: "invalid personality",
			profile: Profile{
				Metadata: Metadata{
					Name:        "Test",
					Personality: "invalid",
				},
			},
			wantErr: true,
			errMsg:  "personality must be",
		},
		{
			name: "logix_like without tags",
			profile: Profile{
				Metadata: Metadata{
					Name:        "Test",
					Personality: "logix_like",
				},
				DataModel: DataModel{},
				StateMachine: StateMachine{
					InitialState: "idle",
					States:       map[string]State{"idle": {}},
				},
			},
			wantErr: true,
			errMsg:  "requires at least one tag",
		},
		{
			name: "adapter without assemblies",
			profile: Profile{
				Metadata: Metadata{
					Name:        "Test",
					Personality: "adapter",
				},
				DataModel: DataModel{},
				StateMachine: StateMachine{
					InitialState: "idle",
					States:       map[string]State{"idle": {}},
				},
			},
			wantErr: true,
			errMsg:  "requires at least one assembly",
		},
		{
			name: "invalid initial state",
			profile: Profile{
				Metadata: Metadata{
					Name:        "Test",
					Personality: "logix_like",
				},
				DataModel: DataModel{
					Tags: []TagDefinition{{Name: "Tag1", Type: "DINT"}},
				},
				StateMachine: StateMachine{
					InitialState: "nonexistent",
					States:       map[string]State{"idle": {}},
				},
			},
			wantErr: true,
			errMsg:  "initial_state",
		},
		{
			name: "transition to unknown state",
			profile: Profile{
				Metadata: Metadata{
					Name:        "Test",
					Personality: "logix_like",
				},
				DataModel: DataModel{
					Tags: []TagDefinition{{Name: "Tag1", Type: "DINT"}},
				},
				StateMachine: StateMachine{
					InitialState: "idle",
					States: map[string]State{
						"idle": {
							Transitions: []Transition{
								{To: "unknown", Condition: "timer:10s"},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "unknown state",
		},
		{
			name: "role references unknown tag",
			profile: Profile{
				Metadata: Metadata{
					Name:        "Test",
					Personality: "logix_like",
				},
				DataModel: DataModel{
					Tags: []TagDefinition{{Name: "Tag1", Type: "DINT"}},
				},
				StateMachine: StateMachine{
					InitialState: "idle",
					States:       map[string]State{"idle": {}},
				},
				Roles: map[string]Role{
					"hmi": {ReadTags: []string{"UnknownTag"}},
				},
			},
			wantErr: true,
			errMsg:  "unknown read tag",
		},
		{
			name: "invalid duration in state",
			profile: Profile{
				Metadata: Metadata{
					Name:        "Test",
					Personality: "logix_like",
				},
				DataModel: DataModel{
					Tags: []TagDefinition{{Name: "Tag1", Type: "DINT"}},
				},
				StateMachine: StateMachine{
					InitialState: "idle",
					States: map[string]State{
						"idle": {Duration: "invalid"},
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid duration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.profile.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestProfileGetters(t *testing.T) {
	profile := Profile{
		Metadata: Metadata{
			Name:        "Test",
			Personality: "logix_like",
		},
		DataModel: DataModel{
			Tags: []TagDefinition{
				{Name: "Tag1", Type: "DINT", Writable: true},
				{Name: "Tag2", Type: "REAL", Writable: false},
			},
			Assemblies: []AssemblyDefinition{
				{Name: "Asm1", Class: 0x04, Instance: 0x64},
			},
		},
		StateMachine: StateMachine{
			InitialState: "idle",
			States: map[string]State{
				"idle":    {},
				"running": {},
			},
		},
		Roles: map[string]Role{
			"hmi":       {},
			"historian": {},
		},
	}

	// Test GetTagByName
	tag := profile.GetTagByName("Tag1")
	if tag == nil || tag.Name != "Tag1" {
		t.Error("GetTagByName failed for Tag1")
	}
	if profile.GetTagByName("NonExistent") != nil {
		t.Error("GetTagByName should return nil for non-existent tag")
	}

	// Test GetAssemblyByName
	asm := profile.GetAssemblyByName("Asm1")
	if asm == nil || asm.Name != "Asm1" {
		t.Error("GetAssemblyByName failed for Asm1")
	}

	// Test GetRole
	role := profile.GetRole("hmi")
	if role == nil {
		t.Error("GetRole failed for hmi")
	}

	// Test RoleNames
	roles := profile.RoleNames()
	if len(roles) != 2 {
		t.Errorf("RoleNames returned %d roles, expected 2", len(roles))
	}

	// Test StateNames
	states := profile.StateNames()
	if len(states) != 2 {
		t.Errorf("StateNames returned %d states, expected 2", len(states))
	}

	// Test WritableTagNames
	writable := profile.WritableTagNames()
	if len(writable) != 1 || writable[0] != "Tag1" {
		t.Errorf("WritableTagNames = %v, expected [Tag1]", writable)
	}

	// Test ToInfo
	info := profile.ToInfo("/path/to/profile.yaml")
	if info.Name != "Test" {
		t.Errorf("ToInfo.Name = %q, expected 'Test'", info.Name)
	}
	if info.RoleCount != 2 {
		t.Errorf("ToInfo.RoleCount = %d, expected 2", info.RoleCount)
	}
	if info.TagCount != 3 { // 2 tags + 1 assembly
		t.Errorf("ToInfo.TagCount = %d, expected 3", info.TagCount)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
