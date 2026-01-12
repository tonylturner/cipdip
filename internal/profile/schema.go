// Package profile implements process profiles for realistic ICS traffic generation.
// Profiles define application-shaped behavior (state machines, roles, events)
// for DPI baselining and torture testing.
package profile

import (
	"fmt"
	"time"
)

// Profile defines a complete process profile for realistic ICS traffic generation.
type Profile struct {
	Metadata     Metadata              `yaml:"metadata"`
	DataModel    DataModel             `yaml:"data_model"`
	StateMachine StateMachine          `yaml:"state_machine"`
	Roles        map[string]Role       `yaml:"roles"`
	Baselining   *BaselineConfig       `yaml:"baselining,omitempty"`
	Torture      *TortureConfig        `yaml:"torture,omitempty"`
}

// Metadata contains profile identification and configuration.
type Metadata struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Version     string `yaml:"version"`
	Seed        int64  `yaml:"seed"`          // 0 = time-based random
	Personality string `yaml:"personality"`   // "adapter" or "logix_like"
	EnableUDPIO bool   `yaml:"enable_udp_io"` // Enable UDP I/O (implicit messaging)
}

// DataModel defines the tags and assemblies available in the profile.
type DataModel struct {
	Tags       []TagDefinition      `yaml:"tags,omitempty"`
	Assemblies []AssemblyDefinition `yaml:"assemblies,omitempty"`
}

// TagDefinition defines a tag for logix-like profiles.
type TagDefinition struct {
	Name         string                 `yaml:"name"`
	Type         string                 `yaml:"type"` // BOOL, SINT, INT, DINT, REAL, etc.
	ArrayLength  int                    `yaml:"array_length,omitempty"`
	InitialValue interface{}            `yaml:"initial_value,omitempty"`
	Writable     bool                   `yaml:"writable"`
	UpdateRule   string                 `yaml:"update_rule"` // static, counter, ramp, toggle, sine, latch
	UpdateParams map[string]interface{} `yaml:"update_params,omitempty"`
}

// FieldMapping maps a tag name to a position within an assembly's data.
// This enables adapter profiles to expose symbolic tag names that resolve
// to specific byte/bit positions in assembly I/O data.
type FieldMapping struct {
	Name       string `yaml:"name"`        // Tag name reference
	Type       string `yaml:"type"`        // BOOL, INT, DINT, REAL
	ByteOffset int    `yaml:"byte_offset"` // Offset within assembly data
	BitOffset  int    `yaml:"bit_offset"`  // For BOOL types (0-7), ignored for others
}

// AssemblyDefinition defines an assembly for adapter-like profiles.
type AssemblyDefinition struct {
	Name       string         `yaml:"name"`
	Class      uint16         `yaml:"class"`
	Instance   uint16         `yaml:"instance"`
	Attribute  uint16         `yaml:"attribute"`
	SizeBytes  int            `yaml:"size_bytes"`
	Writable   bool           `yaml:"writable"`
	UpdateRule string         `yaml:"update_rule"`
	Fields     []FieldMapping `yaml:"fields,omitempty"` // Tag-to-bit mappings for adapter profiles
}

// StateMachine defines the operational state machine.
type StateMachine struct {
	InitialState string           `yaml:"initial_state"`
	States       map[string]State `yaml:"states"`
}

// State defines behavior in a particular operational state.
type State struct {
	Description  string            `yaml:"description"`
	Duration     Duration          `yaml:"duration,omitempty"`      // Minimum time in state
	Transitions  []Transition      `yaml:"transitions,omitempty"`
	TagOverrides map[string]string `yaml:"tag_overrides,omitempty"` // Tag -> update rule override
	Events       []Event           `yaml:"events,omitempty"`
}

// Transition defines a state change condition.
type Transition struct {
	To        string `yaml:"to"`
	Condition string `yaml:"condition"` // "timer:30s", "tag:AlarmAck==true", "event:name"
	Priority  int    `yaml:"priority,omitempty"`
}

// Event defines something that can happen in a state.
type Event struct {
	Name    string   `yaml:"name"`
	Trigger string   `yaml:"trigger"` // "timer:10s", "random:0.1", "once"
	Actions []Action `yaml:"actions"`
}

// Action defines what an event does.
type Action struct {
	Type   string      `yaml:"type"`   // "set_tag", "trigger_transition", "log"
	Target string      `yaml:"target"` // Tag name or transition name
	Value  interface{} `yaml:"value,omitempty"`
}

// Role defines client behavior patterns for a specific role.
type Role struct {
	Description  string       `yaml:"description"`
	PollInterval Duration     `yaml:"poll_interval"`
	ReadTags     []string     `yaml:"read_tags"`
	WriteTags    []string     `yaml:"write_tags"`
	BatchSize    int          `yaml:"batch_size"` // MSP batch size (0 = no batching)
	WriteEvents  []WriteEvent `yaml:"write_events,omitempty"`
}

// WriteEvent defines when a role performs writes.
type WriteEvent struct {
	Trigger   string      `yaml:"trigger"`             // "state:running", "timer:60s", "random:0.05"
	Tag       string      `yaml:"tag"`
	Value     interface{} `yaml:"value"`
	Condition string      `yaml:"condition,omitempty"` // Optional guard
}

// BaselineConfig defines requirements for baseline runs.
type BaselineConfig struct {
	RequiredStates  []string `yaml:"required_states"`
	MinTimePerState Duration `yaml:"min_time_per_state"`
	RequiredEvents  []string `yaml:"required_events"`
	TotalDuration   Duration `yaml:"total_duration"`
	ExportPCAP      bool     `yaml:"export_pcap"`
	ExportSummaries bool     `yaml:"export_summaries"`
}

// TortureConfig defines stress testing parameters.
type TortureConfig struct {
	LatencySpikes *LatencyConfig `yaml:"latency_spikes,omitempty"`
	BurstAmplify  float64        `yaml:"burst_amplify,omitempty"`  // 1.0 = normal, 2.0 = double
	DropRate      float64        `yaml:"drop_rate,omitempty"`      // 0.0 - 1.0
	ChunkedWrites bool           `yaml:"chunked_writes,omitempty"`
	TimingJitter  Duration       `yaml:"timing_jitter,omitempty"`
}

// LatencyConfig defines artificial latency injection.
type LatencyConfig struct {
	Probability float64  `yaml:"probability"` // 0.0 - 1.0
	MinDelay    Duration `yaml:"min_delay"`
	MaxDelay    Duration `yaml:"max_delay"`
}

// Duration is a string that parses to time.Duration (e.g., "30s", "5m", "100ms").
type Duration string

// Parse converts the Duration string to time.Duration.
func (d Duration) Parse() (time.Duration, error) {
	if d == "" {
		return 0, nil
	}
	return time.ParseDuration(string(d))
}

// MustParse converts the Duration string to time.Duration, panicking on error.
func (d Duration) MustParse() time.Duration {
	dur, err := d.Parse()
	if err != nil {
		panic(fmt.Sprintf("invalid duration %q: %v", d, err))
	}
	return dur
}

// ProfileInfo contains lightweight metadata for listing profiles.
type ProfileInfo struct {
	Path        string   `json:"path"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
	Personality string   `json:"personality"`
	EnableUDPIO bool     `json:"enable_udp_io"`
	RoleCount   int      `json:"role_count"`
	TagCount    int      `json:"tag_count"`
	StateCount  int      `json:"state_count"`
	Roles       []string `json:"roles"`
}

// Validate checks the profile for consistency and required fields.
func (p *Profile) Validate() error {
	if p.Metadata.Name == "" {
		return fmt.Errorf("profile metadata.name is required")
	}
	if p.Metadata.Personality != "adapter" && p.Metadata.Personality != "logix_like" {
		return fmt.Errorf("profile metadata.personality must be 'adapter' or 'logix_like', got %q", p.Metadata.Personality)
	}

	// Validate data model
	if p.Metadata.Personality == "logix_like" && len(p.DataModel.Tags) == 0 {
		return fmt.Errorf("logix_like profile requires at least one tag")
	}
	if p.Metadata.Personality == "adapter" && len(p.DataModel.Assemblies) == 0 {
		return fmt.Errorf("adapter profile requires at least one assembly")
	}

	// Validate state machine
	if p.StateMachine.InitialState == "" {
		return fmt.Errorf("state_machine.initial_state is required")
	}
	if _, ok := p.StateMachine.States[p.StateMachine.InitialState]; !ok {
		return fmt.Errorf("initial_state %q not found in states", p.StateMachine.InitialState)
	}

	// Validate transitions reference valid states
	for stateName, state := range p.StateMachine.States {
		for i, trans := range state.Transitions {
			if _, ok := p.StateMachine.States[trans.To]; !ok {
				return fmt.Errorf("state %q transition %d references unknown state %q", stateName, i, trans.To)
			}
		}
	}

	// Build set of valid tag/field names
	tagSet := make(map[string]bool)
	for _, tag := range p.DataModel.Tags {
		tagSet[tag.Name] = true
	}
	// For adapter profiles, field mappings are also valid tag references
	fieldSet := make(map[string]bool)
	for _, asm := range p.DataModel.Assemblies {
		for _, field := range asm.Fields {
			fieldSet[field.Name] = true
		}
	}

	// Validate field mappings don't exceed assembly bounds
	for _, asm := range p.DataModel.Assemblies {
		for _, field := range asm.Fields {
			maxOffset := field.ByteOffset
			switch field.Type {
			case "INT":
				maxOffset += 2
			case "DINT", "REAL":
				maxOffset += 4
			default: // BOOL, SINT
				maxOffset += 1
			}
			if maxOffset > asm.SizeBytes {
				return fmt.Errorf("assembly %q field %q exceeds assembly size (offset %d + size > %d)",
					asm.Name, field.Name, field.ByteOffset, asm.SizeBytes)
			}
		}
	}

	// Validate roles reference valid tags or field mappings
	for roleName, role := range p.Roles {
		for _, tagName := range role.ReadTags {
			if !tagSet[tagName] && !fieldSet[tagName] {
				return fmt.Errorf("role %q references unknown read tag %q", roleName, tagName)
			}
		}
		for _, tagName := range role.WriteTags {
			if !tagSet[tagName] && !fieldSet[tagName] {
				return fmt.Errorf("role %q references unknown write tag %q", roleName, tagName)
			}
		}
	}

	// Validate durations parse correctly
	for stateName, state := range p.StateMachine.States {
		if state.Duration != "" {
			if _, err := state.Duration.Parse(); err != nil {
				return fmt.Errorf("state %q has invalid duration %q: %w", stateName, state.Duration, err)
			}
		}
	}
	for roleName, role := range p.Roles {
		if role.PollInterval != "" {
			if _, err := role.PollInterval.Parse(); err != nil {
				return fmt.Errorf("role %q has invalid poll_interval %q: %w", roleName, role.PollInterval, err)
			}
		}
	}

	return nil
}

// GetTagByName returns a tag definition by name, or nil if not found.
func (p *Profile) GetTagByName(name string) *TagDefinition {
	for i := range p.DataModel.Tags {
		if p.DataModel.Tags[i].Name == name {
			return &p.DataModel.Tags[i]
		}
	}
	return nil
}

// GetAssemblyByName returns an assembly definition by name, or nil if not found.
func (p *Profile) GetAssemblyByName(name string) *AssemblyDefinition {
	for i := range p.DataModel.Assemblies {
		if p.DataModel.Assemblies[i].Name == name {
			return &p.DataModel.Assemblies[i]
		}
	}
	return nil
}

// GetFieldMapping returns the assembly and field mapping for a tag name, or nil if not found.
// This is used for adapter profiles where tags map to assembly bit/byte positions.
func (p *Profile) GetFieldMapping(tagName string) (*AssemblyDefinition, *FieldMapping) {
	for i := range p.DataModel.Assemblies {
		asm := &p.DataModel.Assemblies[i]
		for j := range asm.Fields {
			if asm.Fields[j].Name == tagName {
				return asm, &asm.Fields[j]
			}
		}
	}
	return nil, nil
}

// HasFieldMappings returns true if any assembly has field mappings defined.
func (p *Profile) HasFieldMappings() bool {
	for _, asm := range p.DataModel.Assemblies {
		if len(asm.Fields) > 0 {
			return true
		}
	}
	return false
}

// IsAdapterWithFieldMappings returns true if this is an adapter profile with field mappings.
func (p *Profile) IsAdapterWithFieldMappings() bool {
	return p.Metadata.Personality == "adapter" && p.HasFieldMappings()
}

// GetRole returns a role by name, or nil if not found.
func (p *Profile) GetRole(name string) *Role {
	if role, ok := p.Roles[name]; ok {
		return &role
	}
	return nil
}

// RoleNames returns the names of all defined roles.
func (p *Profile) RoleNames() []string {
	names := make([]string, 0, len(p.Roles))
	for name := range p.Roles {
		names = append(names, name)
	}
	return names
}

// StateNames returns the names of all defined states.
func (p *Profile) StateNames() []string {
	names := make([]string, 0, len(p.StateMachine.States))
	for name := range p.StateMachine.States {
		names = append(names, name)
	}
	return names
}

// WritableTagNames returns names of all writable tags.
func (p *Profile) WritableTagNames() []string {
	var names []string
	for _, tag := range p.DataModel.Tags {
		if tag.Writable {
			names = append(names, tag.Name)
		}
	}
	return names
}

// ToInfo creates a ProfileInfo summary.
func (p *Profile) ToInfo(path string) ProfileInfo {
	roles := make([]string, 0, len(p.Roles))
	for name := range p.Roles {
		roles = append(roles, name)
	}
	return ProfileInfo{
		Path:        path,
		Name:        p.Metadata.Name,
		Description: p.Metadata.Description,
		Version:     p.Metadata.Version,
		Personality: p.Metadata.Personality,
		EnableUDPIO: p.Metadata.EnableUDPIO,
		RoleCount:   len(p.Roles),
		TagCount:    len(p.DataModel.Tags) + len(p.DataModel.Assemblies),
		StateCount:  len(p.StateMachine.States),
		Roles:       roles,
	}
}
