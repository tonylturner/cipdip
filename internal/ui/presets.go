package ui

// ModePreset defines duration/interval presets for client runs.
type ModePreset struct {
	Name     string
	Duration int // seconds
	Interval int // milliseconds
}

// ModePresets contains the standard duration presets.
var ModePresets = []ModePreset{
	{"Quick", 30, 250},
	{"Standard", 300, 250},
	{"Extended", 1800, 250},
	{"Custom", 0, 0}, // User-defined
}
