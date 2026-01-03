package ui

import (
	"fmt"
	"strings"
)

// WizardOptions defines minimal inputs for non-interactive wizard profiles.
type WizardOptions struct {
	Kind        string
	Name        string
	Input       string
	Preset      string
	Mode        string
	ServerIP    string
	ServerPort  int
	OutputDir   string
	Duration    int
	Personality string
	Target      string
	CatalogKey  string
	IP          string
	Port        int
	Service     string
	Class       string
	Instance    string
	Attribute   string
	PayloadHex  string
}

// BuildWizardProfile creates a profile from minimal wizard options.
func BuildWizardProfile(opts WizardOptions) (Profile, error) {
	kind := strings.ToLower(strings.TrimSpace(opts.Kind))
	name := opts.Name
	if name == "" {
		name = kind
	}
	switch kind {
	case "pcap-replay", "pcap_replay":
		spec := map[string]interface{}{}
		if opts.Input != "" {
			spec["input"] = opts.Input
		}
		if opts.Preset != "" {
			spec["preset"] = opts.Preset
		}
		if opts.ServerIP != "" {
			spec["server_ip"] = opts.ServerIP
		}
		if opts.ServerPort > 0 {
			spec["server_port"] = opts.ServerPort
		}
		if opts.Mode != "" {
			spec["mode"] = opts.Mode
		}
		if opts.Input == "" && opts.Preset == "" {
			return Profile{}, fmt.Errorf("pcap-replay wizard requires input or preset")
		}
		return Profile{Version: 1, Kind: "pcap_replay", Name: name, Spec: spec}, nil
	case "baseline":
		spec := map[string]interface{}{}
		if opts.OutputDir != "" {
			spec["output_dir"] = opts.OutputDir
		}
		if opts.Duration > 0 {
			spec["duration"] = opts.Duration
		}
		return Profile{Version: 1, Kind: "baseline", Name: name, Spec: spec}, nil
	case "server":
		spec := map[string]interface{}{}
		if opts.Personality != "" {
			spec["personality"] = opts.Personality
		}
		if opts.Mode != "" {
			spec["mode"] = opts.Mode
		}
		if opts.Target != "" {
			spec["target"] = opts.Target
		}
		if opts.ServerPort > 0 {
			spec["listen_port"] = opts.ServerPort
		}
		return Profile{Version: 1, Kind: "server", Name: name, Spec: spec}, nil
	case "single":
		spec := map[string]interface{}{}
		if opts.IP != "" {
			spec["ip"] = opts.IP
		}
		if opts.Port > 0 {
			spec["port"] = opts.Port
		}
		if opts.Service != "" {
			spec["service"] = opts.Service
		}
		if opts.Class != "" {
			spec["class"] = opts.Class
		}
		if opts.Instance != "" {
			spec["instance"] = opts.Instance
		}
		if opts.Attribute != "" {
			spec["attribute"] = opts.Attribute
		}
		if opts.PayloadHex != "" {
			spec["payload_hex"] = opts.PayloadHex
		}
		return Profile{Version: 1, Kind: "single", Name: name, Spec: spec}, nil
	default:
		return Profile{}, fmt.Errorf("unknown wizard kind: %s", opts.Kind)
	}
}
