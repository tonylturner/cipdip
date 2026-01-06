package pcap

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

var replayPresets = map[string][]string{
	"cl5000eip:firmware-change":                   {"CL5000EIP-Firmware-Change.pcap"},
	"cl5000eip:firmware-change-failure":           {"CL5000EIP-Firmware-Change-Failure.pcap"},
	"cl5000eip:software-download":                 {"CL5000EIP-Software-Download.pcap"},
	"cl5000eip:software-download-failure":         {"CL5000EIP-Software-Download-Failure.pcap"},
	"cl5000eip:software-upload":                   {"CL5000EIP-Software-Upload.pcap"},
	"cl5000eip:software-upload-failure":           {"CL5000EIP-Software-Upload-Failure.pcap"},
	"cl5000eip:reboot-or-restart":                 {"CL5000EIP-Reboot-or-Restart.pcap"},
	"cl5000eip:change-date-attempt":               {"CL5000EIP-Change-Date-Attempt.pcap"},
	"cl5000eip:change-time-attempt":               {"CL5000EIP-Change-Time-Attempt.pcap"},
	"cl5000eip:change-port-configuration-attempt": {"CL5000EIP-Change-Port-Configuration-Attempt.pcap"},
	"cl5000eip:control-protocol-change-attempt":   {"CL5000EIP-Control-Protocol-Change-Attempt.pcap"},
	"cl5000eip:ip-address-change-attempt":         {"CL5000EIP-IP-Address-Change-Attempt.pcap"},
	"cl5000eip:lock-plc-attempt":                  {"CL5000EIP-Lock-PLC-Attempt.pcap"},
	"cl5000eip:unlock-plc-attempt":                {"CL5000EIP-Unlock-PLC-Attempt.pcap"},
	"cl5000eip:remote-mode-change-attempt":        {"CL5000EIP-Remote-Mode-Change-Attempt.pcap"},
	"cl5000eip:view-device-status":                {"CL5000EIP-View-Device-Status.pcap"},
}

var replayPresetGroups = map[string][]string{
	"cl5000eip": {"CL5000EIP-"},
}

func ReplayPresetNames() []string {
	names := make([]string, 0, len(replayPresets))
	for name := range replayPresets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func ReplayPresetGroups() []string {
	names := make([]string, 0, len(replayPresetGroups))
	for name := range replayPresetGroups {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func ResolveReplayPreset(preset, root string, allowMultiple bool) ([]string, error) {
	preset = strings.ToLower(strings.TrimSpace(preset))
	if preset == "" {
		return nil, fmt.Errorf("preset is empty")
	}

	files, err := CollectPcapFiles(root)
	if err != nil {
		return nil, err
	}

	if preset == "cl5000eip" || preset == "cl5000eip:all" {
		matches := filterPresetMatches(files, replayPresetGroups["cl5000eip"], true)
		if len(matches) == 0 {
			return nil, fmt.Errorf("no CL5000EIP pcaps found under %s", root)
		}
		return matches, nil
	}

	patterns, ok := replayPresets[preset]
	if !ok {
		return nil, fmt.Errorf("unknown preset '%s'; use --list-presets", preset)
	}

	matches := filterPresetMatches(files, patterns, allowMultiple)
	if len(matches) == 0 {
		return nil, fmt.Errorf("preset '%s' not found under %s", preset, root)
	}
	return matches, nil
}

func filterPresetMatches(files []string, patterns []string, allowMultiple bool) []string {
	matches := make([]string, 0, len(patterns))
	for _, file := range files {
		base := filepath.Base(file)
		for _, pattern := range patterns {
			if strings.HasPrefix(pattern, "CL5000EIP-") && strings.HasPrefix(base, pattern) {
				matches = append(matches, file)
				break
			}
			if strings.EqualFold(base, pattern) {
				matches = append(matches, file)
				break
			}
		}
		if len(matches) > 0 && !allowMultiple {
			return matches[:1]
		}
	}
	return matches
}
