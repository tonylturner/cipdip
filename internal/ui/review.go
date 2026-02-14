package ui

import (
	"fmt"
	"strings"
)

// RenderReviewScreen formats a review screen for the given profile and command.
func RenderReviewScreen(profile Profile, command CommandSpec) string {
	lines := []string{
		"Review & Execute",
		"Command:",
		FormatCommand(command.Args),
		"",
		"Effective Behavior:",
	}

	behavior := describeBehavior(profile)
	if len(behavior) == 0 {
		behavior = []string{"- No additional behavior details"}
	}
	lines = append(lines, behavior...)

	lines = append(lines, "", "Actions:", "[Run] [Save Config] [Copy Command] [Back]")
	return strings.Join(lines, "\n")
}

func describeBehavior(profile Profile) []string {
	switch strings.ToLower(profile.Kind) {
	case "pcap_replay":
		mode := getString(profile.Spec, "mode")
		arp := getString(profile.Spec, "arp")
		rewrite := getString(profile.Spec, "rewrite")
		return buildBehaviorLines("Raw replay", mode, arp, rewrite)
	case "baseline":
		return []string{"- Baseline suite", "- Scenarios + server personalities"}
	case "server":
		mode := getString(profile.Spec, "mode")
		target := getString(profile.Spec, "target")
		items := []string{"- Server emulator"}
		if mode != "" {
			items = append(items, fmt.Sprintf("- Mode: %s", mode))
		}
		if target != "" {
			items = append(items, fmt.Sprintf("- Target: %s", target))
		}
		return items
	default:
		if strings.ToLower(profile.Kind) == "single" {
			items := []string{}
			if name := strings.TrimSpace(profile.Name); name != "" && name != "single" {
				items = append(items, fmt.Sprintf("- Catalog: %s", name))
			}
			return items
		}
		return nil
	}
}

func buildBehaviorLines(defaultMode, mode, arp, rewrite string) []string {
	items := []string{}
	if mode != "" {
		items = append(items, fmt.Sprintf("- Mode: %s", mode))
	} else if defaultMode != "" {
		items = append(items, fmt.Sprintf("- %s", defaultMode))
	}
	if arp != "" {
		items = append(items, fmt.Sprintf("- ARP: %s", arp))
	}
	if rewrite != "" {
		items = append(items, fmt.Sprintf("- Rewrite: %s", rewrite))
	}
	return items
}
