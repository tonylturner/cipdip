package main

import (
	"strings"

	cipclient "github.com/tturner/cipdip/internal/cip/client"
)

func parseProfileFlag(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func mergeProfiles(existing, extra []string) []string {
	merged := append([]string{}, existing...)
	merged = append(merged, extra...)
	return cipclient.NormalizeCIPProfiles(merged)
}


