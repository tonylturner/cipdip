package ui

import (
	"strings"
	"testing"
)

func TestRenderReviewScreen(t *testing.T) {
	profile := Profile{
		Version: 1,
		Kind:    "pcap_replay",
		Name:    "replay",
		Spec: map[string]interface{}{
			"mode":    "raw",
			"arp":     "prime",
			"rewrite": "auto",
		},
	}
	cmd := CommandSpec{Args: []string{"cipdip", "pcap-replay", "--mode", "raw"}}
	output := RenderReviewScreen(profile, cmd)
	expectContainsString(t, output, "Review & Execute")
	expectContainsString(t, output, "cipdip pcap-replay --mode raw")
	expectContainsString(t, output, "- Mode: raw")
	expectContainsString(t, output, "- ARP: prime")
	expectContainsString(t, output, "- Rewrite: auto")
}

func expectContainsString(t *testing.T, output string, value string) {
	t.Helper()
	if !strings.Contains(output, value) {
		t.Fatalf("expected %q in output:\n%s", value, output)
	}
}
