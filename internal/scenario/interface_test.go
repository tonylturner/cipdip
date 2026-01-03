package scenario

import "testing"

func TestGetScenarioKnown(t *testing.T) {
	names := []string{
		"baseline",
		"mixed",
		"stress",
		"churn",
		"io",
		"edge_valid",
		"edge_vendor",
		"rockwell",
		"vendor_variants",
		"mixed_state",
		"unconnected_send",
		"firewall_hirschmann",
		"firewall_moxa",
		"firewall_dynics",
		"firewall_pack",
	}
	for _, name := range names {
		if _, err := GetScenario(name); err != nil {
			t.Fatalf("GetScenario(%s) error: %v", name, err)
		}
	}
}

func TestGetScenarioUnknown(t *testing.T) {
	if _, err := GetScenario("unknown_scenario"); err == nil {
		t.Fatalf("expected error for unknown scenario")
	}
}
