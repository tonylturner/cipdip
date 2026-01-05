package ui

import "testing"

func TestBuildWizardProfilePcapReplay(t *testing.T) {
	profile, err := BuildWizardProfile(WizardOptions{Kind: "pcap-replay", Input: "pcaps/test.pcap", Mode: "raw"})
	if err != nil {
		t.Fatalf("BuildWizardProfile failed: %v", err)
	}
	if profile.Kind != "pcap_replay" {
		t.Fatalf("expected pcap_replay kind, got %s", profile.Kind)
	}
}

func TestBuildWizardProfileBaseline(t *testing.T) {
	profile, err := BuildWizardProfile(WizardOptions{Kind: "baseline", OutputDir: "out", Duration: 5})
	if err != nil {
		t.Fatalf("BuildWizardProfile failed: %v", err)
	}
	if profile.Kind != "baseline" {
		t.Fatalf("expected baseline kind, got %s", profile.Kind)
	}
}

func TestBuildWizardProfileSingle(t *testing.T) {
	profile, err := BuildWizardProfile(WizardOptions{
		Kind:     "single",
		IP:       "10.0.0.50",
		Port:     44818,
		Service:  "0x0E",
		Class:    "0x01",
		Instance: "0x01",
	})
	if err != nil {
		t.Fatalf("BuildWizardProfile failed: %v", err)
	}
	if profile.Kind != "single" {
		t.Fatalf("expected single kind, got %s", profile.Kind)
	}
	if profile.Spec["service"] == "" {
		t.Fatalf("expected service in spec")
	}
}
