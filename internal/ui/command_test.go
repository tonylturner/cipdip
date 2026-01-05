package ui

import "testing"

func TestBuildPcapReplayCommand(t *testing.T) {
	profile := Profile{
		Version: 1,
		Kind:    "pcap_replay",
		Name:    "replay-test",
		Spec: map[string]interface{}{
			"input":             "pcaps/stress/ENIP.pcap",
			"mode":              "app",
			"server_ip":         "10.0.0.10",
			"server_port":       44818,
			"include_responses": true,
			"interval_ms":       10,
		},
	}
	cmd, err := BuildCommand(profile)
	if err != nil {
		t.Fatalf("BuildCommand failed: %v", err)
	}
	if len(cmd.Args) == 0 || cmd.Args[0] != "cipdip" {
		t.Fatalf("unexpected command: %v", cmd.Args)
	}
	expectContains(t, cmd.Args, "--input")
	expectContains(t, cmd.Args, "pcaps/stress/ENIP.pcap")
	expectContains(t, cmd.Args, "--server-ip")
	expectContains(t, cmd.Args, "10.0.0.10")
}

func TestBuildBaselineCommand(t *testing.T) {
	profile := Profile{
		Version: 1,
		Kind:    "baseline",
		Name:    "baseline-test",
		Spec: map[string]interface{}{
			"output_dir": "baseline_captures",
			"duration":   5,
		},
	}
	cmd, err := BuildCommand(profile)
	if err != nil {
		t.Fatalf("BuildCommand failed: %v", err)
	}
	expectContains(t, cmd.Args, "baseline")
	expectContains(t, cmd.Args, "--output-dir")
	expectContains(t, cmd.Args, "baseline_captures")
}

func TestWriteRunArtifacts(t *testing.T) {
	runDir := t.TempDir()
	resolved := map[string]interface{}{
		"profile": "test",
	}
	summary := RunSummary{
		Status:   "ok",
		Command:  []string{"cipdip", "baseline"},
		ExitCode: 0,
	}
	if err := WriteRunArtifacts(runDir, resolved, summary.Command, "output", summary); err != nil {
		t.Fatalf("WriteRunArtifacts failed: %v", err)
	}
	formatted := FormatCommand(summary.Command)
	if formatted == "" {
		t.Fatalf("expected formatted command output")
	}
}

func expectContains(t *testing.T, args []string, value string) {
	t.Helper()
	for _, arg := range args {
		if arg == value {
			return
		}
	}
	t.Fatalf("expected %q in %v", value, args)
}
