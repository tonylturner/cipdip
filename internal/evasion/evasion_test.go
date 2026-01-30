package evasion

import (
	"testing"
	"time"
)

// --- TCP Segmentation tests ---

func TestPlanTCPSegmentationMidHeader(t *testing.T) {
	payload := make([]byte, 48) // Larger than ENIP header
	for i := range payload {
		payload[i] = byte(i)
	}

	plan, err := PlanTCPSegmentation(payload, TCPSegmentConfig{
		SplitPoint: SplitMidENIPHeader,
	})
	if err != nil {
		t.Fatalf("PlanTCPSegmentation: %v", err)
	}
	if len(plan.Segments) != 2 {
		t.Fatalf("segments = %d, want 2", len(plan.Segments))
	}
	if len(plan.Segments[0].Data) != 12 {
		t.Errorf("seg0 len = %d, want 12", len(plan.Segments[0].Data))
	}
	if len(plan.Segments[1].Data) != 36 {
		t.Errorf("seg1 len = %d, want 36", len(plan.Segments[1].Data))
	}
}

func TestPlanTCPSegmentationBetweenENIPCPF(t *testing.T) {
	payload := make([]byte, 48)
	plan, err := PlanTCPSegmentation(payload, TCPSegmentConfig{
		SplitPoint: SplitBetweenENIPCPF,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Segments) != 2 {
		t.Fatalf("segments = %d, want 2", len(plan.Segments))
	}
	if len(plan.Segments[0].Data) != ENIPHeaderSize {
		t.Errorf("seg0 len = %d, want %d", len(plan.Segments[0].Data), ENIPHeaderSize)
	}
}

func TestPlanTCPSegmentationEveryNBytes(t *testing.T) {
	payload := make([]byte, 20)
	plan, err := PlanTCPSegmentation(payload, TCPSegmentConfig{
		SplitPoint:  SplitEveryNBytes,
		SplitOffset: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Segments) != 4 { // 0-5, 5-10, 10-15, 15-20
		t.Fatalf("segments = %d, want 4", len(plan.Segments))
	}
	for _, seg := range plan.Segments {
		if len(seg.Data) != 5 {
			t.Errorf("segment len = %d, want 5", len(seg.Data))
		}
	}
}

func TestPlanTCPSegmentationWithDelay(t *testing.T) {
	payload := make([]byte, 48)
	plan, err := PlanTCPSegmentation(payload, TCPSegmentConfig{
		SplitPoint:    SplitBetweenENIPCPF,
		InterSegDelay: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.InterSegDelay != 100*time.Millisecond {
		t.Errorf("delay = %v, want 100ms", plan.InterSegDelay)
	}
}

func TestPlanTCPSegmentationEmpty(t *testing.T) {
	_, err := PlanTCPSegmentation(nil, TCPSegmentConfig{})
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
}

func TestPlanTCPSegmentationSmallPayload(t *testing.T) {
	// Payload smaller than any split point → single segment
	payload := make([]byte, 4)
	plan, err := PlanTCPSegmentation(payload, TCPSegmentConfig{
		SplitPoint: SplitMidENIPHeader,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Segments) != 1 {
		t.Fatalf("segments = %d, want 1 (no valid split point)", len(plan.Segments))
	}
}

func TestSplitAtBoundaries(t *testing.T) {
	payload := make([]byte, 80)
	plan := SplitAtBoundaries(payload, 50*time.Millisecond)
	// Should have multiple segments (at least 3-4 boundaries)
	if len(plan.Segments) < 3 {
		t.Errorf("segments = %d, want >= 3", len(plan.Segments))
	}
	// Verify total data equals original
	total := 0
	for _, seg := range plan.Segments {
		total += len(seg.Data)
	}
	if total != 80 {
		t.Errorf("total bytes = %d, want 80", total)
	}
}

// --- IP Fragmentation tests ---

func TestPlanIPFragmentation(t *testing.T) {
	payload := make([]byte, 64)
	for i := range payload {
		payload[i] = byte(i)
	}

	plan, err := PlanIPFragmentation(payload, IPFragmentConfig{
		FragmentSize: 16,
	})
	if err != nil {
		t.Fatalf("PlanIPFragmentation: %v", err)
	}
	if len(plan.Fragments) != 4 { // 64/16 = 4
		t.Fatalf("fragments = %d, want 4", len(plan.Fragments))
	}
	// Last fragment should not have MF flag
	if plan.Fragments[3].MF {
		t.Error("last fragment should not have MF flag")
	}
	// Other fragments should have MF
	for i := 0; i < 3; i++ {
		if !plan.Fragments[i].MF {
			t.Errorf("fragment %d should have MF flag", i)
		}
	}
}

func TestPlanIPFragmentationReverse(t *testing.T) {
	payload := make([]byte, 32)
	plan, err := PlanIPFragmentation(payload, IPFragmentConfig{
		FragmentSize: 16,
		Reverse:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Fragments) != 2 {
		t.Fatalf("fragments = %d, want 2", len(plan.Fragments))
	}
	// In reverse order, the last fragment (highest offset) comes first
	if plan.Fragments[0].Offset < plan.Fragments[1].Offset {
		t.Error("expected reverse order: first fragment should have higher offset")
	}
}

func TestPlanIPFragmentationOverlap(t *testing.T) {
	payload := make([]byte, 32)
	plan, err := PlanIPFragmentation(payload, IPFragmentConfig{
		FragmentSize: 16,
		Overlap:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Should have 3 fragments: overlap decoy + 2 real
	if len(plan.Fragments) != 3 {
		t.Fatalf("fragments = %d, want 3", len(plan.Fragments))
	}
	if plan.Fragments[0].Label != "overlap_decoy" {
		t.Errorf("first fragment label = %q, want overlap_decoy", plan.Fragments[0].Label)
	}
}

func TestPlanIPFragmentationDecoys(t *testing.T) {
	payload := make([]byte, 16)
	plan, err := PlanIPFragmentation(payload, IPFragmentConfig{
		FragmentSize: 8,
		DecoyCount:   3,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 3 decoys + 2 real fragments
	if len(plan.Fragments) != 5 {
		t.Fatalf("fragments = %d, want 5", len(plan.Fragments))
	}
}

func TestPlanIPFragmentationEmpty(t *testing.T) {
	_, err := PlanIPFragmentation(nil, IPFragmentConfig{})
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
}

func TestTotalFragments(t *testing.T) {
	tests := []struct {
		payload, frag, want int
	}{
		{64, 16, 4},
		{64, 8, 8},
		{65, 16, 5},
		{8, 8, 1},
	}
	for _, tt := range tests {
		got := TotalFragments(tt.payload, tt.frag)
		if got != tt.want {
			t.Errorf("TotalFragments(%d, %d) = %d, want %d", tt.payload, tt.frag, got, tt.want)
		}
	}
}

// --- Connection Fuzz tests ---

func TestBuildFuzzActionsAll(t *testing.T) {
	cfg := ConnFuzzConfig{
		SkipRegisterSession:     true,
		DuplicateSessionID:      true,
		ConflictingConnectionID: true,
		OutOfOrderTransitions:   true,
		StaleSessionReuse:       true,
	}
	actions := BuildFuzzActions(cfg)
	if len(actions) < 6 { // 1+1+1+3+1
		t.Errorf("actions = %d, want >= 6", len(actions))
	}
	// Verify all have non-empty names and payloads
	for _, a := range actions {
		if a.Name == "" {
			t.Error("action has empty name")
		}
		if len(a.Payload) == 0 {
			t.Errorf("action %q has empty payload", a.Name)
		}
	}
}

func TestBuildFuzzActionsEmpty(t *testing.T) {
	actions := BuildFuzzActions(ConnFuzzConfig{})
	if len(actions) != 0 {
		t.Errorf("actions = %d, want 0 for empty config", len(actions))
	}
}

func TestFuzzActionENIPHeader(t *testing.T) {
	cfg := ConnFuzzConfig{SkipRegisterSession: true}
	actions := BuildFuzzActions(cfg)
	if len(actions) != 1 {
		t.Fatal("expected 1 action")
	}
	// Verify it's a valid ENIP header (24 bytes minimum)
	if len(actions[0].Payload) < 24 {
		t.Errorf("payload len = %d, want >= 24", len(actions[0].Payload))
	}
}

// --- Anomaly tests ---

func TestBuildAnomalyPacketsAll(t *testing.T) {
	cfg := AnomalyConfig{
		ZeroLengthPayload:   true,
		MaxLengthEPATH:      true,
		ReservedServiceCodes: true,
		UnusualCPFItems:     true,
		MaxConnectionParams: true,
	}
	packets := BuildAnomalyPackets(cfg, 0x12345678)
	// 1 zero + 1 max_epath + 5 reserved_services + 3 unusual_cpf + 1 max_params = 11
	if len(packets) < 10 {
		t.Errorf("packets = %d, want >= 10", len(packets))
	}
	for _, p := range packets {
		if p.Name == "" {
			t.Error("packet has empty name")
		}
		if len(p.Payload) < 24 {
			t.Errorf("packet %q payload len = %d, want >= 24 (ENIP header)", p.Name, len(p.Payload))
		}
	}
}

func TestBuildAnomalyPacketsEmpty(t *testing.T) {
	packets := BuildAnomalyPackets(AnomalyConfig{}, 0)
	if len(packets) != 0 {
		t.Errorf("packets = %d, want 0", len(packets))
	}
}

// --- Timing tests ---

func TestPlanSlowRate(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5}
	plan := PlanSlowRate(payload, 100*time.Millisecond)
	if len(plan.Steps) != 5 {
		t.Fatalf("steps = %d, want 5", len(plan.Steps))
	}
	// First step has no delay
	if plan.Steps[0].Delay != 0 {
		t.Errorf("first step delay = %v, want 0", plan.Steps[0].Delay)
	}
	// Other steps have 100ms delay
	for i := 1; i < len(plan.Steps); i++ {
		if plan.Steps[i].Delay != 100*time.Millisecond {
			t.Errorf("step %d delay = %v, want 100ms", i, plan.Steps[i].Delay)
		}
	}
	if plan.TotalBytes() != 5 {
		t.Errorf("TotalBytes = %d, want 5", plan.TotalBytes())
	}
}

func TestPlanVariableTiming(t *testing.T) {
	payload := make([]byte, 100)
	cfg := TimingConfig{
		VariableTiming: true,
		MinDelay:       10 * time.Millisecond,
		MaxDelay:       50 * time.Millisecond,
	}
	plan := PlanVariableTiming(payload, cfg)
	if len(plan.Steps) < 2 {
		t.Fatalf("steps = %d, want >= 2", len(plan.Steps))
	}
	if plan.TotalBytes() != 100 {
		t.Errorf("TotalBytes = %d, want 100", plan.TotalBytes())
	}
	// Verify delays are within bounds
	for i := 1; i < len(plan.Steps); i++ {
		d := plan.Steps[i].Delay
		if d < cfg.MinDelay || d > cfg.MaxDelay {
			t.Errorf("step %d delay = %v, not in [%v, %v]", i, d, cfg.MinDelay, cfg.MaxDelay)
		}
	}
}

func TestPlanKeepaliveAbuse(t *testing.T) {
	payload := make([]byte, 200)
	cfg := TimingConfig{
		KeepaliveAbuse:    true,
		KeepaliveInterval: 5 * time.Millisecond,
	}
	plan := PlanKeepaliveAbuse(payload, cfg)

	// Should have both keepalive and data steps
	hasKeepalive := false
	hasData := false
	totalData := 0
	for _, step := range plan.Steps {
		if step.Label == "keepalive" {
			hasKeepalive = true
		}
		if step.Label == "data" {
			hasData = true
			totalData += len(step.Data)
		}
	}
	if !hasKeepalive {
		t.Error("no keepalive steps found")
	}
	if !hasData {
		t.Error("no data steps found")
	}
	if totalData != 200 {
		t.Errorf("total data bytes = %d, want 200", totalData)
	}
}

func TestTimingPlanTotalDelay(t *testing.T) {
	plan := &TimingPlan{
		Steps: []TimingStep{
			{Delay: 0},
			{Delay: 100 * time.Millisecond},
			{Delay: 200 * time.Millisecond},
		},
	}
	if plan.TotalDelay() != 300*time.Millisecond {
		t.Errorf("TotalDelay = %v, want 300ms", plan.TotalDelay())
	}
}
