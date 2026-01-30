package scenario

import (
	"context"
	"testing"
	"time"
)

func TestEvasionSegmentScenarioBasicExecution(t *testing.T) {
	scenario := &EvasionSegmentScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Evasion segment scenario failed: %v", err)
	}
}

func TestEvasionSegmentScenarioMetrics(t *testing.T) {
	scenario := &EvasionSegmentScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Evasion segment scenario failed: %v", err)
	}

	recordedMetrics := params.MetricsSink.GetMetrics()
	for _, m := range recordedMetrics {
		if m.Scenario != "evasion_segment" {
			t.Errorf("Expected scenario 'evasion_segment', got '%s'", m.Scenario)
		}
	}
}

func TestEvasionSegmentScenarioContextCancellation(t *testing.T) {
	scenario := &EvasionSegmentScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 10 * time.Second

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := scenario.Run(ctx, client, cfg, params)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Evasion segment scenario failed: %v", err)
	}

	if elapsed > 2*time.Second {
		t.Errorf("Context cancellation took too long: %v", elapsed)
	}
}

func TestEvasionFuzzScenarioBasicExecution(t *testing.T) {
	scenario := &EvasionFuzzScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Evasion fuzz scenario failed: %v", err)
	}
}

func TestEvasionFuzzScenarioMetrics(t *testing.T) {
	scenario := &EvasionFuzzScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Evasion fuzz scenario failed: %v", err)
	}

	recordedMetrics := params.MetricsSink.GetMetrics()
	for _, m := range recordedMetrics {
		if m.Scenario != "evasion_fuzz" {
			t.Errorf("Expected scenario 'evasion_fuzz', got '%s'", m.Scenario)
		}
	}
}

func TestEvasionAnomalyScenarioBasicExecution(t *testing.T) {
	scenario := &EvasionAnomalyScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Evasion anomaly scenario failed: %v", err)
	}
}

func TestEvasionAnomalyScenarioMetrics(t *testing.T) {
	scenario := &EvasionAnomalyScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Evasion anomaly scenario failed: %v", err)
	}

	recordedMetrics := params.MetricsSink.GetMetrics()
	for _, m := range recordedMetrics {
		if m.Scenario != "evasion_anomaly" {
			t.Errorf("Expected scenario 'evasion_anomaly', got '%s'", m.Scenario)
		}
	}
}

func TestEvasionTimingScenarioBasicExecution(t *testing.T) {
	scenario := &EvasionTimingScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Evasion timing scenario failed: %v", err)
	}
}

func TestEvasionTimingScenarioMetrics(t *testing.T) {
	scenario := &EvasionTimingScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Evasion timing scenario failed: %v", err)
	}

	recordedMetrics := params.MetricsSink.GetMetrics()
	for _, m := range recordedMetrics {
		if m.Scenario != "evasion_timing" {
			t.Errorf("Expected scenario 'evasion_timing', got '%s'", m.Scenario)
		}
	}
}

func TestEvasionTimingScenarioContextCancellation(t *testing.T) {
	scenario := &EvasionTimingScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 10 * time.Second

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := scenario.Run(ctx, client, cfg, params)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Evasion timing scenario failed: %v", err)
	}

	if elapsed > 2*time.Second {
		t.Errorf("Context cancellation took too long: %v", elapsed)
	}
}
