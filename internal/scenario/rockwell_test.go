package scenario

import (
	"context"
	"testing"
	"time"

	"github.com/tonylturner/cipdip/internal/metrics"
)

func TestRockwellScenarioBasicExecution(t *testing.T) {
	scenario := &RockwellScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Rockwell scenario failed: %v", err)
	}
}

func TestRockwellScenarioMetricsRecording(t *testing.T) {
	scenario := &RockwellScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Rockwell scenario failed: %v", err)
	}

	// Verify metrics were recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	if len(recordedMetrics) == 0 {
		t.Error("Expected metrics to be recorded")
	}

	// Verify metrics have correct scenario name
	for _, m := range recordedMetrics {
		if m.Scenario != "rockwell" {
			t.Errorf("Expected scenario 'rockwell', got '%s'", m.Scenario)
		}
	}
}

func TestRockwellScenarioOperationTypes(t *testing.T) {
	scenario := &RockwellScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Rockwell scenario failed: %v", err)
	}

	// Verify we have custom operations (Rockwell services are custom)
	recordedMetrics := params.MetricsSink.GetMetrics()
	opTypes := make(map[metrics.OperationType]int)
	for _, m := range recordedMetrics {
		opTypes[m.Operation]++
	}

	// Rockwell should include custom operations
	if opTypes[metrics.OperationCustom] == 0 {
		t.Error("Expected custom operations to be recorded")
	}
}

func TestRockwellScenarioContextCancellation(t *testing.T) {
	scenario := &RockwellScenario{}
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
		t.Fatalf("Rockwell scenario failed: %v", err)
	}

	if elapsed > 2*time.Second {
		t.Errorf("Context cancellation took too long: %v", elapsed)
	}
}

func TestRockwellScenarioConnectionFailure(t *testing.T) {
	scenario := &RockwellScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()

	client.connectError = errConnectionRefused

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err == nil {
		t.Error("Expected error on connection failure")
	}
}

func TestRockwellScenarioWithENBTProfile(t *testing.T) {
	scenario := &RockwellScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	cfg.Protocol.Variant = "rockwell_enbt"
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Rockwell scenario with ENBT profile failed: %v", err)
	}

	// Verify metrics were recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	if len(recordedMetrics) == 0 {
		t.Error("Expected metrics to be recorded")
	}
}

func TestRockwellScenarioDefaultTargets(t *testing.T) {
	scenario := &RockwellScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	// Don't set any edge targets - should use defaults
	cfg.EdgeTargets = nil
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Rockwell scenario with default targets failed: %v", err)
	}

	// Should have recorded metrics from default targets
	recordedMetrics := params.MetricsSink.GetMetrics()
	if len(recordedMetrics) == 0 {
		t.Error("Expected metrics from default targets")
	}
}
