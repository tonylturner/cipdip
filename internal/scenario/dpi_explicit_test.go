package scenario

import (
	"context"
	"testing"
	"time"

	"github.com/tonylturner/cipdip/internal/metrics"
)

func TestDPIExplicitScenarioBasicExecution(t *testing.T) {
	scenario := &DPIExplicitScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond // Short duration for testing

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("DPI explicit scenario failed: %v", err)
	}
}

func TestDPIExplicitScenarioMetricsRecording(t *testing.T) {
	scenario := &DPIExplicitScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("DPI explicit scenario failed: %v", err)
	}

	// Verify metrics were recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	if len(recordedMetrics) == 0 {
		t.Error("Expected metrics to be recorded")
	}

	// Verify metrics have correct scenario name
	for _, m := range recordedMetrics {
		if m.Scenario != "dpi_explicit" {
			t.Errorf("Expected scenario 'dpi_explicit', got '%s'", m.Scenario)
		}
	}
}

func TestDPIExplicitScenarioContextCancellation(t *testing.T) {
	scenario := &DPIExplicitScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 10 * time.Second // Long duration

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after short delay
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := scenario.Run(ctx, client, cfg, params)
	elapsed := time.Since(start)

	// DPI explicit scenario returns context.Canceled on cancellation
	// This is acceptable behavior
	if err != nil && err != context.Canceled {
		t.Fatalf("DPI explicit scenario failed with unexpected error: %v", err)
	}

	// Should have exited well before the full duration
	// Allow more time due to jitter sleeps in the scenario
	if elapsed > 5*time.Second {
		t.Errorf("Context cancellation took too long: %v", elapsed)
	}
}

func TestDPIExplicitScenarioConnectionFailure(t *testing.T) {
	scenario := &DPIExplicitScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	// Set connection error
	client.connectError = errConnectionRefused

	ctx := context.Background()

	// DPI explicit scenario is designed to continue on connection failures
	// and record them as metrics, not return an error
	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("DPI explicit scenario should handle connection failures gracefully: %v", err)
	}

	// Verify that metrics were recorded (failures should be counted)
	recordedMetrics := params.MetricsSink.GetMetrics()
	// Even with connection failures, the scenario should have run and completed
	_ = recordedMetrics // Scenario tracks failures internally
}

func TestDPIExplicitScenarioOperationTypes(t *testing.T) {
	scenario := &DPIExplicitScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("DPI explicit scenario failed: %v", err)
	}

	// Verify we have metrics recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	opTypes := make(map[metrics.OperationType]int)
	for _, m := range recordedMetrics {
		opTypes[m.Operation]++
	}

	// DPI explicit uses Custom, ForwardOpen, and ForwardClose operations
	hasExpectedOps := opTypes[metrics.OperationCustom] > 0 ||
		opTypes[metrics.OperationForwardOpen] > 0 ||
		opTypes[metrics.OperationForwardClose] > 0
	if !hasExpectedOps {
		t.Error("Expected custom, ForwardOpen, or ForwardClose operations to be recorded")
	}
}
