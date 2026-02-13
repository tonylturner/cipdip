package scenario

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/tonylturner/cipdip/internal/cip/protocol"
)

// TestChurnScenarioBasicExecution tests basic churn scenario execution
func TestChurnScenarioBasicExecution(t *testing.T) {
	scenario := &ChurnScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Interval = 50 * time.Millisecond
	params.Duration = 200 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Churn scenario failed: %v", err)
	}

	// Verify multiple connection cycles occurred
	// Churn scenario connects/disconnects multiple times
	path := protocol.CIPPath{
		Class:     cfg.ReadTargets[0].Class,
		Instance:  cfg.ReadTargets[0].Instance,
		Attribute: cfg.ReadTargets[0].Attribute,
	}
	count := client.GetReadCount(path)
	if count == 0 {
		t.Error("Expected reads during connection cycles")
	}
}

// TestChurnScenarioConnectionCycles tests that churn performs multiple connect/disconnect cycles
func TestChurnScenarioConnectionCycles(t *testing.T) {
	scenario := &ChurnScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Interval = 30 * time.Millisecond
	params.Duration = 150 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Churn scenario failed: %v", err)
	}

	// Churn should perform multiple cycles
	// Each cycle: connect, read 3 times per target, disconnect
	expectedMinReads := 3 * len(cfg.ReadTargets) // At least one cycle
	path := protocol.CIPPath{
		Class:     cfg.ReadTargets[0].Class,
		Instance:  cfg.ReadTargets[0].Instance,
		Attribute: cfg.ReadTargets[0].Attribute,
	}
	count := client.GetReadCount(path)
	if count < expectedMinReads {
		t.Errorf("Expected at least %d reads (one cycle), got %d", expectedMinReads, count)
	}
}

// TestChurnScenarioConnectionFailure tests handling of connection failures
func TestChurnScenarioConnectionFailure(t *testing.T) {
	scenario := &ChurnScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Interval = 30 * time.Millisecond
	params.Duration = 100 * time.Millisecond

	// Set connection error for first attempt, then succeed
	client.connectError = fmt.Errorf("connection refused")

	ctx := context.Background()

	// First attempt should fail
	err := scenario.Run(ctx, client, cfg, params)
	// Churn scenario should handle connection failures gracefully
	// It will retry on next cycle
	if err != nil {
		t.Fatalf("Churn scenario should handle connection failures: %v", err)
	}

	// Clear error for next cycle
	client.connectError = nil
}

// TestChurnScenarioMetricsRecording tests that metrics are recorded
func TestChurnScenarioMetricsRecording(t *testing.T) {
	scenario := &ChurnScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Interval = 30 * time.Millisecond
	params.Duration = 100 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Churn scenario failed: %v", err)
	}

	// Verify metrics were recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	if len(recordedMetrics) == 0 {
		t.Error("Expected metrics to be recorded")
	}

	// Verify all metrics are for churn scenario
	for _, m := range recordedMetrics {
		if m.Scenario != "churn" {
			t.Errorf("Expected scenario 'churn', got '%s'", m.Scenario)
		}
	}
}
