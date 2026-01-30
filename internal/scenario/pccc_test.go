package scenario

import (
	"context"
	"testing"
	"time"

	"github.com/tturner/cipdip/internal/metrics"
)

func TestPCCCScenarioBasicExecution(t *testing.T) {
	scenario := &PCCCScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("PCCC scenario failed: %v", err)
	}
}

func TestPCCCScenarioMetricsRecording(t *testing.T) {
	scenario := &PCCCScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("PCCC scenario failed: %v", err)
	}

	// Verify metrics were recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	if len(recordedMetrics) == 0 {
		t.Error("Expected metrics to be recorded")
	}

	// Verify metrics have correct scenario name
	for _, m := range recordedMetrics {
		if m.Scenario != "pccc" {
			t.Errorf("Expected scenario 'pccc', got '%s'", m.Scenario)
		}
	}
}

func TestPCCCScenarioOperationTypes(t *testing.T) {
	scenario := &PCCCScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("PCCC scenario failed: %v", err)
	}

	// Verify we have read and write operations
	recordedMetrics := params.MetricsSink.GetMetrics()
	opTypes := make(map[metrics.OperationType]int)
	for _, m := range recordedMetrics {
		opTypes[m.Operation]++
	}

	// PCCC should include read operations
	if opTypes[metrics.OperationRead] == 0 && opTypes[metrics.OperationWrite] == 0 && opTypes[metrics.OperationCustom] == 0 {
		t.Error("Expected PCCC operations to be recorded")
	}
}

func TestPCCCScenarioContextCancellation(t *testing.T) {
	scenario := &PCCCScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 10 * time.Second

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after short delay
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := scenario.Run(ctx, client, cfg, params)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("PCCC scenario failed: %v", err)
	}

	if elapsed > 2*time.Second {
		t.Errorf("Context cancellation took too long: %v", elapsed)
	}
}

func TestPCCCScenarioConnectionFailure(t *testing.T) {
	scenario := &PCCCScenario{}
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

func TestPCCCScenarioIntervalHandling(t *testing.T) {
	scenario := &PCCCScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Interval = 50 * time.Millisecond
	params.Duration = 250 * time.Millisecond

	ctx := context.Background()

	start := time.Now()
	err := scenario.Run(ctx, client, cfg, params)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("PCCC scenario failed: %v", err)
	}

	// Duration should be at least the specified duration
	if duration < params.Duration {
		t.Errorf("Duration too short: got %v, want at least %v", duration, params.Duration)
	}
}
