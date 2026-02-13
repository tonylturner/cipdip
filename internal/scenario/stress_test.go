package scenario

import (
	"context"
	"testing"
	"time"

	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/metrics"
)

// TestStressScenarioBasicExecution tests basic stress scenario execution
func TestStressScenarioBasicExecution(t *testing.T) {
	scenario := &StressScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Interval = 10 * time.Millisecond  // Short interval for stress
	params.Duration = 100 * time.Millisecond // Short duration for testing

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Stress scenario failed: %v", err)
	}

	// Verify many reads were performed (stress = high frequency)
	path := protocol.CIPPath{
		Class:     cfg.ReadTargets[0].Class,
		Instance:  cfg.ReadTargets[0].Instance,
		Attribute: cfg.ReadTargets[0].Attribute,
	}
	count := client.GetReadCount(path)
	if count < 5 {
		t.Errorf("Expected many reads in stress scenario, got %d", count)
	}
}

// TestStressScenarioMetricsRecording tests that metrics are recorded
func TestStressScenarioMetricsRecording(t *testing.T) {
	scenario := &StressScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Interval = 10 * time.Millisecond
	params.Duration = 100 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Stress scenario failed: %v", err)
	}

	// Verify metrics were recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	if len(recordedMetrics) == 0 {
		t.Error("Expected metrics to be recorded")
	}

	// Verify all metrics are for stress scenario
	for _, m := range recordedMetrics {
		if m.Scenario != "stress" {
			t.Errorf("Expected scenario 'stress', got '%s'", m.Scenario)
		}
		if m.Operation != metrics.OperationRead {
			t.Errorf("Expected operation '%s', got '%s'", metrics.OperationRead, m.Operation)
		}
	}
}

// TestStressScenarioHighFrequency tests that stress scenario performs many operations
func TestStressScenarioHighFrequency(t *testing.T) {
	scenario := &StressScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Interval = 5 * time.Millisecond // Very short interval
	params.Duration = 50 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Stress scenario failed: %v", err)
	}

	// Verify high number of reads
	path := protocol.CIPPath{
		Class:     cfg.ReadTargets[0].Class,
		Instance:  cfg.ReadTargets[0].Instance,
		Attribute: cfg.ReadTargets[0].Attribute,
	}
	count := client.GetReadCount(path)
	if count < 5 {
		t.Errorf("Expected high frequency reads, got %d", count)
	}
}

// TestStressScenarioContextCancellation tests context cancellation
func TestStressScenarioContextCancellation(t *testing.T) {
	scenario := &StressScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Interval = 10 * time.Millisecond
	params.Duration = 5 * time.Second // Long duration

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Stress scenario failed: %v", err)
	}

	// Verify some reads were performed
	path := protocol.CIPPath{
		Class:     cfg.ReadTargets[0].Class,
		Instance:  cfg.ReadTargets[0].Instance,
		Attribute: cfg.ReadTargets[0].Attribute,
	}
	count := client.GetReadCount(path)
	if count == 0 {
		t.Error("Expected at least one read before cancellation")
	}
}
