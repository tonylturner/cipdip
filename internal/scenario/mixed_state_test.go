package scenario

import (
	"context"
	"testing"
	"time"

	"github.com/tonylturner/cipdip/internal/config"
	"github.com/tonylturner/cipdip/internal/metrics"
)

func createMixedStateTestConfig() *config.Config {
	cfg := createTestConfig()
	cfg.IOConnections = []config.IOConnectionConfig{
		{
			Name:                  "TestIO_1",
			Transport:             "udp",
			OToTRPIMs:             100,
			TToORPIMs:             100,
			OToTSizeBytes:         8,
			TToOSizeBytes:         8,
			Priority:              "low",
			TransportClassTrigger: 0x83, // Class 3, cyclic
			Class:                 0x04,
			Instance:              0x65,
		},
		{
			Name:                  "TestIO_2",
			Transport:             "udp",
			OToTRPIMs:             100,
			TToORPIMs:             100,
			OToTSizeBytes:         16,
			TToOSizeBytes:         16,
			Priority:              "low",
			TransportClassTrigger: 0x83,
			Class:                 0x04,
			Instance:              0x66,
		},
	}
	return cfg
}

func TestMixedStateScenarioBasicExecution(t *testing.T) {
	scenario := &MixedStateScenario{}
	client := NewMockClient()
	cfg := createMixedStateTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Mixed state scenario failed: %v", err)
	}
}

func TestMixedStateScenarioMetricsRecording(t *testing.T) {
	scenario := &MixedStateScenario{}
	client := NewMockClient()
	cfg := createMixedStateTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Mixed state scenario failed: %v", err)
	}

	// Verify metrics were recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	if len(recordedMetrics) == 0 {
		t.Error("Expected metrics to be recorded")
	}

	// Verify metrics have correct scenario name
	for _, m := range recordedMetrics {
		if m.Scenario != "mixed_state" {
			t.Errorf("Expected scenario 'mixed_state', got '%s'", m.Scenario)
		}
	}
}

func TestMixedStateScenarioOperationTypes(t *testing.T) {
	scenario := &MixedStateScenario{}
	client := NewMockClient()
	cfg := createMixedStateTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Mixed state scenario failed: %v", err)
	}

	// Verify we have a mix of operation types
	recordedMetrics := params.MetricsSink.GetMetrics()
	opTypes := make(map[metrics.OperationType]int)
	for _, m := range recordedMetrics {
		opTypes[m.Operation]++
	}

	// Mixed state should include reads and I/O operations
	hasReadOrIO := opTypes[metrics.OperationRead] > 0 ||
		opTypes[metrics.OperationOTToTSend] > 0 ||
		opTypes[metrics.OperationTToORecv] > 0
	if !hasReadOrIO {
		t.Error("Expected read or I/O operations to be recorded")
	}
}

func TestMixedStateScenarioIOOperations(t *testing.T) {
	scenario := &MixedStateScenario{}
	client := NewMockClient()
	cfg := createMixedStateTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Mixed state scenario failed: %v", err)
	}

	// Verify I/O operations were recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	opTypes := make(map[metrics.OperationType]int)
	for _, m := range recordedMetrics {
		opTypes[m.Operation]++
	}

	// Should have O->T send and T->O receive operations
	if opTypes[metrics.OperationOTToTSend] == 0 {
		t.Error("Expected O->T send operations to be recorded")
	}
	if opTypes[metrics.OperationTToORecv] == 0 {
		t.Error("Expected T->O receive operations to be recorded")
	}
}

func TestMixedStateScenarioContextCancellation(t *testing.T) {
	scenario := &MixedStateScenario{}
	client := NewMockClient()
	cfg := createMixedStateTestConfig()
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
		t.Fatalf("Mixed state scenario failed: %v", err)
	}

	if elapsed > 2*time.Second {
		t.Errorf("Context cancellation took too long: %v", elapsed)
	}
}

func TestMixedStateScenarioConnectionFailure(t *testing.T) {
	scenario := &MixedStateScenario{}
	client := NewMockClient()
	cfg := createMixedStateTestConfig()
	params := createTestParams()

	client.connectError = errConnectionRefused

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err == nil {
		t.Error("Expected error on connection failure")
	}
}

func TestMixedStateScenarioNoIOConnections(t *testing.T) {
	scenario := &MixedStateScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	cfg.IOConnections = nil
	params := createTestParams()

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err == nil {
		t.Error("Expected error when no I/O connections configured")
	}
}

func TestMixedStateScenarioForwardOpenFailure(t *testing.T) {
	scenario := &MixedStateScenario{}
	client := NewMockClient()
	cfg := createMixedStateTestConfig()
	params := createTestParams()

	client.forwardOpenError = errConnectionRefused

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	// Should fail because no I/O connections could be established
	if err == nil {
		t.Error("Expected error when ForwardOpen fails for all connections")
	}
}

func TestMixedStateScenarioIntervalHandling(t *testing.T) {
	scenario := &MixedStateScenario{}
	client := NewMockClient()
	cfg := createMixedStateTestConfig()
	params := createTestParams()
	params.Interval = 50 * time.Millisecond
	params.Duration = 250 * time.Millisecond

	ctx := context.Background()

	start := time.Now()
	err := scenario.Run(ctx, client, cfg, params)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Mixed state scenario failed: %v", err)
	}

	// Duration should be at least the specified duration
	if duration < params.Duration {
		t.Errorf("Duration too short: got %v, want at least %v", duration, params.Duration)
	}
}

func TestMixedStateScenarioWithReadTargets(t *testing.T) {
	scenario := &MixedStateScenario{}
	client := NewMockClient()
	cfg := createMixedStateTestConfig()
	// Ensure we have read targets (from createTestConfig)
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Mixed state scenario failed: %v", err)
	}

	// Verify we have read operations
	recordedMetrics := params.MetricsSink.GetMetrics()
	opTypes := make(map[metrics.OperationType]int)
	for _, m := range recordedMetrics {
		opTypes[m.Operation]++
	}

	if opTypes[metrics.OperationRead] == 0 {
		t.Error("Expected read operations to be recorded")
	}
}
