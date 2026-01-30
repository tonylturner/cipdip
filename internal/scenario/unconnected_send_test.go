package scenario

import (
	"context"
	"testing"
	"time"

	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/metrics"
)

func createUnconnectedSendTestConfig() *config.Config {
	cfg := createTestConfig()
	cfg.EdgeTargets = []config.EdgeTarget{
		{
			Name:            "UCMM_GetAttr_Test",
			Service:         config.ServiceGetAttributeSingle,
			Class:           0x01,
			Instance:        0x01,
			Attribute:       0x01,
			ExpectedOutcome: "success",
		},
		{
			Name:            "UCMM_SetAttr_Test",
			Service:         config.ServiceSetAttributeSingle,
			Class:           0x01,
			Instance:        0x01,
			Attribute:       0x07,
			ExpectedOutcome: "success",
		},
		{
			Name:            "UCMM_Custom_Test",
			Service:         config.ServiceCustom,
			ServiceCode:     0x0E, // Get_Attribute_Single
			Class:           0x01,
			Instance:        0x01,
			Attribute:       0x01,
			ExpectedOutcome: "any",
		},
	}
	return cfg
}

func TestUnconnectedSendScenarioBasicExecution(t *testing.T) {
	scenario := &UnconnectedSendScenario{}
	client := NewMockClient()
	cfg := createUnconnectedSendTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Unconnected send scenario failed: %v", err)
	}
}

func TestUnconnectedSendScenarioMetricsRecording(t *testing.T) {
	scenario := &UnconnectedSendScenario{}
	client := NewMockClient()
	cfg := createUnconnectedSendTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Unconnected send scenario failed: %v", err)
	}

	// Verify metrics were recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	if len(recordedMetrics) == 0 {
		t.Error("Expected metrics to be recorded")
	}

	// Verify metrics have correct scenario name
	for _, m := range recordedMetrics {
		if m.Scenario != "unconnected_send" {
			t.Errorf("Expected scenario 'unconnected_send', got '%s'", m.Scenario)
		}
	}
}

func TestUnconnectedSendScenarioServiceCodeFormat(t *testing.T) {
	scenario := &UnconnectedSendScenario{}
	client := NewMockClient()
	cfg := createUnconnectedSendTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Unconnected send scenario failed: %v", err)
	}

	// Verify service code format includes outer and embedded codes
	recordedMetrics := params.MetricsSink.GetMetrics()
	for _, m := range recordedMetrics {
		// Service code should be in format "0xXX->0xYY"
		if len(m.ServiceCode) < 10 {
			t.Errorf("Expected service code in '0xXX->0xYY' format, got '%s'", m.ServiceCode)
		}
	}
}

func TestUnconnectedSendScenarioContextCancellation(t *testing.T) {
	scenario := &UnconnectedSendScenario{}
	client := NewMockClient()
	cfg := createUnconnectedSendTestConfig()
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
		t.Fatalf("Unconnected send scenario failed: %v", err)
	}

	if elapsed > 2*time.Second {
		t.Errorf("Context cancellation took too long: %v", elapsed)
	}
}

func TestUnconnectedSendScenarioConnectionFailure(t *testing.T) {
	scenario := &UnconnectedSendScenario{}
	client := NewMockClient()
	cfg := createUnconnectedSendTestConfig()
	params := createTestParams()

	client.connectError = errConnectionRefused

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err == nil {
		t.Error("Expected error on connection failure")
	}
}

func TestUnconnectedSendScenarioNoEdgeTargets(t *testing.T) {
	scenario := &UnconnectedSendScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	cfg.EdgeTargets = nil
	params := createTestParams()

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err == nil {
		t.Error("Expected error when no edge targets configured")
	}
}

func TestUnconnectedSendScenarioOperationTypes(t *testing.T) {
	scenario := &UnconnectedSendScenario{}
	client := NewMockClient()
	cfg := createUnconnectedSendTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Unconnected send scenario failed: %v", err)
	}

	// Verify we have custom operations
	recordedMetrics := params.MetricsSink.GetMetrics()
	opTypes := make(map[metrics.OperationType]int)
	for _, m := range recordedMetrics {
		opTypes[m.Operation]++
	}

	// Unconnected send should use custom operations
	if opTypes[metrics.OperationCustom] == 0 {
		t.Error("Expected custom operations to be recorded")
	}
}

func TestUnconnectedSendScenarioIntervalHandling(t *testing.T) {
	scenario := &UnconnectedSendScenario{}
	client := NewMockClient()
	cfg := createUnconnectedSendTestConfig()
	params := createTestParams()
	params.Interval = 50 * time.Millisecond
	params.Duration = 250 * time.Millisecond

	ctx := context.Background()

	start := time.Now()
	err := scenario.Run(ctx, client, cfg, params)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Unconnected send scenario failed: %v", err)
	}

	// Duration should be at least the specified duration
	if duration < params.Duration {
		t.Errorf("Duration too short: got %v, want at least %v", duration, params.Duration)
	}
}
