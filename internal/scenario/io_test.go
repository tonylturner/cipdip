package scenario

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/tonylturner/cipdip/internal/config"
	"github.com/tonylturner/cipdip/internal/metrics"
)

// createTestConfigWithIO creates a test config with I/O connections
func createTestConfigWithIO() *config.Config {
	return &config.Config{
		Adapter: config.AdapterConfig{
			Name: "Test Adapter",
			Port: 44818,
		},
		IOConnections: []config.IOConnectionConfig{
			{
				Name:                  "IOConn1",
				Transport:             "udp",
				OToTRPIMs:             20,
				TToORPIMs:             20,
				OToTSizeBytes:         8,
				TToOSizeBytes:         8,
				Priority:              "scheduled",
				TransportClassTrigger: 3,
				Class:                 0x04,
				Instance:              0x65,
			},
		},
	}
}

// TestIOScenarioBasicExecution tests basic I/O scenario execution
func TestIOScenarioBasicExecution(t *testing.T) {
	scenario := &IOScenario{}
	client := NewMockClient()
	cfg := createTestConfigWithIO()
	params := createTestParams()
	params.Interval = 20 * time.Millisecond
	params.Duration = 100 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("I/O scenario failed: %v", err)
	}

	// Verify ForwardOpen was called (connection established)
	// We can't directly verify this with the mock, but we can check metrics
	recordedMetrics := params.MetricsSink.GetMetrics()
	hasForwardOpen := false
	for _, m := range recordedMetrics {
		if m.Operation == metrics.OperationForwardOpen {
			hasForwardOpen = true
			break
		}
	}
	if !hasForwardOpen {
		t.Error("Expected ForwardOpen operation to be recorded")
	}
}

// TestIOScenarioNoConnections tests error handling when no I/O connections configured
func TestIOScenarioNoConnections(t *testing.T) {
	scenario := &IOScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	cfg.IOConnections = []config.IOConnectionConfig{} // No I/O connections
	params := createTestParams()

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err == nil {
		t.Error("Expected error when no I/O connections configured")
	}
}

// TestIOScenarioMetricsRecording tests that metrics are recorded for I/O operations
func TestIOScenarioMetricsRecording(t *testing.T) {
	scenario := &IOScenario{}
	client := NewMockClient()
	cfg := createTestConfigWithIO()
	params := createTestParams()
	params.Interval = 20 * time.Millisecond
	params.Duration = 100 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("I/O scenario failed: %v", err)
	}

	// Verify metrics were recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	if len(recordedMetrics) == 0 {
		t.Error("Expected metrics to be recorded")
	}

	// Verify I/O-specific operations
	hasOTToT := false
	hasTToO := false
	hasForwardOpen := false
	hasForwardClose := false

	for _, m := range recordedMetrics {
		if m.Scenario != "io" {
			t.Errorf("Expected scenario 'io', got '%s'", m.Scenario)
		}
		switch m.Operation {
		case metrics.OperationOTToTSend:
			hasOTToT = true
		case metrics.OperationTToORecv:
			hasTToO = true
		case metrics.OperationForwardOpen:
			hasForwardOpen = true
		case metrics.OperationForwardClose:
			hasForwardClose = true
		}
	}

	if !hasForwardOpen {
		t.Error("Expected ForwardOpen metrics to be recorded")
	}
	if !hasOTToT {
		t.Error("Expected O->T send metrics to be recorded")
	}
	if !hasTToO {
		t.Error("Expected T->O receive metrics to be recorded")
	}
	if !hasForwardClose {
		t.Error("Expected ForwardClose metrics to be recorded")
	}
}

// TestIOScenarioForwardOpenFailure tests handling of ForwardOpen failures
func TestIOScenarioForwardOpenFailure(t *testing.T) {
	scenario := &IOScenario{}
	client := NewMockClient()
	cfg := createTestConfigWithIO()
	params := createTestParams()

	// Set ForwardOpen error
	client.forwardOpenError = fmt.Errorf("ForwardOpen failed")

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err == nil {
		t.Error("Expected error when ForwardOpen fails")
	}
}

// TestIOScenarioSendIODataFailure tests handling of SendIOData failures
func TestIOScenarioSendIODataFailure(t *testing.T) {
	scenario := &IOScenario{}
	client := NewMockClient()
	cfg := createTestConfigWithIO()
	params := createTestParams()
	params.Interval = 20 * time.Millisecond
	params.Duration = 100 * time.Millisecond

	// Set SendIOData error (after connection is established)
	client.sendIODataError = fmt.Errorf("SendIOData failed")

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	// Scenario should continue even if SendIOData fails
	if err != nil {
		t.Fatalf("I/O scenario should continue on SendIOData errors: %v", err)
	}

	// Verify error metrics are recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	hasError := false
	for _, m := range recordedMetrics {
		if !m.Success && m.Operation == metrics.OperationOTToTSend {
			hasError = true
			break
		}
	}
	if !hasError {
		t.Error("Expected SendIOData error metrics to be recorded")
	}
}

// TestIOScenarioReceiveIODataFailure tests handling of ReceiveIOData failures
func TestIOScenarioReceiveIODataFailure(t *testing.T) {
	scenario := &IOScenario{}
	client := NewMockClient()
	cfg := createTestConfigWithIO()
	params := createTestParams()
	params.Interval = 20 * time.Millisecond
	params.Duration = 100 * time.Millisecond

	// Set ReceiveIOData error
	client.receiveIODataError = fmt.Errorf("ReceiveIOData failed")

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	// Scenario should continue even if ReceiveIOData fails
	if err != nil {
		t.Fatalf("I/O scenario should continue on ReceiveIOData errors: %v", err)
	}

	// Verify error metrics are recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	hasError := false
	for _, m := range recordedMetrics {
		if !m.Success && m.Operation == metrics.OperationTToORecv {
			hasError = true
			break
		}
	}
	if !hasError {
		t.Error("Expected ReceiveIOData error metrics to be recorded")
	}
}

// TestIOScenarioContextCancellation tests context cancellation
func TestIOScenarioContextCancellation(t *testing.T) {
	scenario := &IOScenario{}
	client := NewMockClient()
	cfg := createTestConfigWithIO()
	params := createTestParams()
	params.Interval = 20 * time.Millisecond
	params.Duration = 5 * time.Second // Long duration

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("I/O scenario failed: %v", err)
	}

	// Verify some operations were performed
	recordedMetrics := params.MetricsSink.GetMetrics()
	if len(recordedMetrics) == 0 {
		t.Error("Expected at least some metrics before cancellation")
	}
}
