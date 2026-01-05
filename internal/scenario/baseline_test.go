package scenario

import (
	"context"
	"fmt"
	"github.com/tturner/cipdip/internal/cip/spec"
	"testing"
	"time"

	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
	"github.com/tturner/cipdip/internal/metrics"
)

// createTestConfig creates a minimal test configuration
func createTestConfig() *config.Config {
	return &config.Config{
		Adapter: config.AdapterConfig{
			Name: "Test Adapter",
			Port: 44818,
		},
		ReadTargets: []config.CIPTarget{
			{
				Name:      "InputBlock1",
				Service:   config.ServiceGetAttributeSingle,
				Class:     0x04,
				Instance:  0x65,
				Attribute: 0x03,
			},
			{
				Name:      "InputBlock2",
				Service:   config.ServiceGetAttributeSingle,
				Class:     0x04,
				Instance:  0x66,
				Attribute: 0x03,
			},
		},
	}
}

// createTestParams creates test scenario parameters
func createTestParams() ScenarioParams {
	logger, _ := logging.NewLogger(logging.LogLevelError, "")
	return ScenarioParams{
		IP:          "127.0.0.1",
		Port:        44818,
		Interval:    100 * time.Millisecond,
		Duration:    500 * time.Millisecond, // Short duration for testing
		MetricsSink: metrics.NewSink(),
		Logger:      logger,
		TargetType:  metrics.TargetTypeEmulatorAdapter,
	}
}

// TestBaselineScenarioBasicExecution tests basic baseline scenario execution
func TestBaselineScenarioBasicExecution(t *testing.T) {
	scenario := &BaselineScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Baseline scenario failed: %v", err)
	}

	// Verify reads were performed
	for _, target := range cfg.ReadTargets {
		path := protocol.CIPPath{
			Class:     target.Class,
			Instance:  target.Instance,
			Attribute: target.Attribute,
		}
		count := client.GetReadCount(path)
		if count == 0 {
			t.Errorf("Expected reads for %s, got 0", target.Name)
		}
	}
}

// TestBaselineScenarioMetricsRecording tests that metrics are recorded correctly
func TestBaselineScenarioMetricsRecording(t *testing.T) {
	scenario := &BaselineScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Baseline scenario failed: %v", err)
	}

	// Verify metrics were recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	if len(recordedMetrics) == 0 {
		t.Error("Expected metrics to be recorded")
	}

	// Verify metrics have correct scenario name
	for _, m := range recordedMetrics {
		if m.Scenario != "baseline" {
			t.Errorf("Expected scenario 'baseline', got '%s'", m.Scenario)
		}
		if m.Operation != metrics.OperationRead {
			t.Errorf("Expected operation '%s', got '%s'", metrics.OperationRead, m.Operation)
		}
		if m.TargetType != params.TargetType {
			t.Errorf("Expected target type %v, got %v", params.TargetType, m.TargetType)
		}
	}
}

// TestBaselineScenarioIntervalHandling tests that interval is respected
func TestBaselineScenarioIntervalHandling(t *testing.T) {
	scenario := &BaselineScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Interval = 50 * time.Millisecond
	params.Duration = 200 * time.Millisecond // Should allow ~4 iterations

	ctx := context.Background()

	start := time.Now()
	err := scenario.Run(ctx, client, cfg, params)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Baseline scenario failed: %v", err)
	}

	// Duration should be at least the specified duration
	if duration < params.Duration {
		t.Errorf("Duration too short: got %v, want at least %v", duration, params.Duration)
	}

	// Verify reads were performed (should be multiple iterations)
	path := protocol.CIPPath{
		Class:     cfg.ReadTargets[0].Class,
		Instance:  cfg.ReadTargets[0].Instance,
		Attribute: cfg.ReadTargets[0].Attribute,
	}
	count := client.GetReadCount(path)
	if count < 2 {
		t.Errorf("Expected multiple reads, got %d", count)
	}
}

// TestBaselineScenarioContextCancellation tests context cancellation handling
func TestBaselineScenarioContextCancellation(t *testing.T) {
	scenario := &BaselineScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 10 * time.Second // Long duration

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Baseline scenario failed: %v", err)
	}

	// Verify some reads were performed before cancellation
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

// TestBaselineScenarioErrorHandling tests error handling for read failures
func TestBaselineScenarioErrorHandling(t *testing.T) {
	scenario := &BaselineScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()

	// Set error for one target
	path := protocol.CIPPath{
		Class:     cfg.ReadTargets[0].Class,
		Instance:  cfg.ReadTargets[0].Instance,
		Attribute: cfg.ReadTargets[0].Attribute,
	}
	client.SetReadError(path, fmt.Errorf("connection error"))

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Baseline scenario should continue on errors: %v", err)
	}

	// Verify metrics include error
	recordedMetrics := params.MetricsSink.GetMetrics()
	hasError := false
	for _, m := range recordedMetrics {
		if !m.Success && m.Error != "" {
			hasError = true
			break
		}
	}
	if !hasError {
		t.Error("Expected error metrics to be recorded")
	}
}

// TestBaselineScenarioCIPErrorStatus tests handling of CIP error status codes
func TestBaselineScenarioCIPErrorStatus(t *testing.T) {
	scenario := &BaselineScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()

	// Set error status response
	path := protocol.CIPPath{
		Class:     cfg.ReadTargets[0].Class,
		Instance:  cfg.ReadTargets[0].Instance,
		Attribute: cfg.ReadTargets[0].Attribute,
	}
	client.SetReadResponse(path, protocol.CIPResponse{
		Service: spec.CIPServiceGetAttributeSingle,
		Status:  0x01, // General error
		Path:    path,
	})

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Baseline scenario should continue on CIP errors: %v", err)
	}

	// Verify metrics include error status
	recordedMetrics := params.MetricsSink.GetMetrics()
	hasErrorStatus := false
	for _, m := range recordedMetrics {
		if !m.Success && m.Status != 0 {
			hasErrorStatus = true
			if m.Status != 0x01 {
				t.Errorf("Expected status 0x01, got 0x%02X", m.Status)
			}
			break
		}
	}
	if !hasErrorStatus {
		t.Error("Expected error status metrics to be recorded")
	}
}

// TestBaselineScenarioConnectionFailure tests connection failure handling
func TestBaselineScenarioConnectionFailure(t *testing.T) {
	scenario := &BaselineScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()

	// Set connection error
	client.connectError = fmt.Errorf("connection refused")

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err == nil {
		t.Error("Expected error on connection failure")
	}
}

// TestBaselineScenarioNoTargets tests scenario with no read targets
func TestBaselineScenarioNoTargets(t *testing.T) {
	scenario := &BaselineScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	cfg.ReadTargets = []config.CIPTarget{} // No targets
	params := createTestParams()

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Baseline scenario should handle no targets gracefully: %v", err)
	}

	// Verify no metrics (or minimal metrics)
	recordedMetrics := params.MetricsSink.GetMetrics()
	// Should have minimal metrics (connection/disconnection)
	if len(recordedMetrics) > 2 {
		t.Errorf("Expected minimal metrics with no targets, got %d", len(recordedMetrics))
	}
}
