package scenario

import (
	"context"
	"testing"
	"time"

	"github.com/tonylturner/cipdip/internal/cip/spec"
	"github.com/tonylturner/cipdip/internal/config"
	"github.com/tonylturner/cipdip/internal/metrics"
)

func createEdgeVendorTestConfig() *config.Config {
	cfg := createTestConfig()
	cfg.EdgeTargets = []config.EdgeTarget{
		{
			Name:            "ReadTag_Test",
			Service:         config.ServiceCustom,
			ServiceCode:     uint8(spec.CIPServiceReadTag),
			Class:           0x0067,
			Instance:        0x0001,
			Attribute:       0x0000,
			ExpectedOutcome: "any",
		},
		{
			Name:            "WriteTag_Test",
			Service:         config.ServiceCustom,
			ServiceCode:     uint8(spec.CIPServiceWriteTag),
			Class:           0x0067,
			Instance:        0x0001,
			Attribute:       0x0000,
			ExpectedOutcome: "any",
		},
		{
			Name:            "ExecutePCCC_Test",
			Service:         config.ServiceCustom,
			ServiceCode:     uint8(spec.CIPServiceExecutePCCC),
			Class:           0x0067,
			Instance:        0x0001,
			Attribute:       0x0000,
			ExpectedOutcome: "any",
		},
	}
	return cfg
}

func TestEdgeVendorScenarioBasicExecution(t *testing.T) {
	scenario := &EdgeVendorScenario{}
	client := NewMockClient()
	cfg := createEdgeVendorTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Edge vendor scenario failed: %v", err)
	}
}

func TestEdgeVendorScenarioMetricsRecording(t *testing.T) {
	scenario := &EdgeVendorScenario{}
	client := NewMockClient()
	cfg := createEdgeVendorTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Edge vendor scenario failed: %v", err)
	}

	// Verify metrics were recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	if len(recordedMetrics) == 0 {
		t.Error("Expected metrics to be recorded")
	}

	// Verify metrics have correct scenario name
	for _, m := range recordedMetrics {
		if m.Scenario != "edge_vendor" {
			t.Errorf("Expected scenario 'edge_vendor', got '%s'", m.Scenario)
		}
	}
}

func TestEdgeVendorScenarioOperationTypes(t *testing.T) {
	scenario := &EdgeVendorScenario{}
	client := NewMockClient()
	cfg := createEdgeVendorTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Edge vendor scenario failed: %v", err)
	}

	// Verify we have custom operations
	recordedMetrics := params.MetricsSink.GetMetrics()
	opTypes := make(map[metrics.OperationType]int)
	for _, m := range recordedMetrics {
		opTypes[m.Operation]++
	}

	// Edge vendor should include custom operations
	if opTypes[metrics.OperationCustom] == 0 {
		t.Error("Expected custom operations to be recorded")
	}
}

func TestEdgeVendorScenarioContextCancellation(t *testing.T) {
	scenario := &EdgeVendorScenario{}
	client := NewMockClient()
	cfg := createEdgeVendorTestConfig()
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
		t.Fatalf("Edge vendor scenario failed: %v", err)
	}

	if elapsed > 2*time.Second {
		t.Errorf("Context cancellation took too long: %v", elapsed)
	}
}

func TestEdgeVendorScenarioConnectionFailure(t *testing.T) {
	scenario := &EdgeVendorScenario{}
	client := NewMockClient()
	cfg := createEdgeVendorTestConfig()
	params := createTestParams()

	client.connectError = errConnectionRefused

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err == nil {
		t.Error("Expected error on connection failure")
	}
}

func TestEdgeVendorScenarioNoEdgeTargets(t *testing.T) {
	scenario := &EdgeVendorScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	// No edge targets
	cfg.EdgeTargets = nil
	params := createTestParams()

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err == nil {
		t.Error("Expected error when no edge targets configured")
	}
}

func TestEdgeVendorScenarioNoMatchingTargets(t *testing.T) {
	scenario := &EdgeVendorScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	// Edge targets with non-vendor service codes
	cfg.EdgeTargets = []config.EdgeTarget{
		{
			Name:        "NonVendor_Test",
			Service:     config.ServiceGetAttributeSingle,
			Class:       0x01,
			Instance:    0x01,
			Attribute:   0x01,
		},
	}
	params := createTestParams()

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err == nil {
		t.Error("Expected error when no matching vendor service codes")
	}
}
