package scenario

import (
	"context"
	"testing"
	"time"

	"github.com/tonylturner/cipdip/internal/metrics"
)

func TestModbusScenarioBasicExecution(t *testing.T) {
	scenario := &ModbusScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Modbus scenario failed: %v", err)
	}
}

func TestModbusScenarioMetricsRecording(t *testing.T) {
	scenario := &ModbusScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Modbus scenario failed: %v", err)
	}

	// Verify metrics were recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	if len(recordedMetrics) == 0 {
		t.Error("Expected metrics to be recorded")
	}

	// Verify metrics have correct scenario name
	for _, m := range recordedMetrics {
		if m.Scenario != "modbus" {
			t.Errorf("Expected scenario 'modbus', got '%s'", m.Scenario)
		}
	}
}

func TestModbusScenarioOperationTypes(t *testing.T) {
	scenario := &ModbusScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Modbus scenario failed: %v", err)
	}

	// Verify we have a mix of operation types
	recordedMetrics := params.MetricsSink.GetMetrics()
	opTypes := make(map[metrics.OperationType]int)
	for _, m := range recordedMetrics {
		opTypes[m.Operation]++
	}

	// Modbus should include both read and write operations
	hasReadOrWrite := opTypes[metrics.OperationRead] > 0 || opTypes[metrics.OperationWrite] > 0
	if !hasReadOrWrite {
		t.Error("Expected Modbus read or write operations")
	}
}

func TestModbusScenarioContextCancellation(t *testing.T) {
	scenario := &ModbusScenario{}
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
		t.Fatalf("Modbus scenario failed: %v", err)
	}

	if elapsed > 2*time.Second {
		t.Errorf("Context cancellation took too long: %v", elapsed)
	}
}

func TestModbusScenarioConnectionFailure(t *testing.T) {
	scenario := &ModbusScenario{}
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

func TestModbusPipelineScenarioBasicExecution(t *testing.T) {
	scenario := &ModbusPipelineScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Modbus pipeline scenario failed: %v", err)
	}
}

func TestModbusPipelineScenarioMetrics(t *testing.T) {
	scenario := &ModbusPipelineScenario{}
	client := NewMockClient()
	cfg := createTestConfig()
	params := createTestParams()
	params.Duration = 500 * time.Millisecond

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Modbus pipeline scenario failed: %v", err)
	}

	recordedMetrics := params.MetricsSink.GetMetrics()
	if len(recordedMetrics) == 0 {
		t.Error("Expected metrics to be recorded")
	}

	for _, m := range recordedMetrics {
		if m.Scenario != "modbus_pipeline" {
			t.Errorf("Expected scenario 'modbus_pipeline', got '%s'", m.Scenario)
		}
	}
}
