package scenario

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/metrics"
)

// createTestConfigWithWrites creates a test config with read and write targets
func createTestConfigWithWrites() *config.Config {
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
		},
		WriteTargets: []config.CIPTarget{
			{
				Name:         "OutputBlock1",
				Service:      config.ServiceSetAttributeSingle,
				Class:        0x04,
				Instance:     0x67,
				Attribute:    0x03,
				Pattern:      "increment",
				InitialValue: 0,
			},
		},
	}
}

// TestMixedScenarioBasicExecution tests basic mixed scenario execution
func TestMixedScenarioBasicExecution(t *testing.T) {
	scenario := &MixedScenario{}
	client := NewMockClient()
	cfg := createTestConfigWithWrites()
	params := createTestParams()

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Mixed scenario failed: %v", err)
	}

	// Verify reads were performed
	for _, target := range cfg.ReadTargets {
		path := cipclient.CIPPath{
			Class:     target.Class,
			Instance:  target.Instance,
			Attribute: target.Attribute,
		}
		count := client.GetReadCount(path)
		if count == 0 {
			t.Errorf("Expected reads for %s, got 0", target.Name)
		}
	}

	// Verify writes were performed
	for _, target := range cfg.WriteTargets {
		path := cipclient.CIPPath{
			Class:     target.Class,
			Instance:  target.Instance,
			Attribute: target.Attribute,
		}
		count := client.GetWriteCount(path)
		if count == 0 {
			t.Errorf("Expected writes for %s, got 0", target.Name)
		}
	}
}

// TestMixedScenarioMetricsRecording tests that metrics are recorded for both reads and writes
func TestMixedScenarioMetricsRecording(t *testing.T) {
	scenario := &MixedScenario{}
	client := NewMockClient()
	cfg := createTestConfigWithWrites()
	params := createTestParams()

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Mixed scenario failed: %v", err)
	}

	// Verify metrics were recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	if len(recordedMetrics) == 0 {
		t.Error("Expected metrics to be recorded")
	}

	// Verify we have both read and write metrics
	hasRead := false
	hasWrite := false
	for _, m := range recordedMetrics {
		if m.Scenario != "mixed" {
			t.Errorf("Expected scenario 'mixed', got '%s'", m.Scenario)
		}
		if m.Operation == metrics.OperationRead {
			hasRead = true
		}
		if m.Operation == metrics.OperationWrite {
			hasWrite = true
		}
	}

	if !hasRead {
		t.Error("Expected read metrics to be recorded")
	}
	if !hasWrite {
		t.Error("Expected write metrics to be recorded")
	}
}

// TestMixedScenarioWritePatterns tests different write patterns
func TestMixedScenarioWritePatterns(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
	}{
		{"increment", "increment"},
		{"toggle", "toggle"},
		{"constant", "constant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scenario := &MixedScenario{}
			client := NewMockClient()
			cfg := createTestConfigWithWrites()
			cfg.WriteTargets[0].Pattern = tt.pattern
			params := createTestParams()
			params.Duration = 200 * time.Millisecond

			ctx := context.Background()

			err := scenario.Run(ctx, client, cfg, params)
			if err != nil {
				t.Fatalf("Mixed scenario failed: %v", err)
			}

			// Verify writes were performed
			path := cipclient.CIPPath{
				Class:     cfg.WriteTargets[0].Class,
				Instance:  cfg.WriteTargets[0].Instance,
				Attribute: cfg.WriteTargets[0].Attribute,
			}
			count := client.GetWriteCount(path)
			if count == 0 {
				t.Errorf("Expected writes for pattern %s, got 0", tt.pattern)
			}
		})
	}
}

// TestMixedScenarioErrorHandling tests error handling for read/write failures
func TestMixedScenarioErrorHandling(t *testing.T) {
	scenario := &MixedScenario{}
	client := NewMockClient()
	cfg := createTestConfigWithWrites()
	params := createTestParams()

	// Set error for read target
	readPath := cipclient.CIPPath{
		Class:     cfg.ReadTargets[0].Class,
		Instance:  cfg.ReadTargets[0].Instance,
		Attribute: cfg.ReadTargets[0].Attribute,
	}
	client.SetReadError(readPath, fmt.Errorf("read error"))

	// Set error for write target
	writePath := cipclient.CIPPath{
		Class:     cfg.WriteTargets[0].Class,
		Instance:  cfg.WriteTargets[0].Instance,
		Attribute: cfg.WriteTargets[0].Attribute,
	}
	client.SetWriteError(writePath, fmt.Errorf("write error"))

	ctx := context.Background()

	err := scenario.Run(ctx, client, cfg, params)
	if err != nil {
		t.Fatalf("Mixed scenario should continue on errors: %v", err)
	}

	// Verify error metrics are recorded
	recordedMetrics := params.MetricsSink.GetMetrics()
	hasReadError := false
	hasWriteError := false
	for _, m := range recordedMetrics {
		if !m.Success {
			if m.Operation == metrics.OperationRead {
				hasReadError = true
			}
			if m.Operation == metrics.OperationWrite {
				hasWriteError = true
			}
		}
	}

	if !hasReadError {
		t.Error("Expected read error metrics to be recorded")
	}
	if !hasWriteError {
		t.Error("Expected write error metrics to be recorded")
	}
}
