package scenario

import (
	"context"
	"testing"
	"time"

	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
	"github.com/tturner/cipdip/internal/metrics"
)

func TestEdgeValidScenarioRequiresTargets(t *testing.T) {
	scenario := &EdgeValidScenario{}
	client := NewMockClient()
	cfg := &config.Config{}
	logger, _ := logging.NewLogger(logging.LogLevelError, "")
	params := ScenarioParams{
		IP:          "127.0.0.1",
		Port:        44818,
		Interval:    50 * time.Millisecond,
		Duration:    200 * time.Millisecond,
		MetricsSink: metrics.NewSink(),
		Logger:      logger,
		TargetType:  metrics.TargetTypeEmulatorAdapter,
	}

	if err := scenario.Run(context.Background(), client, cfg, params); err == nil {
		t.Fatalf("expected error when edge_targets is empty")
	}
}

func TestEdgeValidScenarioRecordsMetrics(t *testing.T) {
	scenario := &EdgeValidScenario{}
	client := NewMockClient()
	cfg := &config.Config{
		Adapter: config.AdapterConfig{
			Name: "Test Adapter",
			Port: 44818,
		},
		EdgeTargets: []config.EdgeTarget{
			{
				Name:      "EdgeGetAttr",
				Service:   config.ServiceGetAttributeSingle,
				Class:     0x04,
				Instance:  0x65,
				Attribute: 0x03,
			},
		},
	}
	logger, _ := logging.NewLogger(logging.LogLevelError, "")
	params := ScenarioParams{
		IP:          "127.0.0.1",
		Port:        44818,
		Interval:    50 * time.Millisecond,
		Duration:    200 * time.Millisecond,
		MetricsSink: metrics.NewSink(),
		Logger:      logger,
		TargetType:  metrics.TargetTypeEmulatorAdapter,
	}

	if err := scenario.Run(context.Background(), client, cfg, params); err != nil {
		t.Fatalf("edge_valid run failed: %v", err)
	}

	metrics := params.MetricsSink.GetMetrics()
	if len(metrics) == 0 {
		t.Fatalf("expected metrics to be recorded")
	}
	for _, m := range metrics {
		if m.Scenario != "edge_valid" {
			t.Fatalf("unexpected scenario name: %s", m.Scenario)
		}
	}
}
