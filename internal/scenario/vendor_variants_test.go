package scenario

import (
	"context"
	"testing"
	"time"

	"github.com/tonylturner/cipdip/internal/config"
	"github.com/tonylturner/cipdip/internal/logging"
	"github.com/tonylturner/cipdip/internal/metrics"
)

func TestVendorVariantsScenarioRequiresVariants(t *testing.T) {
	scenario := &VendorVariantsScenario{}
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

	err := scenario.Run(context.Background(), client, cfg, params)
	if err == nil {
		t.Fatalf("expected error when protocol_variants is empty")
	}
}

func TestVendorVariantsScenarioRecordsMetrics(t *testing.T) {
	scenario := &VendorVariantsScenario{}
	client := NewMockClient()
	cfg := &config.Config{
		Adapter: config.AdapterConfig{
			Name: "Test Adapter",
			Port: 44818,
		},
		ReadTargets: []config.CIPTarget{
			{
				Name:      "IdentityVendor",
				Service:   config.ServiceGetAttributeSingle,
				Class:     0x01,
				Instance:  0x01,
				Attribute: 0x01,
			},
		},
		ProtocolVariants: []config.ProtocolConfig{
			{
				Mode:    "vendor_variant",
				Variant: "rockwell_v32",
			},
			{
				Mode:    "vendor_variant",
				Variant: "schneider_m580",
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

	err := scenario.Run(context.Background(), client, cfg, params)
	if err != nil {
		t.Fatalf("vendor_variants run failed: %v", err)
	}

	metrics := params.MetricsSink.GetMetrics()
	if len(metrics) == 0 {
		t.Fatalf("expected metrics to be recorded")
	}

	hasRockwell := false
	hasSchneider := false
	for _, m := range metrics {
		if m.Scenario == "vendor_variants:rockwell_v32" {
			hasRockwell = true
		}
		if m.Scenario == "vendor_variants:schneider_m580" {
			hasSchneider = true
		}
	}
	if !hasRockwell || !hasSchneider {
		t.Fatalf("expected metrics for both variants, got rockwell=%t schneider=%t", hasRockwell, hasSchneider)
	}
}
