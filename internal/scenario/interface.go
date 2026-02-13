package scenario

// Scenario interface and common types

import (
	"context"
	"time"

	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/config"
	"github.com/tonylturner/cipdip/internal/logging"
	"github.com/tonylturner/cipdip/internal/metrics"
)

// ScenarioParams contains parameters for running a scenario
type ScenarioParams struct {
	IP          string
	Port        int
	Interval    time.Duration
	Duration    time.Duration
	MetricsSink *metrics.Sink
	Logger      *logging.Logger
	TargetType  metrics.TargetType
}

// Scenario defines the interface for all scenarios
type Scenario interface {
	Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error
}

// GetScenario returns a scenario implementation by name
func GetScenario(name string) (Scenario, error) {
	switch name {
	case "baseline":
		return &BaselineScenario{}, nil
	case "mixed":
		return &MixedScenario{}, nil
	case "stress":
		return &StressScenario{}, nil
	case "churn":
		return &ChurnScenario{}, nil
	case "io":
		return &IOScenario{}, nil
	case "edge_valid":
		return &EdgeValidScenario{}, nil
	case "edge_vendor":
		return &EdgeVendorScenario{}, nil
	case "rockwell":
		return &RockwellScenario{}, nil
	case "vendor_variants":
		return &VendorVariantsScenario{}, nil
	case "mixed_state":
		return &MixedStateScenario{}, nil
	case "unconnected_send":
		return &UnconnectedSendScenario{}, nil
	case "dpi_explicit":
		return &DPIExplicitScenario{}, nil
	case "firewall_hirschmann":
		return &FirewallScenario{Vendor: "hirschmann"}, nil
	case "firewall_moxa":
		return &FirewallScenario{Vendor: "moxa"}, nil
	case "firewall_dynics":
		return &FirewallScenario{Vendor: "dynics"}, nil
	case "firewall_pack":
		return &FirewallScenario{Vendor: "pack"}, nil
	case "pccc":
		return &PCCCScenario{}, nil
	case "modbus":
		return &ModbusScenario{}, nil
	case "modbus_pipeline":
		return &ModbusPipelineScenario{}, nil
	case "evasion_segment":
		return &EvasionSegmentScenario{}, nil
	case "evasion_fuzz":
		return &EvasionFuzzScenario{}, nil
	case "evasion_anomaly":
		return &EvasionAnomalyScenario{}, nil
	case "evasion_timing":
		return &EvasionTimingScenario{}, nil
	default:
		return nil, &UnknownScenarioError{Name: name}
	}
}

// UnknownScenarioError represents an error for unknown scenario names
type UnknownScenarioError struct {
	Name string
}

func (e *UnknownScenarioError) Error() string {
	return "unknown scenario: " + e.Name
}


