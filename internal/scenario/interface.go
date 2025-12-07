package scenario

// Scenario interface and common types

import (
	"context"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
	"github.com/tturner/cipdip/internal/metrics"
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
