package scenario

// Churn scenario: Repeated connection setup/teardown

import (
	"context"
	"fmt"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/metrics"
)

// ChurnScenario implements the churn scenario
type ChurnScenario struct{}

// Run executes the churn scenario
func (s *ChurnScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting churn scenario")
	params.Logger.Verbose("  Read targets: %d", len(cfg.ReadTargets))
	params.Logger.Verbose("  Interval: %v", params.Interval)
	params.Logger.Verbose("  Duration: %v", params.Duration)

	// Create deadline for duration
	deadline := time.Now().Add(params.Duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	cycleCount := 0
	failedConnections := 0
	startTime := time.Now()

	// Outer loop: connection cycles
	for {
		select {
		case <-ctx.Done():
			params.Logger.Info("Churn scenario completed (duration expired or cancelled)")
			return nil
		default:
		}

		// Check if we've exceeded duration
		if time.Now().After(deadline) {
			break
		}

		cycleCount++

		// Connect
		port := params.Port
		if port == 0 {
			port = cfg.Adapter.Port
			if port == 0 {
				port = 44818 // Default
			}
		}
		if err := client.Connect(ctx, params.IP, port); err != nil {
			failedConnections++
			params.Logger.Error("Connection failed in cycle %d: %v", cycleCount, err)
			
			// Record connection failure metric
			metric := metrics.Metric{
				Timestamp:  time.Now(),
				Scenario:   "churn",
				TargetType: params.TargetType,
				Operation:  metrics.OperationRead,
				Success:    false,
				Error:      fmt.Sprintf("connection failed: %v", err),
			}
			params.MetricsSink.Record(metric)

			// Sleep before retry
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(params.Interval):
			}
			continue
		}

		// Perform 1-3 reads per target
		readCount := 3
		if len(cfg.ReadTargets) > 0 {
			for i := 0; i < readCount; i++ {
				for _, target := range cfg.ReadTargets {
					path := cipclient.CIPPath{
						Class:     target.Class,
						Instance:  target.Instance,
						Attribute: target.Attribute,
						Name:      target.Name,
					}

					start := time.Now()
					resp, err := client.ReadAttribute(ctx, path)
					rtt := time.Since(start).Seconds() * 1000

					success := err == nil && resp.Status == 0
					var errorMsg string
					if err != nil {
						errorMsg = err.Error()
					} else if resp.Status != 0 {
						errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
					}

					metric := metrics.Metric{
						Timestamp:   time.Now(),
						Scenario:    "churn",
						TargetType:  params.TargetType,
						Operation:   metrics.OperationRead,
						TargetName:  target.Name,
						ServiceCode: fmt.Sprintf("0x%02X", uint8(cipclient.CIPServiceGetAttributeSingle)),
						Success:     success,
						RTTMs:       rtt,
						Status:      resp.Status,
						Error:       errorMsg,
					}
					params.MetricsSink.Record(metric)

					if !success {
						params.Logger.LogOperation(
							"READ",
							target.Name,
							fmt.Sprintf("0x%02X", uint8(cipclient.CIPServiceGetAttributeSingle)),
							success,
							rtt,
							resp.Status,
							err,
						)
					}
				}
			}
		}

		// Disconnect
		if err := client.Disconnect(ctx); err != nil {
			params.Logger.Error("Disconnect failed in cycle %d: %v", cycleCount, err)
		}

		// Sleep between cycles
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(params.Interval):
		}
	}

	elapsed := time.Since(startTime)
	params.Logger.Info("Churn scenario completed: %d cycles in %v, %d failed connections", cycleCount, elapsed, failedConnections)

	return nil
}
