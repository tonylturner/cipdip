package scenario

// Churn scenario: Repeated connection setup/teardown

import (
	"context"
	"fmt"
	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
	"time"

	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/config"
	"github.com/tonylturner/cipdip/internal/metrics"
	"github.com/tonylturner/cipdip/internal/progress"
)

// ChurnScenario implements the churn scenario
type ChurnScenario struct{}

// Run executes the churn scenario
func (s *ChurnScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting churn scenario")
	params.Logger.Verbose("  Read targets: %d", len(cfg.ReadTargets))
	params.Logger.Verbose("  Custom targets: %d", len(cfg.CustomTargets))
	params.Logger.Verbose("  Interval: %v", params.Interval)
	params.Logger.Verbose("  Duration: %v", params.Duration)

	// Create deadline for duration
	deadline := time.Now().Add(params.Duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	cycleCount := 0
	failedConnections := 0
	startTime := time.Now()
	fmt.Printf("[CLIENT] Starting churn scenario (connection cycles every %dms)\n", params.Interval.Milliseconds())
	fmt.Printf("[CLIENT] Will run for %d seconds or until interrupted\n\n", int(params.Duration.Seconds()))

	// Calculate total cycles for progress bar
	totalCycles := int64(params.Duration / params.Interval)
	if totalCycles == 0 {
		totalCycles = 1 // At least 1 cycle
	}
	progressBar := progress.NewProgressBar(totalCycles, "Churn scenario")
	defer progressBar.Finish()

	var lastOp time.Time

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
		jitterMs := computeJitterMs(&lastOp, params.Interval)

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
			fmt.Printf("[CLIENT] Cycle %d: Connection FAILED: %v\n", cycleCount, err)
			params.Logger.Error("Connection failed in cycle %d: %v", cycleCount, err)

			// Record connection failure metric
			metric := metrics.Metric{
				Timestamp:  time.Now(),
				Scenario:   "churn",
				TargetType: params.TargetType,
				Operation:  metrics.OperationRead,
				Success:    false,
				JitterMs:   jitterMs,
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
		} else {
			fmt.Printf("[CLIENT] Cycle %d: Connected successfully\n", cycleCount)
		}

		// Perform 1-3 reads per target
		readCount := 3
		if len(cfg.ReadTargets) > 0 {
			for i := 0; i < readCount; i++ {
				for _, target := range cfg.ReadTargets {
					// Check deadline before each operation
					select {
					case <-ctx.Done():
						params.Logger.Info("Churn scenario completed (deadline during reads)")
						return nil
					default:
					}

					path := protocol.CIPPath{
						Class:     target.Class,
						Instance:  target.Instance,
						Attribute: target.Attribute,
						Name:      target.Name,
					}

					start := time.Now()
					resp, err := client.ReadAttribute(ctx, path)
					rtt := time.Since(start).Seconds() * 1000

					// Log operation
					if err == nil && resp.Status == 0 {
						payloadSize := 0
						if resp.Payload != nil {
							payloadSize = len(resp.Payload)
						}
						fmt.Printf("[CLIENT] Cycle %d Read %s: status=0x%02X payload=%d bytes RTT=%.2fms\n",
							cycleCount, target.Name, resp.Status, payloadSize, rtt)
					} else {
						errorMsg := "unknown error"
						if err != nil {
							errorMsg = err.Error()
						} else if resp.Status != 0 {
							errorMsg = fmt.Sprintf("CIP status 0x%02X", resp.Status)
						}
						fmt.Printf("[CLIENT] Cycle %d Read %s FAILED: %s\n", cycleCount, target.Name, errorMsg)
					}

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
						ServiceCode: fmt.Sprintf("0x%02X", uint8(spec.CIPServiceGetAttributeSingle)),
						Success:     success,
						RTTMs:       rtt,
						JitterMs:    jitterMs,
						Status:      resp.Status,
						Error:       errorMsg,
					}
					params.MetricsSink.Record(metric)

					if !success {
						params.Logger.LogOperation(
							"READ",
							target.Name,
							fmt.Sprintf("0x%02X", uint8(spec.CIPServiceGetAttributeSingle)),
							success,
							rtt,
							resp.Status,
							err,
						)
					}
				}
			}
		}

		for _, target := range cfg.CustomTargets {
			// Check deadline before each operation
			select {
			case <-ctx.Done():
				params.Logger.Info("Churn scenario completed (deadline during custom targets)")
				return nil
			default:
			}

			serviceCode, err := serviceCodeForTarget(target.Service, target.ServiceCode)
			if err != nil {
				return err
			}
			req := protocol.CIPRequest{
				Service: serviceCode,
				Path: protocol.CIPPath{
					Class:     target.Class,
					Instance:  target.Instance,
					Attribute: target.Attribute,
					Name:      target.Name,
				},
			}
			req, err = applyTargetPayload(req, target.PayloadType, target.PayloadParams, target.RequestPayloadHex)
			if err != nil {
				return fmt.Errorf("custom target %s payload: %w", target.Name, err)
			}

			start := time.Now()
			resp, err := client.InvokeService(ctx, req)
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
				Operation:   metrics.OperationCustom,
				TargetName:  target.Name,
				ServiceCode: fmt.Sprintf("0x%02X", uint8(serviceCode)),
				Success:     success,
				RTTMs:       rtt,
				JitterMs:    jitterMs,
				Status:      resp.Status,
				Error:       errorMsg,
			}
			params.MetricsSink.Record(metric)

			if !success {
				params.Logger.LogOperation(
					"CUSTOM",
					target.Name,
					fmt.Sprintf("0x%02X", uint8(serviceCode)),
					success,
					rtt,
					resp.Status,
					err,
				)
			}
		}

		// Disconnect
		if err := client.Disconnect(ctx); err != nil {
			fmt.Printf("[CLIENT] Cycle %d: Disconnect FAILED: %v\n", cycleCount, err)
			params.Logger.Error("Disconnect failed in cycle %d: %v", cycleCount, err)
		} else {
			fmt.Printf("[CLIENT] Cycle %d: Disconnected\n", cycleCount)
		}

		progressBar.Increment()

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


