package scenario

// Stress scenario: High-frequency reads to stress DPI

import (
	"context"
	"fmt"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/metrics"
	"github.com/tturner/cipdip/internal/progress"
)

// StressScenario implements the stress scenario
type StressScenario struct{}

// Run executes the stress scenario
func (s *StressScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting stress scenario")
	params.Logger.Verbose("  Read targets: %d", len(cfg.ReadTargets))
	params.Logger.Verbose("  Custom targets: %d", len(cfg.CustomTargets))
	params.Logger.Verbose("  Interval: %v", params.Interval)
	params.Logger.Verbose("  Duration: %v", params.Duration)

	// Connect to the device
	port := params.Port
	if port == 0 {
		port = cfg.Adapter.Port
		if port == 0 {
			port = 44818 // Default
		}
	}
	if err := client.Connect(ctx, params.IP, port); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Disconnect(ctx)

	// Create deadline for duration
	deadline := time.Now().Add(params.Duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	loopCount := 0
	startTime := time.Now()
	timeoutCount := 0
	fmt.Printf("[CLIENT] Starting stress scenario (polling %d targets every %dms)\n", len(cfg.ReadTargets), params.Interval.Milliseconds())
	fmt.Printf("[CLIENT] Will run for %d seconds or until interrupted\n\n", int(params.Duration.Seconds()))

	// Calculate total operations for progress bar
	totalOps := int64(params.Duration / params.Interval)
	if totalOps == 0 {
		totalOps = 1 // At least 1 operation
	}
	progressBar := progress.NewProgressBar(totalOps, "Stress scenario")
	defer progressBar.Finish()

	// Main loop
	for {
		select {
		case <-ctx.Done():
			params.Logger.Info("Stress scenario completed (duration expired or cancelled)")
			return nil
		default:
		}

		// Check if we've exceeded duration
		if time.Now().After(deadline) {
			break
		}

		// Perform reads for each target (serial, one after another)
		for _, target := range cfg.ReadTargets {
			path := protocol.CIPPath{
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
				// Check for timeout
				if contains(errorMsg, "timeout") || contains(errorMsg, "deadline") {
					timeoutCount++
				}
			} else if resp.Status != 0 {
				errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
			}

			// Log operation (only failures in stress mode to reduce noise)
			if !success {
				fmt.Printf("[CLIENT] Read %s FAILED: %s (RTT=%.2fms)\n", target.Name, errorMsg, rtt)
			} else {
				// Log every 100th success to show activity without flooding
				if loopCount%100 == 0 {
					payloadSize := 0
					if resp.Payload != nil {
						payloadSize = len(resp.Payload)
					}
					fmt.Printf("[CLIENT] Read %s: status=0x%02X payload=%d bytes RTT=%.2fms (loop %d)\n",
						target.Name, resp.Status, payloadSize, rtt, loopCount)
				}
			}

			metric := metrics.Metric{
				Timestamp:   time.Now(),
				Scenario:    "stress",
				TargetType:  params.TargetType,
				Operation:   metrics.OperationRead,
				TargetName:  target.Name,
				ServiceCode: fmt.Sprintf("0x%02X", uint8(spec.CIPServiceGetAttributeSingle)),
				Success:     success,
				RTTMs:       rtt,
				Status:      resp.Status,
				Error:       errorMsg,
			}
			params.MetricsSink.Record(metric)

			// Only log failures in stress mode to reduce noise
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

		for _, target := range cfg.CustomTargets {
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
				Scenario:    "stress",
				TargetType:  params.TargetType,
				Operation:   metrics.OperationCustom,
				TargetName:  target.Name,
				ServiceCode: fmt.Sprintf("0x%02X", uint8(serviceCode)),
				Success:     success,
				RTTMs:       rtt,
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

		loopCount++
		progressBar.Increment()

		// Sleep for interval (short interval for stress)
		select {
		case <-ctx.Done():
			break
		case <-time.After(params.Interval):
		}
	}

	elapsed := time.Since(startTime)
	params.Logger.Info("Stress scenario completed: %d loops in %v, %d timeouts", loopCount, elapsed, timeoutCount)

	return nil
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
