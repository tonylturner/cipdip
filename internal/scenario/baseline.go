package scenario

// Baseline scenario: Low-frequency, read-only polling

import (
	"context"
	"fmt"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/metrics"
	"github.com/tturner/cipdip/internal/progress"
)

// BaselineScenario implements the baseline scenario
type BaselineScenario struct{}

// Run executes the baseline scenario
func (s *BaselineScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting baseline scenario")
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
	defer func() {
		fmt.Printf("[CLIENT] Disconnecting...\n")
		client.Disconnect(ctx)
	}()

	// Create deadline for duration
	deadline := time.Now().Add(params.Duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	loopCount := 0
	startTime := time.Now()
	fmt.Printf("[CLIENT] Starting baseline scenario (polling %d targets every %dms)\n", len(cfg.ReadTargets), params.Interval.Milliseconds())
	fmt.Printf("[CLIENT] Will run for %d seconds or until interrupted\n\n", int(params.Duration.Seconds()))

	// Calculate total operations for progress bar
	totalOps := int64(params.Duration / params.Interval)
	if totalOps == 0 {
		totalOps = 1 // At least 1 operation
	}
	progressBar := progress.NewProgressBar(totalOps, "Baseline scenario")
	defer progressBar.Finish()

	// Main loop
	for {
		select {
		case <-ctx.Done():
			params.Logger.Info("Baseline scenario completed (duration expired or cancelled)")
			fmt.Printf("[CLIENT] Scenario completed after %d operations\n", loopCount)
			return nil
		default:
		}

		// Check if we've exceeded duration
		if time.Now().After(deadline) {
			break
		}

		// Perform reads for each target
		for _, target := range cfg.ReadTargets {
			path := cipclient.CIPPath{
				Class:     target.Class,
				Instance:  target.Instance,
				Attribute: target.Attribute,
				Name:      target.Name,
			}

			// Measure RTT
			start := time.Now()
			resp, err := client.ReadAttribute(ctx, path)
			rtt := time.Since(start).Seconds() * 1000 // Convert to milliseconds

			// Log operation
			if err == nil && resp.Status == 0 {
				payloadSize := 0
				if resp.Payload != nil {
					payloadSize = len(resp.Payload)
				}
				fmt.Printf("[CLIENT] Read %s: class=0x%04X instance=0x%04X status=0x%02X payload=%d bytes RTT=%.2fms\n",
					target.Name, path.Class, path.Instance, resp.Status, payloadSize, rtt)
			} else {
				errorMsg := "unknown error"
				if err != nil {
					errorMsg = err.Error()
				} else if resp.Status != 0 {
					errorMsg = fmt.Sprintf("CIP status 0x%02X", resp.Status)
				}
				fmt.Printf("[CLIENT] Read %s FAILED: %s\n", target.Name, errorMsg)
			}

			// Record metric
			success := err == nil && resp.Status == 0
			var errorMsg string
			if err != nil {
				errorMsg = err.Error()
			} else if resp.Status != 0 {
				errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
			}

			metric := metrics.Metric{
				Timestamp:   time.Now(),
				Scenario:    "baseline",
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

			// Log operation
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

		for _, target := range cfg.CustomTargets {
			serviceCode, err := serviceCodeForTarget(target.Service, target.ServiceCode)
			if err != nil {
				return err
			}
			payload, err := parseHexPayload(target.RequestPayloadHex)
			if err != nil {
				return fmt.Errorf("custom target %s payload: %w", target.Name, err)
			}

			req := cipclient.CIPRequest{
				Service: serviceCode,
				Path: cipclient.CIPPath{
					Class:     target.Class,
					Instance:  target.Instance,
					Attribute: target.Attribute,
					Name:      target.Name,
				},
				Payload: payload,
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
				Scenario:    "baseline",
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

		loopCount++
		progressBar.Increment()

		// Sleep for interval
		select {
		case <-ctx.Done():
			break
		case <-time.After(params.Interval):
		}
	}

	elapsed := time.Since(startTime)
	params.Logger.Info("Baseline scenario completed: %d loops in %v", loopCount, elapsed)

	return nil
}
