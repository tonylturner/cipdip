package scenario

// Mixed scenario: Medium-frequency mixed reads and writes

import (
	"context"
	"fmt"
	"github.com/tturner/cipdip/internal/cip/spec"
	"time"

	"github.com/tturner/cipdip/internal/cip/codec"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/metrics"
	"github.com/tturner/cipdip/internal/progress"
)

// MixedScenario implements the mixed scenario
type MixedScenario struct {
	writeCounters map[string]int64 // Track counters for increment pattern
	writeToggles  map[string]bool  // Track toggle state for toggle pattern
}

// Run executes the mixed scenario
func (s *MixedScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting mixed scenario")
	params.Logger.Verbose("  Read targets: %d", len(cfg.ReadTargets))
	params.Logger.Verbose("  Write targets: %d", len(cfg.WriteTargets))
	params.Logger.Verbose("  Custom targets: %d", len(cfg.CustomTargets))
	params.Logger.Verbose("  Interval: %v", params.Interval)
	params.Logger.Verbose("  Duration: %v", params.Duration)

	// Initialize write state
	s.writeCounters = make(map[string]int64)
	s.writeToggles = make(map[string]bool)

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
	fmt.Printf("[CLIENT] Starting mixed scenario (reads: %d, writes: %d, interval: %dms)\n", len(cfg.ReadTargets), len(cfg.WriteTargets), params.Interval.Milliseconds())
	fmt.Printf("[CLIENT] Will run for %d seconds or until interrupted\n\n", int(params.Duration.Seconds()))

	// Calculate total operations for progress bar
	totalOps := int64(params.Duration / params.Interval)
	if totalOps == 0 {
		totalOps = 1 // At least 1 operation
	}
	progressBar := progress.NewProgressBar(totalOps, "Mixed scenario")
	defer progressBar.Finish()

	// Main loop
	for {
		select {
		case <-ctx.Done():
			params.Logger.Info("Mixed scenario completed (duration expired or cancelled)")
			return nil
		default:
		}

		// Check if we've exceeded duration
		if time.Now().After(deadline) {
			break
		}

		// Perform reads for all read targets
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

			success := err == nil && resp.Status == 0
			var errorMsg string
			if err != nil {
				errorMsg = err.Error()
			} else if resp.Status != 0 {
				errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
			}

			metric := metrics.Metric{
				Timestamp:   time.Now(),
				Scenario:    "mixed",
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
				Scenario:    "mixed",
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

		// Perform writes for all write targets
		for _, target := range cfg.WriteTargets {
			path := protocol.CIPPath{
				Class:     target.Class,
				Instance:  target.Instance,
				Attribute: target.Attribute,
				Name:      target.Name,
			}

			// Generate value based on pattern
			value := s.generateValue(target)

			// Encode value to bytes (using 32-bit integer for now)
			valueBytes := make([]byte, 4)
			order := cipclient.CurrentProtocolProfile().CIPByteOrder
			codec.PutUint32(order, valueBytes, uint32(value))

			start := time.Now()
			resp, err := client.WriteAttribute(ctx, path, valueBytes)
			rtt := time.Since(start).Seconds() * 1000

			// Log operation
			if err == nil && resp.Status == 0 {
				fmt.Printf("[CLIENT] Write %s: class=0x%04X instance=0x%04X status=0x%02X value=%d RTT=%.2fms\n",
					target.Name, path.Class, path.Instance, resp.Status, value, rtt)
			} else {
				errorMsg := "unknown error"
				if err != nil {
					errorMsg = err.Error()
				} else if resp.Status != 0 {
					errorMsg = fmt.Sprintf("CIP status 0x%02X", resp.Status)
				}
				fmt.Printf("[CLIENT] Write %s FAILED: %s\n", target.Name, errorMsg)
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
				Scenario:    "mixed",
				TargetType:  params.TargetType,
				Operation:   metrics.OperationWrite,
				TargetName:  target.Name,
				ServiceCode: fmt.Sprintf("0x%02X", uint8(spec.CIPServiceSetAttributeSingle)),
				Success:     success,
				RTTMs:       rtt,
				Status:      resp.Status,
				Error:       errorMsg,
			}
			params.MetricsSink.Record(metric)

			params.Logger.LogOperation(
				"WRITE",
				target.Name,
				fmt.Sprintf("0x%02X", uint8(spec.CIPServiceSetAttributeSingle)),
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
	params.Logger.Info("Mixed scenario completed: %d loops in %v", loopCount, elapsed)

	return nil
}

// generateValue generates a value based on the target's pattern
func (s *MixedScenario) generateValue(target config.CIPTarget) int64 {
	switch target.Pattern {
	case "increment":
		val := s.writeCounters[target.Name]
		s.writeCounters[target.Name] = val + 1
		return val
	case "toggle":
		val := s.writeToggles[target.Name]
		s.writeToggles[target.Name] = !val
		if val {
			return 1
		}
		return 0
	case "constant":
		return target.InitialValue
	default:
		// Default to increment if pattern not specified
		val := s.writeCounters[target.Name]
		s.writeCounters[target.Name] = val + 1
		return val
	}
}
