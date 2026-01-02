package scenario

// Unconnected-send scenario: UCMM wrapper with embedded CIP requests.

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/metrics"
	"github.com/tturner/cipdip/internal/progress"
)

// UnconnectedSendScenario implements UCMM unconnected send tests.
type UnconnectedSendScenario struct{}

// Run executes the unconnected_send scenario.
func (s *UnconnectedSendScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting unconnected_send scenario")
	params.Logger.Verbose("  Edge targets: %d", len(cfg.EdgeTargets))
	params.Logger.Verbose("  Interval: %v", params.Interval)
	params.Logger.Verbose("  Duration: %v", params.Duration)

	if len(cfg.EdgeTargets) == 0 {
		return fmt.Errorf("unconnected_send requires edge_targets in config")
	}

	port := params.Port
	if port == 0 {
		port = cfg.Adapter.Port
		if port == 0 {
			port = 44818
		}
	}
	if err := client.Connect(ctx, params.IP, port); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Disconnect(ctx)

	filtered := make([]config.EdgeTarget, 0, len(cfg.EdgeTargets))
	for _, target := range cfg.EdgeTargets {
		if target.Service == config.ServiceCustom || target.Service == config.ServiceGetAttributeSingle || target.Service == config.ServiceSetAttributeSingle {
			filtered = append(filtered, target)
		}
	}
	if len(filtered) == 0 {
		return fmt.Errorf("unconnected_send has no usable edge_targets")
	}

	deadline := time.Now().Add(params.Duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	totalOps := int64(params.Duration / params.Interval)
	if totalOps == 0 {
		totalOps = 1
	}
	progressBar := progress.NewProgressBar(totalOps, "Unconnected-send scenario")
	defer progressBar.Finish()

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var lastOp time.Time

	for {
		select {
		case <-ctx.Done():
			params.Logger.Info("unconnected_send scenario completed (duration expired or cancelled)")
			return nil
		default:
		}

		if time.Now().After(deadline) {
			break
		}

		for _, target := range filtered {
			if cfg.ScenarioJitterMs > 0 {
				jitterDelay := time.Duration(rng.Intn(cfg.ScenarioJitterMs+1)) * time.Millisecond
				time.Sleep(jitterDelay)
			}

			serviceCode, err := serviceCodeForTarget(target.Service, target.ServiceCode)
			if err != nil {
				return err
			}
			payload, err := parseHexPayload(target.RequestPayloadHex)
			if err != nil {
				return fmt.Errorf("edge target %s payload: %w", target.Name, err)
			}

			embeddedReq := cipclient.CIPRequest{
				Service: serviceCode,
				Path: cipclient.CIPPath{
					Class:     target.Class,
					Instance:  target.Instance,
					Attribute: target.Attribute,
					Name:      target.Name,
				},
				Payload: payload,
			}

			jitterMs := computeJitterMs(&lastOp, params.Interval)
			start := time.Now()
			outerResp, embeddedResp, err := client.InvokeUnconnectedSend(ctx, embeddedReq, cipclient.UnconnectedSendOptions{})
			rtt := time.Since(start).Seconds() * 1000

			status := uint8(0)
			if err != nil {
				status = 0xFF
			} else if embeddedResp.Status != 0 {
				status = embeddedResp.Status
			} else {
				status = outerResp.Status
			}

			if err == nil && target.ForceStatus != nil {
				status = *target.ForceStatus
			}

			outcome := classifyOutcome(err, status)
			success := err == nil && status == 0

			var errorMsg string
			if err != nil {
				errorMsg = err.Error()
			} else if status != 0 {
				if target.ForceStatus != nil {
					errorMsg = fmt.Sprintf("Forced CIP status: 0x%02X", status)
				} else {
					errorMsg = fmt.Sprintf("CIP status: 0x%02X", status)
				}
			}

			metric := metrics.Metric{
				Timestamp:       time.Now(),
				Scenario:        "unconnected_send",
				TargetType:      params.TargetType,
				Operation:       metrics.OperationCustom,
				TargetName:      target.Name,
				ServiceCode:     fmt.Sprintf("0x%02X->0x%02X", uint8(cipclient.CIPServiceUnconnectedSend), uint8(serviceCode)),
				Success:         success,
				RTTMs:           rtt,
				JitterMs:        jitterMs,
				Status:          status,
				Error:           errorMsg,
				Outcome:         outcome,
				ExpectedOutcome: target.ExpectedOutcome,
			}
			params.MetricsSink.Record(metric)
		}

		progressBar.Increment()
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(params.Interval):
		}
	}

	return nil
}
