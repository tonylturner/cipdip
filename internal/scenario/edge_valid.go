package scenario

// Edge-valid scenario: protocol-valid edge cases for DPI falsification.

import (
	"context"
	"fmt"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"math/rand"
	"time"

	cipclient "github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/metrics"
	"github.com/tturner/cipdip/internal/progress"
)

// EdgeValidScenario implements protocol-valid edge case traffic.
type EdgeValidScenario struct{}

// Run executes the edge-valid scenario.
func (s *EdgeValidScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting edge_valid scenario")
	params.Logger.Verbose("  Edge targets: %d", len(cfg.EdgeTargets))
	params.Logger.Verbose("  Interval: %v", params.Interval)
	params.Logger.Verbose("  Duration: %v", params.Duration)

	if len(cfg.EdgeTargets) == 0 {
		return fmt.Errorf("edge_valid requires edge_targets in config")
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

	deadline := time.Now().Add(params.Duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	totalOps := int64(params.Duration / params.Interval)
	if totalOps == 0 {
		totalOps = 1
	}
	progressBar := progress.NewProgressBar(totalOps, "Edge-valid scenario")
	defer progressBar.Finish()

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var lastOp time.Time

	for {
		select {
		case <-ctx.Done():
			params.Logger.Info("edge_valid scenario completed (duration expired or cancelled)")
			return nil
		default:
		}

		if time.Now().After(deadline) {
			break
		}

		for _, target := range cfg.EdgeTargets {
			if cfg.ScenarioJitterMs > 0 {
				jitterDelay := time.Duration(rng.Intn(cfg.ScenarioJitterMs+1)) * time.Millisecond
				time.Sleep(jitterDelay)
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
				return fmt.Errorf("edge target %s payload: %w", target.Name, err)
			}

			jitterMs := computeJitterMs(&lastOp, params.Interval)
			start := time.Now()
			resp, err := client.InvokeService(ctx, req)
			rtt := time.Since(start).Seconds() * 1000

			outcome := classifyOutcome(err, resp.Status)
			success := err == nil && resp.Status == 0

			operation := metrics.OperationCustom
			switch target.Service {
			case config.ServiceGetAttributeSingle:
				operation = metrics.OperationRead
			case config.ServiceSetAttributeSingle:
				operation = metrics.OperationWrite
			}

			var errorMsg string
			if err != nil {
				errorMsg = err.Error()
			} else if resp.Status != 0 {
				errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
			}

			metric := metrics.Metric{
				Timestamp:       time.Now(),
				Scenario:        "edge_valid",
				TargetType:      params.TargetType,
				Operation:       operation,
				TargetName:      target.Name,
				ServiceCode:     fmt.Sprintf("0x%02X", uint8(serviceCode)),
				Success:         success,
				RTTMs:           rtt,
				JitterMs:        jitterMs,
				Status:          resp.Status,
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


