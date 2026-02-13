package scenario

// Mixed-state scenario: interleave UCMM and connected I/O traffic.

import (
	"context"
	"fmt"
	"github.com/tonylturner/cipdip/internal/cip/spec"
	"math/rand"
	"time"

	"github.com/tonylturner/cipdip/internal/cip/codec"
	"github.com/tonylturner/cipdip/internal/cip/protocol"
	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/config"
	"github.com/tonylturner/cipdip/internal/metrics"
	"github.com/tonylturner/cipdip/internal/progress"
)

// MixedStateScenario implements mixed UCMM and connected I/O traffic.
type MixedStateScenario struct{}

// Run executes the mixed_state scenario.
func (s *MixedStateScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting mixed_state scenario")
	params.Logger.Verbose("  Read targets: %d", len(cfg.ReadTargets))
	params.Logger.Verbose("  I/O connections: %d", len(cfg.IOConnections))
	params.Logger.Verbose("  Interval: %v", params.Interval)
	params.Logger.Verbose("  Duration: %v", params.Duration)

	if len(cfg.IOConnections) == 0 {
		return fmt.Errorf("mixed_state requires io_connections in config")
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

	var ioConns []*cipclient.IOConnection
	for _, connCfg := range cfg.IOConnections {
		transport := connCfg.Transport
		if transport == "" {
			transport = "udp"
		}
		connParams := cipclient.ConnectionParams{
			Name:                  connCfg.Name,
			Transport:             transport,
			OToTRPIMs:             connCfg.OToTRPIMs,
			TToORPIMs:             connCfg.TToORPIMs,
			OToTSizeBytes:         connCfg.OToTSizeBytes,
			TToOSizeBytes:         connCfg.TToOSizeBytes,
			Priority:              connCfg.Priority,
			TransportClassTrigger: connCfg.TransportClassTrigger,
			Class:                 connCfg.Class,
			Instance:              connCfg.Instance,
			ConnectionPathHex:     connCfg.ConnectionPathHex,
		}

		conn, err := client.ForwardOpen(ctx, connParams)
		if err != nil {
			params.Logger.Error("Failed to open I/O connection %s: %v", connCfg.Name, err)
			continue
		}
		ioConns = append(ioConns, conn)
	}

	if len(ioConns) == 0 {
		return fmt.Errorf("no I/O connections could be established")
	}

	deadline := time.Now().Add(params.Duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	totalOps := int64(params.Duration / params.Interval)
	if totalOps == 0 {
		totalOps = 1
	}
	progressBar := progress.NewProgressBar(totalOps, "Mixed-state scenario")
	defer progressBar.Finish()

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var lastOp time.Time
	counter := uint32(0)

	for {
		select {
		case <-ctx.Done():
			params.Logger.Info("mixed_state scenario completed (duration expired or cancelled)")
			return nil
		default:
		}

		if time.Now().After(deadline) {
			break
		}

		if cfg.ScenarioJitterMs > 0 {
			jitterDelay := time.Duration(rng.Intn(cfg.ScenarioJitterMs+1)) * time.Millisecond
			time.Sleep(jitterDelay)
		}

		jitterMs := computeJitterMs(&lastOp, params.Interval)

		for _, target := range cfg.ReadTargets {
			// Check deadline before each operation
			select {
			case <-ctx.Done():
				params.Logger.Info("Mixed state scenario completed (deadline during reads)")
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

			success := err == nil && resp.Status == 0
			var errorMsg string
			if err != nil {
				errorMsg = err.Error()
			} else if resp.Status != 0 {
				errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
			}

			metric := metrics.Metric{
				Timestamp:   time.Now(),
				Scenario:    "mixed_state",
				TargetType:  params.TargetType,
				Operation:   metrics.OperationRead,
				TargetName:  target.Name,
				ServiceCode: fmt.Sprintf("0x%02X", uint8(spec.CIPServiceGetAttributeSingle)),
				Success:     success,
				RTTMs:       rtt,
				JitterMs:    jitterMs,
				Status:      resp.Status,
				Error:       errorMsg,
				Outcome:     classifyOutcome(err, resp.Status),
			}
			params.MetricsSink.Record(metric)
		}

		for i, conn := range ioConns {
			connCfg := cfg.IOConnections[i]

			counter++
			oToTData := make([]byte, connCfg.OToTSizeBytes)
			if len(oToTData) >= 4 {
				order := cipclient.CurrentProtocolProfile().CIPByteOrder
				codec.PutUint32(order, oToTData[0:4], counter)
			} else {
				oToTData[0] = byte(counter)
			}

			start := time.Now()
			err := client.SendIOData(ctx, conn, oToTData)
			rtt := time.Since(start).Seconds() * 1000

			metric := metrics.Metric{
				Timestamp:  time.Now(),
				Scenario:   "mixed_state",
				TargetType: params.TargetType,
				Operation:  metrics.OperationOTToTSend,
				TargetName: connCfg.Name,
				Success:    err == nil,
				RTTMs:      rtt,
				JitterMs:   jitterMs,
				Error:      errorString(err),
				Outcome:    classifyOutcome(err, 0),
			}
			params.MetricsSink.Record(metric)

			start = time.Now()
			_, err = client.ReceiveIOData(ctx, conn)
			rtt = time.Since(start).Seconds() * 1000

			metric = metrics.Metric{
				Timestamp:  time.Now(),
				Scenario:   "mixed_state",
				TargetType: params.TargetType,
				Operation:  metrics.OperationTToORecv,
				TargetName: connCfg.Name,
				Success:    err == nil,
				RTTMs:      rtt,
				JitterMs:   jitterMs,
				Error:      errorString(err),
				Outcome:    classifyOutcome(err, 0),
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

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}


