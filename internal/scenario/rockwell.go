package scenario

// Rockwell scenario: consolidated Logix + ENBT edge cases.

import (
	"context"
	"fmt"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"math/rand"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/metrics"
	"github.com/tturner/cipdip/internal/progress"
)

// RockwellScenario implements Rockwell-specific edge cases.
type RockwellScenario struct{}

// Run executes the rockwell scenario.
func (s *RockwellScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting rockwell scenario")
	params.Logger.Verbose("  Interval: %v", params.Interval)
	params.Logger.Verbose("  Duration: %v", params.Duration)

	targets := buildRockwellTargets(cfg)
	if len(targets) == 0 {
		return fmt.Errorf("rockwell scenario has no targets (check edge_targets or defaults)")
	}
	params.Logger.Verbose("  Targets: %d", len(targets))

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
	progressBar := progress.NewProgressBar(totalOps, "Rockwell scenario")
	defer progressBar.Finish()

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var lastOp time.Time

	for {
		select {
		case <-ctx.Done():
			params.Logger.Info("rockwell scenario completed (duration expired or cancelled)")
			return nil
		default:
		}

		if time.Now().After(deadline) {
			break
		}

		for _, target := range targets {
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
				return fmt.Errorf("rockwell target %s payload: %w", target.Name, err)
			}

			jitterMs := computeJitterMs(&lastOp, params.Interval)
			start := time.Now()
			resp, err := client.InvokeService(ctx, req)
			rtt := time.Since(start).Seconds() * 1000

			outcome := classifyOutcome(err, resp.Status)
			success := err == nil && resp.Status == 0

			var errorMsg string
			if err != nil {
				errorMsg = err.Error()
			} else if resp.Status != 0 {
				errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
			}

			metric := metrics.Metric{
				Timestamp:       time.Now(),
				Scenario:        "rockwell",
				TargetType:      params.TargetType,
				Operation:       metrics.OperationCustom,
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

func buildRockwellTargets(cfg *config.Config) []config.EdgeTarget {
	allowedServices := map[uint8]bool{
		uint8(protocol.CIPServiceExecutePCCC):          true,
		uint8(protocol.CIPServiceReadTag):              true,
		uint8(protocol.CIPServiceWriteTag):             true,
		uint8(protocol.CIPServiceReadModifyWrite):      true,
		uint8(protocol.CIPServiceReadTagFragmented):    true,
		uint8(protocol.CIPServiceWriteTagFragmented):   true,
		uint8(protocol.CIPServiceGetInstanceAttrList):  true,
		uint8(protocol.CIPServiceGetConnectionData):    true,
		uint8(protocol.CIPServiceSearchConnectionData): true,
		uint8(protocol.CIPServiceGetConnectionOwner):   true,
		uint8(protocol.CIPServiceLargeForwardOpen):     true,
		0x51: true, // Unknown service observed in ENBT/PCAPs
	}

	filtered := make([]config.EdgeTarget, 0, len(cfg.EdgeTargets))
	for _, target := range cfg.EdgeTargets {
		if target.Service != config.ServiceCustom {
			continue
		}
		if !allowedServices[target.ServiceCode] {
			continue
		}
		filtered = append(filtered, target)
	}
	if len(filtered) > 0 {
		return filtered
	}

	targets := []config.EdgeTarget{
		{
			Name:            "Rockwell_Execute_PCCC",
			Service:         config.ServiceCustom,
			ServiceCode:     uint8(protocol.CIPServiceExecutePCCC),
			Class:           0x0067,
			Instance:        0x0001,
			Attribute:       0x0000,
			ExpectedOutcome: "any",
		},
		{
			Name:              "Rockwell_Read_Tag",
			Service:           config.ServiceCustom,
			ServiceCode:       uint8(protocol.CIPServiceReadTag),
			Class:             0x0067,
			Instance:          0x0001,
			Attribute:         0x0000,
			RequestPayloadHex: "0100", // element count = 1
			ExpectedOutcome:   "any",
		},
		{
			Name:              "Rockwell_Write_Tag",
			Service:           config.ServiceCustom,
			ServiceCode:       uint8(protocol.CIPServiceWriteTag),
			Class:             0x0067,
			Instance:          0x0001,
			Attribute:         0x0000,
			RequestPayloadHex: "C4000100000000", // DINT, 1 element, 4 bytes data
			ExpectedOutcome:   "any",
		},
		{
			Name:              "Rockwell_Read_Tag_Fragmented",
			Service:           config.ServiceCustom,
			ServiceCode:       uint8(protocol.CIPServiceReadTagFragmented),
			Class:             0x0067,
			Instance:          0x0001,
			Attribute:         0x0000,
			RequestPayloadHex: "010000000000", // element count + byte offset
			ExpectedOutcome:   "any",
		},
		{
			Name:              "Rockwell_Write_Tag_Fragmented",
			Service:           config.ServiceCustom,
			ServiceCode:       uint8(protocol.CIPServiceWriteTagFragmented),
			Class:             0x0067,
			Instance:          0x0001,
			Attribute:         0x0000,
			RequestPayloadHex: "C400010000000000000000", // DINT, count, offset, data
			ExpectedOutcome:   "any",
		},
		{
			Name:            "Rockwell_Get_Instance_Attribute_List",
			Service:         config.ServiceCustom,
			ServiceCode:     uint8(protocol.CIPServiceGetInstanceAttrList),
			Class:           0x0067,
			Instance:        0x0001,
			Attribute:       0x0000,
			ExpectedOutcome: "any",
		},
		{
			Name:            "Rockwell_Unknown_0x51_ENBT",
			Service:         config.ServiceCustom,
			ServiceCode:     0x51,
			Class:           0x00A1,
			Instance:        0x0001,
			Attribute:       0x0000,
			ExpectedOutcome: "any",
		},
		{
			Name:            "ConnMgr_Get_Connection_Data",
			Service:         config.ServiceCustom,
			ServiceCode:     uint8(protocol.CIPServiceGetConnectionData),
			Class:           0x0006,
			Instance:        0x0001,
			Attribute:       0x0000,
			ExpectedOutcome: "any",
		},
		{
			Name:            "ConnMgr_Search_Connection_Data",
			Service:         config.ServiceCustom,
			ServiceCode:     uint8(protocol.CIPServiceSearchConnectionData),
			Class:           0x0006,
			Instance:        0x0001,
			Attribute:       0x0000,
			ExpectedOutcome: "any",
		},
		{
			Name:            "ConnMgr_Get_Connection_Owner",
			Service:         config.ServiceCustom,
			ServiceCode:     uint8(protocol.CIPServiceGetConnectionOwner),
			Class:           0x0006,
			Instance:        0x0001,
			Attribute:       0x0000,
			ExpectedOutcome: "any",
		},
		{
			Name:            "ConnMgr_Large_Forward_Open",
			Service:         config.ServiceCustom,
			ServiceCode:     uint8(protocol.CIPServiceLargeForwardOpen),
			Class:           0x0006,
			Instance:        0x0001,
			Attribute:       0x0000,
			ExpectedOutcome: "any",
		},
	}

	if !hasENBTProfile(cfg) {
		return filterOutENBTTargets(targets)
	}

	return targets
}

func hasENBTProfile(cfg *config.Config) bool {
	if cfg.Protocol.Variant == "rockwell_enbt" {
		return true
	}
	for _, variant := range cfg.ProtocolVariants {
		if variant.Variant == "rockwell_enbt" {
			return true
		}
	}
	return false
}

func filterOutENBTTargets(targets []config.EdgeTarget) []config.EdgeTarget {
	filtered := make([]config.EdgeTarget, 0, len(targets))
	for _, target := range targets {
		if target.Class == 0x00A1 {
			continue
		}
		filtered = append(filtered, target)
	}
	return filtered
}
