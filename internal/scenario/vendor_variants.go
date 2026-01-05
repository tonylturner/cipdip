package scenario

// Vendor-variants scenario: cycle through protocol profiles and replay traffic.

import (
	"context"
	"fmt"
	"github.com/tturner/cipdip/internal/cip/spec"
	"math/rand"
	"time"

	"github.com/tturner/cipdip/internal/cip/codec"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/metrics"
	"github.com/tturner/cipdip/internal/progress"
)

// VendorVariantsScenario implements protocol variant replay.
type VendorVariantsScenario struct {
	writeCounters map[string]int64
	writeToggles  map[string]bool
}

// Run executes the vendor-variants scenario.
func (s *VendorVariantsScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting vendor_variants scenario")
	params.Logger.Verbose("  Variants: %d", len(cfg.ProtocolVariants))
	params.Logger.Verbose("  Interval: %v", params.Interval)
	params.Logger.Verbose("  Duration: %v", params.Duration)

	if len(cfg.ProtocolVariants) == 0 {
		return fmt.Errorf("vendor_variants requires protocol_variants in config")
	}

	s.writeCounters = make(map[string]int64)
	s.writeToggles = make(map[string]bool)

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

	prevProfile := cipclient.CurrentProtocolProfile()
	defer cipclient.SetProtocolProfile(prevProfile)

	perVariant := params.Duration / time.Duration(len(cfg.ProtocolVariants))
	if perVariant < 100*time.Millisecond {
		perVariant = 100 * time.Millisecond
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for _, variant := range cfg.ProtocolVariants {
		profile := cipclient.ResolveProtocolProfile(
			variant.Mode,
			variant.Variant,
			variant.Overrides.ENIPEndianness,
			variant.Overrides.CIPEndianness,
			variant.Overrides.CIPPathSize,
			variant.Overrides.CIPResponseReserved,
			variant.Overrides.UseCPF,
			variant.Overrides.IOSequenceMode,
		)
		cipclient.SetProtocolProfile(profile)

		variantName := variant.Variant
		if variantName == "" {
			variantName = variant.Mode
		}
		scenarioName := fmt.Sprintf("vendor_variants:%s", variantName)

		deadline := time.Now().Add(perVariant)
		ctxVariant, cancel := context.WithDeadline(ctx, deadline)
		totalOps := int64(perVariant / params.Interval)
		if totalOps == 0 {
			totalOps = 1
		}
		progressBar := progress.NewProgressBar(totalOps, scenarioName)

		var lastOp time.Time
		for {
			select {
			case <-ctxVariant.Done():
				cancel()
				progressBar.Finish()
				goto nextVariant
			default:
			}

			if time.Now().After(deadline) {
				cancel()
				progressBar.Finish()
				break
			}

			if cfg.ScenarioJitterMs > 0 {
				jitterDelay := time.Duration(rng.Intn(cfg.ScenarioJitterMs+1)) * time.Millisecond
				time.Sleep(jitterDelay)
			}

			jitterMs := computeJitterMs(&lastOp, params.Interval)

			for _, target := range cfg.ReadTargets {
				path := protocol.CIPPath{
					Class:     target.Class,
					Instance:  target.Instance,
					Attribute: target.Attribute,
					Name:      target.Name,
				}

				start := time.Now()
				resp, err := client.ReadAttribute(ctxVariant, path)
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
					Scenario:    scenarioName,
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

			for _, target := range cfg.WriteTargets {
				path := protocol.CIPPath{
					Class:     target.Class,
					Instance:  target.Instance,
					Attribute: target.Attribute,
					Name:      target.Name,
				}

				value := s.generateValue(target)
				valueBytes := make([]byte, 4)
				order := cipclient.CurrentProtocolProfile().CIPByteOrder
				codec.PutUint32(order, valueBytes, uint32(value))

				start := time.Now()
				resp, err := client.WriteAttribute(ctxVariant, path, valueBytes)
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
					Scenario:    scenarioName,
					TargetType:  params.TargetType,
					Operation:   metrics.OperationWrite,
					TargetName:  target.Name,
					ServiceCode: fmt.Sprintf("0x%02X", uint8(spec.CIPServiceSetAttributeSingle)),
					Success:     success,
					RTTMs:       rtt,
					JitterMs:    jitterMs,
					Status:      resp.Status,
					Error:       errorMsg,
					Outcome:     classifyOutcome(err, resp.Status),
				}
				params.MetricsSink.Record(metric)
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
				resp, err := client.InvokeService(ctxVariant, req)
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
					Scenario:    scenarioName,
					TargetType:  params.TargetType,
					Operation:   metrics.OperationCustom,
					TargetName:  target.Name,
					ServiceCode: fmt.Sprintf("0x%02X", uint8(serviceCode)),
					Success:     success,
					RTTMs:       rtt,
					JitterMs:    jitterMs,
					Status:      resp.Status,
					Error:       errorMsg,
					Outcome:     classifyOutcome(err, resp.Status),
				}
				params.MetricsSink.Record(metric)
			}

			progressBar.Increment()

			select {
			case <-ctxVariant.Done():
				cancel()
				progressBar.Finish()
				goto nextVariant
			case <-time.After(params.Interval):
			}
		}

	nextVariant:
		continue
	}

	return nil
}

func (s *VendorVariantsScenario) generateValue(target config.CIPTarget) int64 {
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
		val := s.writeCounters[target.Name]
		s.writeCounters[target.Name] = val + 1
		return val
	}
}
