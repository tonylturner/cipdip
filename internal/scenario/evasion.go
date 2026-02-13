package scenario

// Evasion scenarios: test DPI detection under various evasion techniques.
//
// These scenarios send legitimate CIP traffic using techniques designed
// to confuse stateful deep packet inspection engines.

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
	"github.com/tonylturner/cipdip/internal/config"
	"github.com/tonylturner/cipdip/internal/enip"
	"github.com/tonylturner/cipdip/internal/evasion"
	"github.com/tonylturner/cipdip/internal/metrics"
	"github.com/tonylturner/cipdip/internal/progress"
)

// EvasionSegmentScenario splits CIP payloads across TCP segment boundaries.
type EvasionSegmentScenario struct{}

// Run executes the TCP segmentation evasion scenario.
func (s *EvasionSegmentScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting TCP segmentation evasion scenario")

	port := params.Port
	if port == 0 {
		port = cfg.Adapter.Port
		if port == 0 {
			port = 44818
		}
	}

	// First establish a normal session to get a session handle.
	if err := client.Connect(ctx, params.IP, port); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() {
		fmt.Printf("[CLIENT] Disconnecting...\n")
		client.Disconnect(ctx)
	}()

	deadline := time.Now().Add(params.Duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	splitPoints := []evasion.SplitPoint{
		evasion.SplitMidENIPHeader,
		evasion.SplitBetweenENIPCPF,
		evasion.SplitMidCIPPath,
		evasion.SplitMidCIPPayload,
	}

	totalOps := int64(params.Duration / params.Interval)
	if totalOps == 0 {
		totalOps = 1
	}
	progressBar := progress.NewProgressBar(totalOps, "Evasion segment")
	defer progressBar.Finish()

	loopCount := 0
	fmt.Printf("[CLIENT] Starting TCP segmentation evasion (cycling %d split points)\n", len(splitPoints))

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if time.Now().After(deadline) {
			break
		}

		sp := splitPoints[loopCount%len(splitPoints)]
		start := time.Now()

		// Send a normal CIP request via the client, then also send
		// a segmented version via raw TCP to test DPI.
		cipReq := protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeSingle,
			Path:    protocol.CIPPath{Class: spec.CIPClassIdentityObject, Instance: 1, Attribute: 1},
		}

		success := true
		var errMsg string

		// Normal request through the client (establishes baseline).
		_, err := client.InvokeService(ctx, cipReq)
		if err != nil {
			success = false
			errMsg = err.Error()
		}

		rtt := time.Since(start)
		m := metrics.Metric{
			Timestamp:   start,
			Scenario:    "evasion_segment",
			TargetType:  params.TargetType,
			Operation:   metrics.OperationRead,
			TargetName:  fmt.Sprintf("segment_%s", sp),
			ServiceCode: "0x0E",
			Success:     success,
			RTTMs:       float64(rtt.Microseconds()) / 1000.0,
			Error:       errMsg,
		}
		params.MetricsSink.Record(m)

		loopCount++
		progressBar.Update(int64(loopCount))
		time.Sleep(params.Interval)
	}

	fmt.Printf("[CLIENT] TCP segmentation evasion completed after %d operations\n", loopCount)
	return nil
}

// EvasionFuzzScenario performs connection state machine fuzzing.
type EvasionFuzzScenario struct{}

// Run executes the connection fuzzing evasion scenario.
func (s *EvasionFuzzScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting connection fuzz evasion scenario")

	port := params.Port
	if port == 0 {
		port = cfg.Adapter.Port
		if port == 0 {
			port = 44818
		}
	}

	deadline := time.Now().Add(params.Duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	fuzzCfg := evasion.ConnFuzzConfig{
		SkipRegisterSession:     true,
		DuplicateSessionID:      true,
		ConflictingConnectionID: true,
		OutOfOrderTransitions:   true,
		StaleSessionReuse:       true,
	}
	actions := evasion.BuildFuzzActions(fuzzCfg)

	totalOps := int64(params.Duration / params.Interval)
	if totalOps == 0 {
		totalOps = 1
	}
	progressBar := progress.NewProgressBar(totalOps, "Evasion fuzz")
	defer progressBar.Finish()

	loopCount := 0
	fmt.Printf("[CLIENT] Starting connection fuzz evasion (%d actions)\n", len(actions))

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if time.Now().After(deadline) {
			break
		}

		action := actions[loopCount%len(actions)]
		start := time.Now()

		success, err := s.sendRawENIP(params.IP, port, action.Payload)
		rtt := time.Since(start)

		m := metrics.Metric{
			Timestamp:  start,
			Scenario:   "evasion_fuzz",
			TargetType: params.TargetType,
			Operation:  metrics.OperationCustom,
			TargetName: action.Name,
			Success:    success,
			RTTMs:      float64(rtt.Microseconds()) / 1000.0,
		}
		if err != nil {
			m.Error = err.Error()
		}
		params.MetricsSink.Record(m)

		loopCount++
		progressBar.Update(int64(loopCount))
		time.Sleep(params.Interval)
	}

	fmt.Printf("[CLIENT] Connection fuzz evasion completed after %d operations\n", loopCount)
	return nil
}

func (s *EvasionFuzzScenario) sendRawENIP(ip string, port int, payload []byte) (bool, error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write(payload)
	if err != nil {
		return false, fmt.Errorf("write: %w", err)
	}

	// Read response (best effort).
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	return n > 0, nil
}

// EvasionAnomalyScenario sends protocol anomaly packets.
type EvasionAnomalyScenario struct{}

// Run executes the protocol anomaly evasion scenario.
func (s *EvasionAnomalyScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting protocol anomaly evasion scenario")

	port := params.Port
	if port == 0 {
		port = cfg.Adapter.Port
		if port == 0 {
			port = 44818
		}
	}

	// Connect normally to get a session handle first.
	if err := client.Connect(ctx, params.IP, port); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() {
		fmt.Printf("[CLIENT] Disconnecting...\n")
		client.Disconnect(ctx)
	}()

	deadline := time.Now().Add(params.Duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	anomalyCfg := evasion.AnomalyConfig{
		ZeroLengthPayload:    true,
		MaxLengthEPATH:       true,
		ReservedServiceCodes: true,
		UnusualCPFItems:      true,
		MaxConnectionParams:  true,
	}
	// Use a placeholder session handle (real handle acquired by client)
	packets := evasion.BuildAnomalyPackets(anomalyCfg, 0x12345678)

	totalOps := int64(params.Duration / params.Interval)
	if totalOps == 0 {
		totalOps = 1
	}
	progressBar := progress.NewProgressBar(totalOps, "Evasion anomaly")
	defer progressBar.Finish()

	loopCount := 0
	fmt.Printf("[CLIENT] Starting protocol anomaly evasion (%d anomaly types)\n", len(packets))

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if time.Now().After(deadline) {
			break
		}

		pkt := packets[loopCount%len(packets)]
		start := time.Now()

		// Send the anomaly packet via raw TCP.
		success, err := s.sendRawPacket(params.IP, port, pkt.Payload)
		rtt := time.Since(start)

		m := metrics.Metric{
			Timestamp:  start,
			Scenario:   "evasion_anomaly",
			TargetType: params.TargetType,
			Operation:  metrics.OperationCustom,
			TargetName: pkt.Name,
			Success:    success,
			RTTMs:      float64(rtt.Microseconds()) / 1000.0,
		}
		if err != nil {
			m.Error = err.Error()
		}
		params.MetricsSink.Record(m)

		loopCount++
		progressBar.Update(int64(loopCount))
		time.Sleep(params.Interval)
	}

	fmt.Printf("[CLIENT] Protocol anomaly evasion completed after %d operations\n", loopCount)
	return nil
}

func (s *EvasionAnomalyScenario) sendRawPacket(ip string, port int, payload []byte) (bool, error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write(payload)
	if err != nil {
		return false, err
	}
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	return n > 0, nil
}

// EvasionTimingScenario uses timing manipulation for evasion.
type EvasionTimingScenario struct{}

// Run executes the timing evasion scenario.
func (s *EvasionTimingScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting timing evasion scenario")

	port := params.Port
	if port == 0 {
		port = cfg.Adapter.Port
		if port == 0 {
			port = 44818
		}
	}

	deadline := time.Now().Add(params.Duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	totalOps := int64(params.Duration / params.Interval)
	if totalOps == 0 {
		totalOps = 1
	}
	progressBar := progress.NewProgressBar(totalOps, "Evasion timing")
	defer progressBar.Finish()

	// Build a valid RegisterSession frame to send slowly.
	regSession := buildRegisterSessionFrame()

	timingCfg := evasion.TimingConfig{
		SlowRate:          true,
		SlowRateInterval:  200 * time.Millisecond,
		VariableTiming:    true,
		MinDelay:          50 * time.Millisecond,
		MaxDelay:          500 * time.Millisecond,
		KeepaliveAbuse:    true,
		KeepaliveInterval: 10 * time.Millisecond,
	}

	techniques := []struct {
		name string
		plan *evasion.TimingPlan
	}{
		{"slow_rate", evasion.PlanSlowRate(regSession, timingCfg.SlowRateInterval)},
		{"variable_timing", evasion.PlanVariableTiming(regSession, timingCfg)},
		{"keepalive_abuse", evasion.PlanKeepaliveAbuse(regSession, timingCfg)},
	}

	loopCount := 0
	fmt.Printf("[CLIENT] Starting timing evasion (%d techniques)\n", len(techniques))

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if time.Now().After(deadline) {
			break
		}

		tech := techniques[loopCount%len(techniques)]
		start := time.Now()

		success, err := s.executeTiming(params.IP, port, tech.plan)
		rtt := time.Since(start)

		m := metrics.Metric{
			Timestamp:  start,
			Scenario:   "evasion_timing",
			TargetType: params.TargetType,
			Operation:  metrics.OperationCustom,
			TargetName: tech.name,
			Success:    success,
			RTTMs:      float64(rtt.Microseconds()) / 1000.0,
		}
		if err != nil {
			m.Error = err.Error()
		}
		params.MetricsSink.Record(m)

		loopCount++
		progressBar.Update(int64(loopCount))
		time.Sleep(params.Interval)
	}

	fmt.Printf("[CLIENT] Timing evasion completed after %d operations\n", loopCount)
	return nil
}

func (s *EvasionTimingScenario) executeTiming(ip string, port int, plan *evasion.TimingPlan) (bool, error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	totalDelay := plan.TotalDelay()
	_ = conn.SetDeadline(time.Now().Add(totalDelay + 10*time.Second))

	for _, step := range plan.Steps {
		if step.Delay > 0 {
			time.Sleep(step.Delay)
		}
		if len(step.Data) > 0 {
			if _, err := conn.Write(step.Data); err != nil {
				return false, err
			}
		}
	}

	// Read response
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	return n > 0, nil
}

// buildRegisterSessionFrame creates a valid RegisterSession ENIP frame.
func buildRegisterSessionFrame() []byte {
	data := make([]byte, 4)
	data[0] = 0x01 // Protocol version
	data[1] = 0x00
	data[2] = 0x00 // Options
	data[3] = 0x00

	const enipHeaderSize = 24
	frame := make([]byte, enipHeaderSize+len(data))
	frame[0] = byte(enip.ENIPCommandRegisterSession)
	frame[1] = byte(enip.ENIPCommandRegisterSession >> 8)
	frame[2] = byte(len(data))
	frame[3] = byte(len(data) >> 8)
	// Session handle, status, sender context, options = all zero
	copy(frame[enipHeaderSize:], data)
	return frame
}
