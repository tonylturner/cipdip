package scenario

// DPI Explicit scenario: vendor-neutral DPI explicit messaging stress test for TCP 44818.
// Tests 6 phases with TIME-DRIVEN loops to stress DPI state tracking.
//
// SPEC: Minimum 300 seconds (5 minutes) runtime. NO early termination.
// Phase durations: 30s + 45s + 75s + 75s + 45s + 60s = 330s minimum.

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
	"github.com/tonylturner/cipdip/internal/config"
	"github.com/tonylturner/cipdip/internal/metrics"
)

// DPIExplicitScenario implements vendor-neutral DPI explicit messaging stress tests.
type DPIExplicitScenario struct{}

// DPIPhase represents a test phase in the DPI scenario.
type DPIPhase struct {
	Number      int
	Name        string
	Description string
	Weight      float64 // Proportional weight for duration calculation
}

// Phase weights (proportional to total duration)
// Weights sum to 1.0 - actual duration calculated at runtime from params.Duration
var dpiPhases = []DPIPhase{
	{0, "Baseline Sanity", "Control - verify basic explicit messaging works", 0.09},       // ~9%
	{1, "Read-Only Ambiguity", "Test single vs MSP encoding assumptions", 0.14},           // ~14%
	{2, "Connection Lifecycle", "ForwardOpen/Close churn stress test", 0.23},              // ~23%
	{3, "Large Payloads", "Fragmentation pressure and reassembly", 0.23},                  // ~23%
	{4, "Realistic Violations", "Invalid classes/instances/attributes, error handling", 0.14}, // ~14%
	{5, "Allowlist Precision", "Class/service filtering granularity", 0.17},               // ~17%
}

// PhaseResult tracks results for a single phase.
type PhaseResult struct {
	Phase         DPIPhase
	TotalRequests int
	Successes     int
	Failures      int
	Timeouts      int
	Resets        int
	RTTs          []float64
	Notes         []string
}

// Jitter configuration
const (
	minJitterMs = 50
	maxJitterMs = 200
)

// jitterSleep adds randomized delay between requests
func jitterSleep(ctx context.Context) {
	jitter := time.Duration(minJitterMs+rand.Intn(maxJitterMs-minJitterMs)) * time.Millisecond
	select {
	case <-ctx.Done():
	case <-time.After(jitter):
	}
}

// classifyOperation maps CIP service codes to metric operation types.
func classifyOperation(svc protocol.CIPServiceCode) metrics.OperationType {
	switch svc {
	case spec.CIPServiceGetAttributeSingle, spec.CIPServiceGetAttributeAll:
		return metrics.OperationRead
	case spec.CIPServiceSetAttributeSingle:
		return metrics.OperationWrite
	default:
		return metrics.OperationCustom
	}
}

// phaseSlug converts a phase name to a lowercase slug for metric labels.
func phaseSlug(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, " ", "_"))
}

// phaseScenarioLabel returns the scenario label for a given phase result.
func phaseScenarioLabel(result *PhaseResult) string {
	return fmt.Sprintf("dpi_explicit:phase_%d_%s", result.Phase.Number, phaseSlug(result.Phase.Name))
}

// Run executes the DPI explicit scenario for the requested duration.
// Duration is divided proportionally across 6 phases based on weights.
func (s *DPIExplicitScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting dpi_explicit scenario")
	params.Logger.Info("Target: %s:%d", params.IP, params.Port)
	params.Logger.Info("Duration: %v", params.Duration)

	port := params.Port
	if port == 0 {
		port = cfg.Adapter.Port
		if port == 0 {
			port = 44818
		}
	}

	// Calculate phase durations from weights
	phaseDurations := make([]time.Duration, len(dpiPhases))
	for i, phase := range dpiPhases {
		phaseDurations[i] = time.Duration(float64(params.Duration) * phase.Weight)
		// Ensure minimum 1 second per phase
		if phaseDurations[i] < time.Second {
			phaseDurations[i] = time.Second
		}
	}

	// Log phase breakdown
	params.Logger.Info("Phase breakdown:")
	for i, phase := range dpiPhases {
		params.Logger.Info("  Phase %d (%s): %v", phase.Number, phase.Name, phaseDurations[i].Round(time.Second))
	}

	startTime := time.Now()
	var allResults []PhaseResult

	// Run all 6 phases
	for i, phase := range dpiPhases {
		// Check if overall context is done
		select {
		case <-ctx.Done():
			params.Logger.Info("Context cancelled, stopping scenario")
			s.logFinalSummary(params, allResults)
			return ctx.Err()
		default:
		}

		phaseDuration := phaseDurations[i]
		elapsed := time.Since(startTime)

		params.Logger.Info("")
		params.Logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		params.Logger.Info("Phase %d: %s (duration: %v, elapsed: %v)", phase.Number, phase.Name, phaseDuration.Round(time.Second), elapsed.Round(time.Second))
		params.Logger.Info("  %s", phase.Description)
		params.Logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		result := PhaseResult{Phase: phase}

		// Create phase context with calculated duration
		phaseCtx, phaseCancel := context.WithTimeout(ctx, phaseDuration)

		// Run the phase for its duration
		switch phase.Number {
		case 0:
			s.runBaselineSanityLoop(phaseCtx, client, params, port, &result)
		case 1:
			s.runReadOnlyAmbiguityLoop(phaseCtx, client, params, port, &result)
		case 2:
			s.runConnectionLifecycleLoop(phaseCtx, client, params, port, &result)
		case 3:
			s.runLargePayloadsLoop(phaseCtx, client, params, port, &result)
		case 4:
			s.runRealisticViolationsLoop(phaseCtx, client, params, port, &result)
		case 5:
			s.runAllowlistPrecisionLoop(phaseCtx, client, params, port, &result)
		}

		phaseCancel()
		allResults = append(allResults, result)
		s.logPhaseSummary(params, &result)
	}

	// Log completion
	totalElapsed := time.Since(startTime)
	params.Logger.Info("")
	params.Logger.Info("Scenario completed: %v elapsed (requested: %v)", totalElapsed.Round(time.Second), params.Duration)

	s.logFinalSummary(params, allResults)
	return nil
}

// Phase 0: Baseline Sanity - TIME-DRIVEN LOOP
func (s *DPIExplicitScenario) runBaselineSanityLoop(ctx context.Context, client cipclient.Client, params ScenarioParams, port int, result *PhaseResult) {
	params.Logger.Info("  Running baseline sanity checks in loop until phase timeout...")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Connect for this iteration
		if err := client.Connect(ctx, params.IP, port); err != nil {
			result.Notes = append(result.Notes, fmt.Sprintf("Connect failed: %v", err))
			result.Failures++
			jitterSleep(ctx)
			continue
		}

		// Test 1: List Identity
		s.testRequest(ctx, client, params, result, "Identity Read", protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeAll,
			Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
		})
		jitterSleep(ctx)

		// Test 2: Read Identity Vendor ID
		s.testRequest(ctx, client, params, result, "Vendor ID Read", protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeSingle,
			Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x01},
		})
		jitterSleep(ctx)

		// Test 3: Read Identity Product Type
		s.testRequest(ctx, client, params, result, "Product Type Read", protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeSingle,
			Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x02},
		})
		jitterSleep(ctx)

		// Test 4: Message Router status
		s.testRequest(ctx, client, params, result, "Message Router", protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeAll,
			Path:    protocol.CIPPath{Class: 0x02, Instance: 0x01},
		})
		jitterSleep(ctx)

		// Test 5: Serial Number
		s.testRequest(ctx, client, params, result, "Serial Number", protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeSingle,
			Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x06},
		})
		jitterSleep(ctx)

		// Test 6: Product Name
		s.testRequest(ctx, client, params, result, "Product Name", protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeSingle,
			Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x07},
		})

		_ = client.Disconnect(ctx)
		jitterSleep(ctx)
	}
}

// Phase 1: Read-Only Ambiguity - TIME-DRIVEN LOOP
func (s *DPIExplicitScenario) runReadOnlyAmbiguityLoop(ctx context.Context, client cipclient.Client, params ScenarioParams, port int, result *PhaseResult) {
	params.Logger.Info("  Running MSP encoding tests in loop until phase timeout...")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := client.Connect(ctx, params.IP, port); err != nil {
			result.Notes = append(result.Notes, fmt.Sprintf("Connect failed: %v", err))
			result.Failures++
			jitterSleep(ctx)
			continue
		}

		// Single request
		s.testRequest(ctx, client, params, result, "Single Read (Identity)", protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeSingle,
			Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x01},
		})
		jitterSleep(ctx)

		// MSP with 3 requests
		mspRequests := []protocol.CIPRequest{
			{Service: spec.CIPServiceGetAttributeSingle, Path: protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x01}},
			{Service: spec.CIPServiceGetAttributeSingle, Path: protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x02}},
			{Service: spec.CIPServiceGetAttributeSingle, Path: protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x03}},
		}
		if mspReq, err := cipclient.BuildMultipleServiceRequest(mspRequests); err == nil {
			s.testRequest(ctx, client, params, result, "MSP Read (3 attrs)", mspReq)
		}
		jitterSleep(ctx)

		// MSP with 5 requests
		msp5 := []protocol.CIPRequest{
			{Service: spec.CIPServiceGetAttributeSingle, Path: protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x01}},
			{Service: spec.CIPServiceGetAttributeSingle, Path: protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x02}},
			{Service: spec.CIPServiceGetAttributeSingle, Path: protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x03}},
			{Service: spec.CIPServiceGetAttributeSingle, Path: protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x06}},
			{Service: spec.CIPServiceGetAttributeSingle, Path: protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x07}},
		}
		if mspReq, err := cipclient.BuildMultipleServiceRequest(msp5); err == nil {
			s.testRequest(ctx, client, params, result, "MSP Read (5 attrs)", mspReq)
		}
		jitterSleep(ctx)

		// MSP with mixed services
		mixedMSP := []protocol.CIPRequest{
			{Service: spec.CIPServiceGetAttributeSingle, Path: protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x01}},
			{Service: spec.CIPServiceGetAttributeAll, Path: protocol.CIPPath{Class: 0x01, Instance: 0x01}},
		}
		if mixedReq, err := cipclient.BuildMultipleServiceRequest(mixedMSP); err == nil {
			s.testRequest(ctx, client, params, result, "MSP Mixed Services", mixedReq)
		}
		jitterSleep(ctx)

		// MSP targeting different classes
		multiClassMSP := []protocol.CIPRequest{
			{Service: spec.CIPServiceGetAttributeAll, Path: protocol.CIPPath{Class: 0x01, Instance: 0x01}},
			{Service: spec.CIPServiceGetAttributeAll, Path: protocol.CIPPath{Class: 0x02, Instance: 0x01}},
		}
		if mcReq, err := cipclient.BuildMultipleServiceRequest(multiClassMSP); err == nil {
			s.testRequest(ctx, client, params, result, "MSP Multi-Class", mcReq)
		}

		_ = client.Disconnect(ctx)
		jitterSleep(ctx)
	}
}

// Phase 2: Connection Lifecycle - TIME-DRIVEN ForwardOpen/Close churn (MANDATORY)
func (s *DPIExplicitScenario) runConnectionLifecycleLoop(ctx context.Context, client cipclient.Client, params ScenarioParams, port int, result *PhaseResult) {
	params.Logger.Info("  Running ForwardOpen/Close churn loop (MANDATORY STRESS TEST)...")

	connectionID := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := client.Connect(ctx, params.IP, port); err != nil {
			result.Notes = append(result.Notes, fmt.Sprintf("Connect failed: %v", err))
			result.Failures++
			jitterSleep(ctx)
			continue
		}

		// Do multiple ForwardOpen/Close cycles per connection
		for cycle := 0; cycle < 3; cycle++ {
			select {
			case <-ctx.Done():
				_ = client.Disconnect(ctx)
				return
			default:
			}

			connectionID++
			connParams := cipclient.ConnectionParams{
				Name:          fmt.Sprintf("dpi_churn_%d", connectionID),
				OToTRPIMs:     100,
				TToORPIMs:     100,
				OToTSizeBytes: 500,
				TToOSizeBytes: 500,
			}

			// ForwardOpen
			start := time.Now()
			conn, err := client.ForwardOpen(ctx, connParams)
			rtt := time.Since(start).Seconds() * 1000

			result.TotalRequests++
			if err != nil {
				result.Failures++
				result.Notes = append(result.Notes, fmt.Sprintf("ForwardOpen %d failed: %v", connectionID, err))
				params.MetricsSink.Record(metrics.Metric{
					Timestamp:       time.Now(),
					Scenario:        phaseScenarioLabel(result),
					TargetType:      params.TargetType,
					Operation:       metrics.OperationForwardOpen,
					TargetName:      fmt.Sprintf("churn_%d", connectionID),
					ServiceCode:     "0x54",
					Success:         false,
					RTTMs:           rtt,
					Error:           err.Error(),
					Outcome:         classifyOutcome(err, 0),
					ExpectedOutcome: "success",
				})
				jitterSleep(ctx)
				continue
			}

			result.Successes++
			result.RTTs = append(result.RTTs, rtt)
			params.MetricsSink.Record(metrics.Metric{
				Timestamp:       time.Now(),
				Scenario:        phaseScenarioLabel(result),
				TargetType:      params.TargetType,
				Operation:       metrics.OperationForwardOpen,
				TargetName:      fmt.Sprintf("churn_%d", connectionID),
				ServiceCode:     "0x54",
				Success:         true,
				RTTMs:           rtt,
				Outcome:         "success",
				ExpectedOutcome: "success",
			})

			// Brief hold time before close
			jitterSleep(ctx)

			// ForwardClose
			start = time.Now()
			err = client.ForwardClose(ctx, conn)
			closeRTT := time.Since(start).Seconds() * 1000

			result.TotalRequests++
			if err != nil {
				result.Failures++
				params.MetricsSink.Record(metrics.Metric{
					Timestamp:       time.Now(),
					Scenario:        phaseScenarioLabel(result),
					TargetType:      params.TargetType,
					Operation:       metrics.OperationForwardClose,
					TargetName:      fmt.Sprintf("churn_%d", connectionID),
					ServiceCode:     "0x4E",
					Success:         false,
					RTTMs:           closeRTT,
					Error:           err.Error(),
					Outcome:         classifyOutcome(err, 0),
					ExpectedOutcome: "success",
				})
			} else {
				result.Successes++
				result.RTTs = append(result.RTTs, closeRTT)
				params.MetricsSink.Record(metrics.Metric{
					Timestamp:       time.Now(),
					Scenario:        phaseScenarioLabel(result),
					TargetType:      params.TargetType,
					Operation:       metrics.OperationForwardClose,
					TargetName:      fmt.Sprintf("churn_%d", connectionID),
					ServiceCode:     "0x4E",
					Success:         true,
					RTTMs:           closeRTT,
					Outcome:         "success",
					ExpectedOutcome: "success",
				})
			}

			jitterSleep(ctx)
		}

		_ = client.Disconnect(ctx)
		jitterSleep(ctx)
	}
}

// Phase 3: Large Payloads - TIME-DRIVEN fragmentation stress
func (s *DPIExplicitScenario) runLargePayloadsLoop(ctx context.Context, client cipclient.Client, params ScenarioParams, port int, result *PhaseResult) {
	params.Logger.Info("  Running large payload fragmentation tests in loop...")

	payloadSizes := []int{100, 500, 1000, 1400, 2000, 2500}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := client.Connect(ctx, params.IP, port); err != nil {
			result.Notes = append(result.Notes, fmt.Sprintf("Connect failed: %v", err))
			result.Failures++
			jitterSleep(ctx)
			continue
		}

		for _, size := range payloadSizes {
			select {
			case <-ctx.Done():
				_ = client.Disconnect(ctx)
				return
			default:
			}

			// Build large MSP request
			numRequests := size / 20
			if numRequests < 2 {
				numRequests = 2
			}
			if numRequests > 50 {
				numRequests = 50
			}

			requests := make([]protocol.CIPRequest, numRequests)
			for i := 0; i < numRequests; i++ {
				requests[i] = protocol.CIPRequest{
					Service: spec.CIPServiceGetAttributeSingle,
					Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: uint16((i % 7) + 1)},
				}
			}

			mspReq, err := cipclient.BuildMultipleServiceRequest(requests)
			if err != nil {
				result.Notes = append(result.Notes, fmt.Sprintf("MSP build error for size %d: %v", size, err))
				continue
			}

			testName := fmt.Sprintf("Large MSP (~%d bytes, %d reqs)", size, numRequests)
			s.testRequest(ctx, client, params, result, testName, mspReq)
			jitterSleep(ctx)
		}

		// Also test Get Attribute All
		s.testRequest(ctx, client, params, result, "Get All Attributes (Identity)", protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeAll,
			Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
		})
		jitterSleep(ctx)

		s.testRequest(ctx, client, params, result, "Get All Attributes (TCP/IP)", protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeAll,
			Path:    protocol.CIPPath{Class: 0xF5, Instance: 0x01},
		})

		_ = client.Disconnect(ctx)
		jitterSleep(ctx)
	}
}

// Phase 4: Realistic Violations - TIME-DRIVEN error handling tests
func (s *DPIExplicitScenario) runRealisticViolationsLoop(ctx context.Context, client cipclient.Client, params ScenarioParams, port int, result *PhaseResult) {
	params.Logger.Info("  Running error handling tests in loop...")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := client.Connect(ctx, params.IP, port); err != nil {
			result.Notes = append(result.Notes, fmt.Sprintf("Connect failed: %v", err))
			result.Failures++
			jitterSleep(ctx)
			continue
		}

		// Invalid class
		s.testRequestExpectError(ctx, client, params, result, "Invalid Class (0xFF)", protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeSingle,
			Path:    protocol.CIPPath{Class: 0xFF, Instance: 0x01, Attribute: 0x01},
		})
		jitterSleep(ctx)

		// Invalid instance
		s.testRequestExpectError(ctx, client, params, result, "Invalid Instance (0xFFFF)", protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeSingle,
			Path:    protocol.CIPPath{Class: 0x01, Instance: 0xFFFF, Attribute: 0x01},
		})
		jitterSleep(ctx)

		// Invalid attribute
		s.testRequestExpectError(ctx, client, params, result, "Invalid Attribute (0xFF)", protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeSingle,
			Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0xFF},
		})
		jitterSleep(ctx)

		// Invalid service
		s.testRequestExpectError(ctx, client, params, result, "Invalid Service (0xFF)", protocol.CIPRequest{
			Service: protocol.CIPServiceCode(0xFF),
			Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
		})
		jitterSleep(ctx)

		// Zero instance
		s.testRequest(ctx, client, params, result, "Zero Instance", protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeSingle,
			Path:    protocol.CIPPath{Class: 0x01, Instance: 0x00, Attribute: 0x01},
		})
		jitterSleep(ctx)

		// Reserved class
		s.testRequestExpectError(ctx, client, params, result, "Reserved Class (0x64)", protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeAll,
			Path:    protocol.CIPPath{Class: 0x64, Instance: 0x01},
		})
		jitterSleep(ctx)

		// High instance number
		s.testRequestExpectError(ctx, client, params, result, "High Instance (0x1000)", protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeAll,
			Path:    protocol.CIPPath{Class: 0x01, Instance: 0x1000},
		})

		_ = client.Disconnect(ctx)
		jitterSleep(ctx)
	}
}

// Phase 5: Allowlist Precision - TIME-DRIVEN filtering tests
func (s *DPIExplicitScenario) runAllowlistPrecisionLoop(ctx context.Context, client cipclient.Client, params ScenarioParams, port int, result *PhaseResult) {
	params.Logger.Info("  Running allowlist precision tests in loop...")

	allowedClasses := []struct {
		class uint16
		name  string
	}{
		{0x01, "Identity"},
		{0x02, "Message Router"},
		{0x06, "Connection Manager"},
		{0xF5, "TCP/IP Interface"},
		{0xF6, "Ethernet Link"},
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := client.Connect(ctx, params.IP, port); err != nil {
			result.Notes = append(result.Notes, fmt.Sprintf("Connect failed: %v", err))
			result.Failures++
			jitterSleep(ctx)
			continue
		}

		// Test all allowed classes
		for _, ac := range allowedClasses {
			s.testRequest(ctx, client, params, result, fmt.Sprintf("Class 0x%02X (%s)", ac.class, ac.name), protocol.CIPRequest{
				Service: spec.CIPServiceGetAttributeAll,
				Path:    protocol.CIPPath{Class: ac.class, Instance: 0x01},
			})
			jitterSleep(ctx)
		}

		// Test write service (should be restricted)
		s.testRequest(ctx, client, params, result, "Set Attribute (may be blocked)", protocol.CIPRequest{
			Service: spec.CIPServiceSetAttributeSingle,
			Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x07},
			Payload: []byte("Test"),
		})
		jitterSleep(ctx)

		// Test reset service (should be restricted)
		s.testRequest(ctx, client, params, result, "Reset Service (should be blocked)", protocol.CIPRequest{
			Service: spec.CIPServiceReset,
			Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
		})
		jitterSleep(ctx)

		// Test various individual attributes
		for attr := uint16(1); attr <= 7; attr++ {
			s.testRequest(ctx, client, params, result, fmt.Sprintf("Identity Attr %d", attr), protocol.CIPRequest{
				Service: spec.CIPServiceGetAttributeSingle,
				Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: attr},
			})
			jitterSleep(ctx)
		}

		_ = client.Disconnect(ctx)
		jitterSleep(ctx)
	}
}

// testRequest executes a request and records results
func (s *DPIExplicitScenario) testRequest(ctx context.Context, client cipclient.Client, params ScenarioParams, result *PhaseResult, name string, req protocol.CIPRequest) {
	start := time.Now()
	resp, err := client.InvokeService(ctx, req)
	rtt := time.Since(start).Seconds() * 1000

	result.TotalRequests++

	success := err == nil && resp.Status == 0
	var errorMsg string
	if err != nil {
		errorMsg = err.Error()
		if isTimeout(err) {
			result.Timeouts++
		} else if isReset(err) {
			result.Resets++
		}
	} else if resp.Status != 0 {
		errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
	}

	if success {
		result.Successes++
		result.RTTs = append(result.RTTs, rtt)
		params.Logger.Info("    ✓ %s: %.2fms", name, rtt)
	} else {
		result.Failures++
		params.Logger.Info("    ✗ %s: %s", name, errorMsg)
	}

	// Record metric
	params.MetricsSink.Record(metrics.Metric{
		Timestamp:       time.Now(),
		Scenario:        phaseScenarioLabel(result),
		TargetType:      params.TargetType,
		Operation:       classifyOperation(req.Service),
		TargetName:      name,
		ServiceCode:     fmt.Sprintf("0x%02X", uint8(req.Service)),
		Success:         success,
		RTTMs:           rtt,
		Status:          resp.Status,
		Error:           errorMsg,
		Outcome:         classifyOutcome(err, resp.Status),
		ExpectedOutcome: "success",
	})
}

// testRequestExpectError executes a request expecting an error response
func (s *DPIExplicitScenario) testRequestExpectError(ctx context.Context, client cipclient.Client, params ScenarioParams, result *PhaseResult, name string, req protocol.CIPRequest) {
	start := time.Now()
	resp, err := client.InvokeService(ctx, req)
	rtt := time.Since(start).Seconds() * 1000

	result.TotalRequests++

	gotProperError := err == nil && resp.Status != 0
	gotSuccess := err == nil && resp.Status == 0

	var errorMsg string
	if err != nil {
		errorMsg = err.Error()
		if isTimeout(err) {
			result.Timeouts++
			result.Notes = append(result.Notes, fmt.Sprintf("%s: Timeout (DPI may be dropping)", name))
		} else if isReset(err) {
			result.Resets++
			result.Notes = append(result.Notes, fmt.Sprintf("%s: TCP Reset (DPI blocking?)", name))
		}
		result.Failures++
		params.Logger.Info("    ? %s: %s (expected error response, got connection error)", name, errorMsg)
	} else if gotProperError {
		result.Successes++
		result.RTTs = append(result.RTTs, rtt)
		params.Logger.Info("    ✓ %s: CIP error 0x%02X (correct behavior)", name, resp.Status)
	} else if gotSuccess {
		result.Failures++
		result.Notes = append(result.Notes, fmt.Sprintf("%s: Unexpected success (false negative?)", name))
		params.Logger.Info("    ! %s: Unexpected success - security concern", name)
	}

	params.MetricsSink.Record(metrics.Metric{
		Timestamp:       time.Now(),
		Scenario:        phaseScenarioLabel(result),
		TargetType:      params.TargetType,
		Operation:       classifyOperation(req.Service),
		TargetName:      name,
		ServiceCode:     fmt.Sprintf("0x%02X", uint8(req.Service)),
		Success:         gotProperError,
		RTTMs:           rtt,
		Status:          resp.Status,
		Error:           errorMsg,
		Outcome:         classifyOutcome(err, resp.Status),
		ExpectedOutcome: "error",
	})
}

func (s *DPIExplicitScenario) logPhaseSummary(params ScenarioParams, result *PhaseResult) {
	params.Logger.Info("")
	params.Logger.Info("  Phase %d Summary:", result.Phase.Number)
	params.Logger.Info("    Weight: %.0f%%", result.Phase.Weight*100)
	params.Logger.Info("    Requests: %d total, %d success, %d fail", result.TotalRequests, result.Successes, result.Failures)
	if result.Timeouts > 0 {
		params.Logger.Info("    Timeouts: %d", result.Timeouts)
	}
	if result.Resets > 0 {
		params.Logger.Info("    TCP Resets: %d", result.Resets)
	}
	if len(result.RTTs) > 0 {
		median, p95 := calculatePercentiles(result.RTTs)
		params.Logger.Info("    RTT: median=%.2fms p95=%.2fms", median, p95)
	}
	for _, note := range result.Notes {
		params.Logger.Info("    Note: %s", note)
	}
}

func (s *DPIExplicitScenario) logFinalSummary(params ScenarioParams, results []PhaseResult) {
	params.Logger.Info("")
	params.Logger.Info("═══════════════════════════════════════════════════════════")
	params.Logger.Info("DPI EXPLICIT STRESS TEST SUMMARY")
	params.Logger.Info("═══════════════════════════════════════════════════════════")

	totalRequests := 0
	totalSuccesses := 0
	totalFailures := 0
	totalTimeouts := 0
	totalResets := 0
	var allRTTs []float64

	for _, r := range results {
		totalRequests += r.TotalRequests
		totalSuccesses += r.Successes
		totalFailures += r.Failures
		totalTimeouts += r.Timeouts
		totalResets += r.Resets
		allRTTs = append(allRTTs, r.RTTs...)

		status := "PASS"
		if r.Failures > 0 {
			status = "FAIL"
		}
		params.Logger.Info("  Phase %d (%s): %s (%d/%d)", r.Phase.Number, r.Phase.Name, status, r.Successes, r.TotalRequests)
	}

	params.Logger.Info("")
	if totalRequests > 0 {
		params.Logger.Info("Overall: %d/%d requests succeeded (%.1f%%)", totalSuccesses, totalRequests, float64(totalSuccesses)/float64(totalRequests)*100)
	} else {
		params.Logger.Info("Overall: No requests completed")
	}
	if totalTimeouts > 0 {
		params.Logger.Info("Timeouts: %d (potential silent drops)", totalTimeouts)
	}
	if totalResets > 0 {
		params.Logger.Info("TCP Resets: %d (active blocking)", totalResets)
	}
	if len(allRTTs) > 0 {
		median, p95 := calculatePercentiles(allRTTs)
		params.Logger.Info("RTT: median=%.2fms p95=%.2fms", median, p95)
	}
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return dpiContains(errStr, "timeout") || dpiContains(errStr, "deadline")
}

func isReset(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return dpiContains(errStr, "reset") || dpiContains(errStr, "RST") || dpiContains(errStr, "connection refused")
}

func dpiContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && dpiContainsAt(s, substr))
}

func dpiContainsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func calculatePercentiles(rtts []float64) (median, p95 float64) {
	if len(rtts) == 0 {
		return 0, 0
	}

	// Simple sort for percentile calculation
	sorted := make([]float64, len(rtts))
	copy(sorted, rtts)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	median = sorted[len(sorted)/2]
	p95Idx := int(float64(len(sorted)) * 0.95)
	if p95Idx >= len(sorted) {
		p95Idx = len(sorted) - 1
	}
	p95 = sorted[p95Idx]

	return median, p95
}
