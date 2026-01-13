package scenario

// DPI Explicit scenario: vendor-neutral DPI explicit messaging test for TCP 44818.
// Tests 6 phases to identify DPI weaknesses and breakage points.

import (
	"context"
	"fmt"
	"time"

	cipclient "github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/metrics"
	"github.com/tturner/cipdip/internal/progress"
)

// DPIExplicitScenario implements vendor-neutral DPI explicit messaging tests.
type DPIExplicitScenario struct{}

// DPIPhase represents a test phase in the DPI scenario.
type DPIPhase struct {
	Number      int
	Name        string
	Description string
}

var dpiPhases = []DPIPhase{
	{0, "Baseline Sanity", "Control - verify basic explicit messaging works"},
	{1, "Read-Only Ambiguity", "Test single vs MSP encoding assumptions"},
	{2, "Connection Lifecycle", "Primary breakage test - ForwardOpen/Close churn"},
	{3, "Large Payloads", "Fragmentation pressure and reassembly"},
	{4, "Realistic Violations", "Invalid classes/instances/attributes, error handling"},
	{5, "Allowlist Precision", "Class/service filtering granularity"},
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

// Run executes the DPI explicit scenario.
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

	// Calculate time per phase
	phaseTime := params.Duration / time.Duration(len(dpiPhases))
	if phaseTime < 10*time.Second {
		phaseTime = 10 * time.Second
	}

	totalOps := int64(len(dpiPhases))
	progressBar := progress.NewProgressBar(totalOps, "DPI Explicit Test")
	defer progressBar.Finish()

	results := make([]PhaseResult, len(dpiPhases))

	for i, phase := range dpiPhases {
		select {
		case <-ctx.Done():
			params.Logger.Info("DPI scenario cancelled")
			return nil
		default:
		}

		params.Logger.Info("")
		params.Logger.Info("═══════════════════════════════════════════════════════════")
		params.Logger.Info("Phase %d: %s", phase.Number, phase.Name)
		params.Logger.Info("  %s", phase.Description)
		params.Logger.Info("═══════════════════════════════════════════════════════════")

		result := PhaseResult{Phase: phase}

		phaseCtx, cancel := context.WithTimeout(ctx, phaseTime)

		switch phase.Number {
		case 0:
			s.runBaselineSanity(phaseCtx, client, params, port, &result)
		case 1:
			s.runReadOnlyAmbiguity(phaseCtx, client, params, port, &result)
		case 2:
			s.runConnectionLifecycle(phaseCtx, client, params, port, &result)
		case 3:
			s.runLargePayloads(phaseCtx, client, params, port, &result)
		case 4:
			s.runRealisticViolations(phaseCtx, client, params, port, &result)
		case 5:
			s.runAllowlistPrecision(phaseCtx, client, params, port, &result)
		}

		cancel()
		results[i] = result

		// Log phase summary
		s.logPhaseSummary(params, &result)
		progressBar.Increment()
	}

	// Final summary
	s.logFinalSummary(params, results)

	return nil
}

// Phase 0: Baseline Sanity - verify basic explicit messaging works
func (s *DPIExplicitScenario) runBaselineSanity(ctx context.Context, client cipclient.Client, params ScenarioParams, port int, result *PhaseResult) {
	params.Logger.Info("  Testing basic connectivity and identity read...")

	// Connect
	if err := client.Connect(ctx, params.IP, port); err != nil {
		result.Notes = append(result.Notes, fmt.Sprintf("CRITICAL: Cannot connect: %v", err))
		result.Failures++
		return
	}
	defer client.Disconnect(ctx)

	// Test 1: List Identity
	s.testRequest(ctx, client, params, result, "Identity Read", protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeAll,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
	})

	// Test 2: Read Identity Vendor ID
	s.testRequest(ctx, client, params, result, "Vendor ID Read", protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x01},
	})

	// Test 3: Read Identity Product Type
	s.testRequest(ctx, client, params, result, "Product Type Read", protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x02},
	})

	// Test 4: Message Router status
	s.testRequest(ctx, client, params, result, "Message Router", protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeAll,
		Path:    protocol.CIPPath{Class: 0x02, Instance: 0x01},
	})

	if result.Failures == 0 {
		result.Notes = append(result.Notes, "Baseline sanity PASSED - basic messaging works")
	} else {
		result.Notes = append(result.Notes, "WARNING: Baseline failures detected - DPI may be blocking basic traffic")
	}
}

// Phase 1: Read-Only Ambiguity - test single vs MSP encoding
func (s *DPIExplicitScenario) runReadOnlyAmbiguity(ctx context.Context, client cipclient.Client, params ScenarioParams, port int, result *PhaseResult) {
	params.Logger.Info("  Testing single request vs MSP encoding ambiguity...")

	if err := client.Connect(ctx, params.IP, port); err != nil {
		result.Notes = append(result.Notes, fmt.Sprintf("Cannot connect: %v", err))
		result.Failures++
		return
	}
	defer client.Disconnect(ctx)

	// Test single requests
	s.testRequest(ctx, client, params, result, "Single Read (Identity)", protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x01},
	})

	// Test Multiple Service Packet with same request
	mspRequests := []protocol.CIPRequest{
		{Service: spec.CIPServiceGetAttributeSingle, Path: protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x01}},
		{Service: spec.CIPServiceGetAttributeSingle, Path: protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x02}},
		{Service: spec.CIPServiceGetAttributeSingle, Path: protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x03}},
	}

	mspReq, err := cipclient.BuildMultipleServiceRequest(mspRequests)
	if err != nil {
		result.Notes = append(result.Notes, fmt.Sprintf("MSP build error: %v", err))
		result.Failures++
	} else {
		s.testRequest(ctx, client, params, result, "MSP Read (3 attributes)", mspReq)
	}

	// Test MSP with mixed services
	mixedMSP := []protocol.CIPRequest{
		{Service: spec.CIPServiceGetAttributeSingle, Path: protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x01}},
		{Service: spec.CIPServiceGetAttributeAll, Path: protocol.CIPPath{Class: 0x01, Instance: 0x01}},
	}

	mixedReq, err := cipclient.BuildMultipleServiceRequest(mixedMSP)
	if err == nil {
		s.testRequest(ctx, client, params, result, "MSP Mixed Services", mixedReq)
	}
}

// Phase 2: Connection Lifecycle - ForwardOpen/Close churn
func (s *DPIExplicitScenario) runConnectionLifecycle(ctx context.Context, client cipclient.Client, params ScenarioParams, port int, result *PhaseResult) {
	params.Logger.Info("  Testing ForwardOpen/Close connection churn...")

	if err := client.Connect(ctx, params.IP, port); err != nil {
		result.Notes = append(result.Notes, fmt.Sprintf("Cannot connect: %v", err))
		result.Failures++
		return
	}
	defer client.Disconnect(ctx)

	// Churn connections
	churnCount := 5
	for i := 0; i < churnCount; i++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		connParams := cipclient.ConnectionParams{
			Name:          fmt.Sprintf("dpi_churn_%d", i),
			OToTRPIMs:     100, // 100ms
			TToORPIMs:     100,
			OToTSizeBytes: 500,
			TToOSizeBytes: 500,
		}

		start := time.Now()
		conn, err := client.ForwardOpen(ctx, connParams)
		rtt := time.Since(start).Seconds() * 1000

		result.TotalRequests++
		if err != nil {
			result.Failures++
			result.Notes = append(result.Notes, fmt.Sprintf("ForwardOpen %d failed: %v", i, err))

			// Record metric
			params.MetricsSink.Record(metrics.Metric{
				Timestamp:  time.Now(),
				Scenario:   "dpi_explicit",
				TargetType: params.TargetType,
				Operation:  metrics.OperationForwardOpen,
				TargetName: fmt.Sprintf("churn_%d", i),
				Success:    false,
				RTTMs:      rtt,
				Error:      err.Error(),
			})
			continue
		}

		result.Successes++
		result.RTTs = append(result.RTTs, rtt)

		params.MetricsSink.Record(metrics.Metric{
			Timestamp:  time.Now(),
			Scenario:   "dpi_explicit",
			TargetType: params.TargetType,
			Operation:  metrics.OperationForwardOpen,
			TargetName: fmt.Sprintf("churn_%d", i),
			Success:    true,
			RTTMs:      rtt,
		})

		// Brief pause then close
		time.Sleep(100 * time.Millisecond)

		start = time.Now()
		err = client.ForwardClose(ctx, conn)
		closeRTT := time.Since(start).Seconds() * 1000

		result.TotalRequests++
		if err != nil {
			result.Failures++
			params.MetricsSink.Record(metrics.Metric{
				Timestamp:  time.Now(),
				Scenario:   "dpi_explicit",
				TargetType: params.TargetType,
				Operation:  metrics.OperationForwardClose,
				TargetName: fmt.Sprintf("churn_%d", i),
				Success:    false,
				RTTMs:      closeRTT,
				Error:      err.Error(),
			})
		} else {
			result.Successes++
			result.RTTs = append(result.RTTs, closeRTT)
			params.MetricsSink.Record(metrics.Metric{
				Timestamp:  time.Now(),
				Scenario:   "dpi_explicit",
				TargetType: params.TargetType,
				Operation:  metrics.OperationForwardClose,
				TargetName: fmt.Sprintf("churn_%d", i),
				Success:    true,
				RTTMs:      closeRTT,
			})
		}

		// Brief pause between churn cycles
		time.Sleep(200 * time.Millisecond)
	}

	if result.Failures > 0 {
		result.Notes = append(result.Notes, fmt.Sprintf("Connection lifecycle: %d/%d failures - potential DPI state tracking issue", result.Failures, result.TotalRequests))
	} else {
		result.Notes = append(result.Notes, "Connection lifecycle PASSED")
	}
}

// Phase 3: Large Payloads - fragmentation and reassembly
func (s *DPIExplicitScenario) runLargePayloads(ctx context.Context, client cipclient.Client, params ScenarioParams, port int, result *PhaseResult) {
	params.Logger.Info("  Testing large payload fragmentation and reassembly...")

	if err := client.Connect(ctx, params.IP, port); err != nil {
		result.Notes = append(result.Notes, fmt.Sprintf("Cannot connect: %v", err))
		result.Failures++
		return
	}
	defer client.Disconnect(ctx)

	// Test various payload sizes
	payloadSizes := []int{100, 500, 1000, 1400, 2000}

	for _, size := range payloadSizes {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Build large MSP request
		numRequests := size / 20 // Roughly 20 bytes per request
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

		testName := fmt.Sprintf("Large MSP (~%d bytes, %d requests)", size, numRequests)
		s.testRequest(ctx, client, params, result, testName, mspReq)
	}

	// Test Get Attribute All on larger objects
	s.testRequest(ctx, client, params, result, "Get All Attributes (Identity)", protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeAll,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
	})
}

// Phase 4: Realistic Violations - invalid classes/instances/attributes
func (s *DPIExplicitScenario) runRealisticViolations(ctx context.Context, client cipclient.Client, params ScenarioParams, port int, result *PhaseResult) {
	params.Logger.Info("  Testing error handling for invalid requests...")

	if err := client.Connect(ctx, params.IP, port); err != nil {
		result.Notes = append(result.Notes, fmt.Sprintf("Cannot connect: %v", err))
		result.Failures++
		return
	}
	defer client.Disconnect(ctx)

	// Invalid class
	s.testRequestExpectError(ctx, client, params, result, "Invalid Class (0xFF)", protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0xFF, Instance: 0x01, Attribute: 0x01},
	})

	// Invalid instance
	s.testRequestExpectError(ctx, client, params, result, "Invalid Instance (0xFFFF)", protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0xFFFF, Attribute: 0x01},
	})

	// Invalid attribute
	s.testRequestExpectError(ctx, client, params, result, "Invalid Attribute (0xFF)", protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0xFF},
	})

	// Invalid service
	s.testRequestExpectError(ctx, client, params, result, "Invalid Service (0xFF)", protocol.CIPRequest{
		Service: protocol.CIPServiceCode(0xFF),
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
	})

	// Zero instance (often special)
	s.testRequest(ctx, client, params, result, "Zero Instance", protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x00, Attribute: 0x01},
	})
}

// Phase 5: Allowlist Precision - class/service filtering granularity
func (s *DPIExplicitScenario) runAllowlistPrecision(ctx context.Context, client cipclient.Client, params ScenarioParams, port int, result *PhaseResult) {
	params.Logger.Info("  Testing class/service filtering precision...")

	if err := client.Connect(ctx, params.IP, port); err != nil {
		result.Notes = append(result.Notes, fmt.Sprintf("Cannot connect: %v", err))
		result.Failures++
		return
	}
	defer client.Disconnect(ctx)

	// Common CIP classes that should be accessible
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

	for _, ac := range allowedClasses {
		s.testRequest(ctx, client, params, result, fmt.Sprintf("Class 0x%02X (%s)", ac.class, ac.name), protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeAll,
			Path:    protocol.CIPPath{Class: ac.class, Instance: 0x01},
		})
	}

	// Test write service (should typically be restricted)
	s.testRequest(ctx, client, params, result, "Set Attribute (may be blocked)", protocol.CIPRequest{
		Service: spec.CIPServiceSetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x07}, // Product Name
		Payload: []byte("Test"),
	})

	// Test reset service (should be restricted)
	s.testRequest(ctx, client, params, result, "Reset Service (should be blocked)", protocol.CIPRequest{
		Service: spec.CIPServiceReset,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
	})
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
		Timestamp:   time.Now(),
		Scenario:    "dpi_explicit",
		TargetType:  params.TargetType,
		Operation:   metrics.OperationCustom,
		TargetName:  name,
		ServiceCode: fmt.Sprintf("0x%02X", uint8(req.Service)),
		Success:     success,
		RTTMs:       rtt,
		Status:      resp.Status,
		Error:       errorMsg,
	})
}

// testRequestExpectError executes a request expecting an error response
func (s *DPIExplicitScenario) testRequestExpectError(ctx context.Context, client cipclient.Client, params ScenarioParams, result *PhaseResult, name string, req protocol.CIPRequest) {
	start := time.Now()
	resp, err := client.InvokeService(ctx, req)
	rtt := time.Since(start).Seconds() * 1000

	result.TotalRequests++

	// For error tests, success means we got a proper CIP error response (not a timeout/reset)
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
		Timestamp:   time.Now(),
		Scenario:    "dpi_explicit",
		TargetType:  params.TargetType,
		Operation:   metrics.OperationCustom,
		TargetName:  name,
		ServiceCode: fmt.Sprintf("0x%02X", uint8(req.Service)),
		Success:     gotProperError,
		RTTMs:       rtt,
		Status:      resp.Status,
		Error:       errorMsg,
	})
}

func (s *DPIExplicitScenario) logPhaseSummary(params ScenarioParams, result *PhaseResult) {
	params.Logger.Info("")
	params.Logger.Info("  Phase %d Summary:", result.Phase.Number)
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
	params.Logger.Info("DPI EXPLICIT TEST SUMMARY")
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
	params.Logger.Info("Overall: %d/%d requests succeeded (%.1f%%)", totalSuccesses, totalRequests, float64(totalSuccesses)/float64(totalRequests)*100)
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
