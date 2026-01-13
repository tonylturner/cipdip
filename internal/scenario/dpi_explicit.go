package scenario

// DPI Explicit Messaging Test Scenario
// Generic, vendor-neutral DPI regression testing focused on TCP 44818 explicit messaging.

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/metrics"
)

// DPIExplicitScenario implements the generic DPI explicit messaging test scenario.
type DPIExplicitScenario struct{}

// dpiPhase represents a test phase in the DPI scenario.
type dpiPhase struct {
	ID          string
	Name        string
	Description string
	Run         func(ctx context.Context, client client.Client, cfg *config.Config, params ScenarioParams, rng *rand.Rand) (*dpiPhaseResult, error)
}

// dpiPhaseResult captures results from a single phase.
type dpiPhaseResult struct {
	Phase         string
	TotalRequests int
	Successes     int
	Failures      int
	Timeouts      int
	Retries       int
	AvgRTTMs      float64
	P95RTTMs      float64
	Notes         []string
}

func (s *DPIExplicitScenario) Run(ctx context.Context, c client.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting dpi_explicit scenario - Generic DPI Explicit Messaging Test")
	params.Logger.Info("Focus: TCP 44818 explicit messaging, vendor-neutral")

	port := params.Port
	if port == 0 {
		port = cfg.Adapter.Port
		if port == 0 {
			port = 44818
		}
	}

	if err := c.Connect(ctx, params.IP, port); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer c.Disconnect(ctx)

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	phases := []dpiPhase{
		{
			ID:          "phase0",
			Name:        "Baseline Sanity",
			Description: "Control - verify explicit messaging works without DPI stress",
			Run:         runPhase0BaselineSanity,
		},
		{
			ID:          "phase1",
			Name:        "Read-Only Ambiguity",
			Description: "Test encoding assumptions - single vs MSP requests",
			Run:         runPhase1ReadOnlyAmbiguity,
		},
		{
			ID:          "phase2",
			Name:        "Connection Lifecycle",
			Description: "Primary breakage test - Forward Open/Close churn",
			Run:         runPhase2ConnectionLifecycle,
		},
		{
			ID:          "phase3",
			Name:        "Large Payloads",
			Description: "Fragmentation pressure and reassembly testing",
			Run:         runPhase3LargePayloads,
		},
		{
			ID:          "phase4",
			Name:        "Realistic Violations",
			Description: "Plausible protocol deviations and error handling",
			Run:         runPhase4RealisticViolations,
		},
		{
			ID:          "phase5",
			Name:        "Allowlist Precision",
			Description: "Class/service filtering granularity assessment",
			Run:         runPhase5AllowlistPrecision,
		},
	}

	var allResults []*dpiPhaseResult

	for _, phase := range phases {
		params.Logger.Info("=== %s: %s ===", phase.Name, phase.Description)

		result, err := phase.Run(ctx, c, cfg, params, rng)
		if err != nil {
			params.Logger.Error("Phase %s failed: %v", phase.ID, err)
			// Continue to next phase rather than abort
			result = &dpiPhaseResult{
				Phase: phase.ID,
				Notes: []string{fmt.Sprintf("Phase failed: %v", err)},
			}
		}

		allResults = append(allResults, result)

		// Log phase summary
		if result.TotalRequests > 0 {
			successRate := float64(result.Successes) / float64(result.TotalRequests) * 100
			params.Logger.Info("Phase %s: %d/%d (%.1f%%) success, avg RTT: %.2fms",
				phase.ID, result.Successes, result.TotalRequests, successRate, result.AvgRTTMs)
		}

		for _, note := range result.Notes {
			params.Logger.Info("  Note: %s", note)
		}

		// Brief pause between phases
		time.Sleep(500 * time.Millisecond)
	}

	// Final summary
	params.Logger.Info("=== DPI Explicit Scenario Complete ===")
	for _, r := range allResults {
		if r.TotalRequests > 0 {
			successRate := float64(r.Successes) / float64(r.TotalRequests) * 100
			params.Logger.Info("  %s: %.1f%% success (%d/%d)", r.Phase, successRate, r.Successes, r.TotalRequests)
		}
	}

	return nil
}

// Phase 0: Baseline Sanity (Control)
func runPhase0BaselineSanity(ctx context.Context, c client.Client, cfg *config.Config, params ScenarioParams, rng *rand.Rand) (*dpiPhaseResult, error) {
	result := &dpiPhaseResult{Phase: "phase0"}
	var rtts []float64

	// Simple identity reads - the most basic CIP operation
	targets := []protocol.CIPPath{
		{Class: 0x01, Instance: 0x01, Attribute: 0x01, Name: "vendor_id"},
		{Class: 0x01, Instance: 0x01, Attribute: 0x02, Name: "device_type"},
		{Class: 0x01, Instance: 0x01, Attribute: 0x03, Name: "product_code"},
		{Class: 0x01, Instance: 0x01, Attribute: 0x07, Name: "product_name"},
	}

	// Run 10 iterations for stability measurement
	for iteration := 0; iteration < 10; iteration++ {
		for _, path := range targets {
			result.TotalRequests++

			start := time.Now()
			resp, err := c.ReadAttribute(ctx, path)
			rtt := time.Since(start).Seconds() * 1000
			rtts = append(rtts, rtt)

			success := err == nil && resp.Status == 0
			if success {
				result.Successes++
			} else {
				result.Failures++
			}

			// Record metric
			var errorMsg string
			if err != nil {
				errorMsg = err.Error()
			} else if resp.Status != 0 {
				errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
			}

			metric := metrics.Metric{
				Timestamp:   time.Now(),
				Scenario:    "dpi_explicit:phase0_baseline",
				TargetType:  params.TargetType,
				Operation:   metrics.OperationRead,
				TargetName:  path.Name,
				ServiceCode: fmt.Sprintf("0x%02X", uint8(spec.CIPServiceGetAttributeSingle)),
				Success:     success,
				RTTMs:       rtt,
				Status:      resp.Status,
				Error:       errorMsg,
			}
			params.MetricsSink.Record(metric)

			// Small delay between requests
			time.Sleep(50 * time.Millisecond)
		}
	}

	// Calculate RTT stats
	if len(rtts) > 0 {
		result.AvgRTTMs = avgFloat64(rtts)
		result.P95RTTMs = percentileFloat64(rtts, 95)
	}

	// Assess baseline
	successRate := float64(result.Successes) / float64(result.TotalRequests) * 100
	if successRate < 95 {
		result.Notes = append(result.Notes, fmt.Sprintf("WARNING: Baseline success rate %.1f%% is below expected 95%%", successRate))
	}
	if result.AvgRTTMs > 50 {
		result.Notes = append(result.Notes, fmt.Sprintf("WARNING: Baseline avg RTT %.2fms is elevated", result.AvgRTTMs))
	}

	return result, nil
}

// Phase 1: Explicit Read-Only Ambiguity
func runPhase1ReadOnlyAmbiguity(ctx context.Context, c client.Client, cfg *config.Config, params ScenarioParams, rng *rand.Rand) (*dpiPhaseResult, error) {
	result := &dpiPhaseResult{Phase: "phase1"}
	var rtts []float64

	// Test same logical reads in different encodings
	singleSuccesses := 0
	singleTotal := 0
	mspSuccesses := 0
	mspTotal := 0

	paths := []protocol.CIPPath{
		{Class: 0x01, Instance: 0x01, Attribute: 0x01, Name: "vendor_id"},
		{Class: 0x01, Instance: 0x01, Attribute: 0x02, Name: "device_type"},
		{Class: 0x01, Instance: 0x01, Attribute: 0x03, Name: "product_code"},
	}

	// Part A: Single-service requests
	for i := 0; i < 5; i++ {
		for _, path := range paths {
			result.TotalRequests++
			singleTotal++

			start := time.Now()
			resp, err := c.ReadAttribute(ctx, path)
			rtt := time.Since(start).Seconds() * 1000
			rtts = append(rtts, rtt)

			success := err == nil && resp.Status == 0
			if success {
				result.Successes++
				singleSuccesses++
			} else {
				result.Failures++
			}

			var errorMsg string
			if err != nil {
				errorMsg = err.Error()
			} else if resp.Status != 0 {
				errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
			}

			metric := metrics.Metric{
				Timestamp:   time.Now(),
				Scenario:    "dpi_explicit:phase1_single",
				TargetType:  params.TargetType,
				Operation:   metrics.OperationRead,
				TargetName:  path.Name,
				ServiceCode: fmt.Sprintf("0x%02X", uint8(spec.CIPServiceGetAttributeSingle)),
				Success:     success,
				RTTMs:       rtt,
				Status:      resp.Status,
				Error:       errorMsg,
			}
			params.MetricsSink.Record(metric)

			time.Sleep(30 * time.Millisecond)
		}
	}

	// Part B: Multiple Service Packet (MSP) requests - same logical reads
	for i := 0; i < 5; i++ {
		result.TotalRequests++
		mspTotal++

		// Build MSP request with all three reads
		var requests []protocol.CIPRequest
		for _, path := range paths {
			requests = append(requests, protocol.CIPRequest{
				Service: spec.CIPServiceGetAttributeSingle,
				Path:    path,
			})
		}

		// Build the MSP request
		mspReq, err := client.BuildMultipleServiceRequest(requests)
		if err != nil {
			result.Failures++
			continue
		}

		start := time.Now()
		mspResp, err := c.InvokeService(ctx, mspReq)
		rtt := time.Since(start).Seconds() * 1000
		rtts = append(rtts, rtt)

		// MSP success if we got a response
		success := err == nil && mspResp.Status == 0
		if success {
			// Parse sub-responses to check individual status
			subResps, parseErr := client.ParseMultipleServiceResponsePayload(mspResp.Payload, protocol.CIPPath{})
			if parseErr == nil {
				for _, subResp := range subResps {
					if subResp.Status != 0 {
						success = false
						break
					}
				}
			}
		}

		if success {
			result.Successes++
			mspSuccesses++
		} else {
			result.Failures++
		}

		var errorMsg string
		if err != nil {
			errorMsg = err.Error()
		} else if mspResp.Status != 0 {
			errorMsg = fmt.Sprintf("CIP status: 0x%02X", mspResp.Status)
		}

		metric := metrics.Metric{
			Timestamp:   time.Now(),
			Scenario:    "dpi_explicit:phase1_msp",
			TargetType:  params.TargetType,
			Operation:   metrics.OperationCustom,
			TargetName:  "msp_batch_read",
			ServiceCode: fmt.Sprintf("0x%02X", uint8(spec.CIPServiceMultipleService)),
			Success:     success,
			RTTMs:       rtt,
			Error:       errorMsg,
		}
		params.MetricsSink.Record(metric)

		time.Sleep(50 * time.Millisecond)
	}

	// Calculate RTT stats
	if len(rtts) > 0 {
		result.AvgRTTMs = avgFloat64(rtts)
		result.P95RTTMs = percentileFloat64(rtts, 95)
	}

	// Analyze ambiguity
	singleRate := float64(singleSuccesses) / float64(singleTotal) * 100
	mspRate := float64(mspSuccesses) / float64(mspTotal) * 100

	if singleRate > 90 && mspRate > 90 {
		result.Notes = append(result.Notes, "Both single and MSP reads succeed - policy may have encoding ambiguity")
	} else if singleRate > 90 && mspRate < 50 {
		result.Notes = append(result.Notes, "Single reads pass but MSP fails - operational fragility detected")
	} else if singleRate < 50 && mspRate > 90 {
		result.Notes = append(result.Notes, "MSP passes but single reads fail - unusual filtering behavior")
	}

	result.Notes = append(result.Notes, fmt.Sprintf("Single: %.1f%%, MSP: %.1f%%", singleRate, mspRate))

	return result, nil
}

// Phase 2: Connection Lifecycle Stability (PRIMARY BREAKAGE TEST)
func runPhase2ConnectionLifecycle(ctx context.Context, c client.Client, cfg *config.Config, params ScenarioParams, rng *rand.Rand) (*dpiPhaseResult, error) {
	result := &dpiPhaseResult{Phase: "phase2"}
	var rtts []float64

	// Connection churn parameters
	churnCycles := 10
	minChurnDelayMs := 1000
	maxChurnDelayMs := 3000

	foSuccesses := 0
	fcSuccesses := 0
	foTotal := 0
	fcTotal := 0

	for cycle := 0; cycle < churnCycles; cycle++ {
		// Forward Open
		result.TotalRequests++
		foTotal++

		connParams := client.ConnectionParams{
			Name:                  fmt.Sprintf("dpi_test_conn_%d", cycle),
			Transport:             "tcp", // Explicit messaging only
			OToTRPIMs:             100,
			TToORPIMs:             100,
			OToTSizeBytes:         32,
			TToOSizeBytes:         32,
			Priority:              "low",
			TransportClassTrigger: 0xA3, // Class 3, client trigger
		}

		start := time.Now()
		conn, err := c.ForwardOpen(ctx, connParams)
		rtt := time.Since(start).Seconds() * 1000
		rtts = append(rtts, rtt)

		foSuccess := err == nil
		if foSuccess {
			result.Successes++
			foSuccesses++
		} else {
			result.Failures++
			result.Notes = append(result.Notes, fmt.Sprintf("Cycle %d: ForwardOpen failed: %v", cycle, err))
		}

		var errorMsg string
		if err != nil {
			errorMsg = err.Error()
		}

		metric := metrics.Metric{
			Timestamp:   time.Now(),
			Scenario:    "dpi_explicit:phase2_lifecycle",
			TargetType:  params.TargetType,
			Operation:   metrics.OperationForwardOpen,
			TargetName:  connParams.Name,
			Success:     foSuccess,
			RTTMs:       rtt,
			Error:       errorMsg,
		}
		params.MetricsSink.Record(metric)

		// If ForwardOpen succeeded, do ForwardClose
		if foSuccess && conn != nil {
			// Brief pause before close
			time.Sleep(time.Duration(200+rng.Intn(300)) * time.Millisecond)

			result.TotalRequests++
			fcTotal++

			start = time.Now()
			err = c.ForwardClose(ctx, conn)
			rtt = time.Since(start).Seconds() * 1000
			rtts = append(rtts, rtt)

			fcSuccess := err == nil
			if fcSuccess {
				result.Successes++
				fcSuccesses++
			} else {
				result.Failures++
				result.Notes = append(result.Notes, fmt.Sprintf("Cycle %d: ForwardClose failed: %v", cycle, err))
			}

			errorMsg = ""
			if err != nil {
				errorMsg = err.Error()
			}

			metric = metrics.Metric{
				Timestamp:   time.Now(),
				Scenario:    "dpi_explicit:phase2_lifecycle",
				TargetType:  params.TargetType,
				Operation:   metrics.OperationForwardClose,
				TargetName:  connParams.Name,
				Success:     fcSuccess,
				RTTMs:       rtt,
				Error:       errorMsg,
			}
			params.MetricsSink.Record(metric)
		}

		// Churn delay
		delay := time.Duration(minChurnDelayMs+rng.Intn(maxChurnDelayMs-minChurnDelayMs)) * time.Millisecond
		time.Sleep(delay)
	}

	// Calculate RTT stats
	if len(rtts) > 0 {
		result.AvgRTTMs = avgFloat64(rtts)
		result.P95RTTMs = percentileFloat64(rtts, 95)
	}

	// Assess lifecycle stability
	foRate := float64(foSuccesses) / float64(foTotal) * 100
	fcRate := float64(fcSuccesses) / float64(fcTotal) * 100

	if foRate < 90 {
		result.Notes = append(result.Notes, fmt.Sprintf("BREAKAGE: ForwardOpen success rate %.1f%% indicates DPI interference", foRate))
	}
	if fcRate < 90 {
		result.Notes = append(result.Notes, fmt.Sprintf("BREAKAGE: ForwardClose success rate %.1f%% indicates state tracking issues", fcRate))
	}
	if result.P95RTTMs > 200 {
		result.Notes = append(result.Notes, fmt.Sprintf("WARNING: p95 RTT %.2fms indicates latency impact", result.P95RTTMs))
	}

	result.Notes = append(result.Notes, fmt.Sprintf("ForwardOpen: %.1f%%, ForwardClose: %.1f%%", foRate, fcRate))

	return result, nil
}

// Phase 3: Large Explicit Payloads / Fragmentation Pressure
func runPhase3LargePayloads(ctx context.Context, c client.Client, cfg *config.Config, params ScenarioParams, rng *rand.Rand) (*dpiPhaseResult, error) {
	result := &dpiPhaseResult{Phase: "phase3"}
	var rtts []float64

	// Test with increasingly large read requests
	// Read assembly data which can return larger payloads
	assemblies := []struct {
		class    uint16
		instance uint16
		name     string
	}{
		{0x04, 0x64, "assembly_100"},  // Assembly class, instance 100
		{0x04, 0x65, "assembly_101"},  // Assembly class, instance 101
		{0x04, 0xC8, "assembly_200"},  // Assembly class, instance 200
	}

	smallSuccesses := 0
	largeSuccesses := 0
	smallTotal := 0
	largeTotal := 0

	// Part A: Small reads (Get Attribute Single)
	for i := 0; i < 5; i++ {
		for _, asm := range assemblies {
			result.TotalRequests++
			smallTotal++

			path := protocol.CIPPath{
				Class:     asm.class,
				Instance:  asm.instance,
				Attribute: 0x03, // Data attribute
				Name:      asm.name,
			}

			start := time.Now()
			resp, err := c.ReadAttribute(ctx, path)
			rtt := time.Since(start).Seconds() * 1000
			rtts = append(rtts, rtt)

			// Accept success or "attribute not supported" (0x14) as valid
			success := err == nil && (resp.Status == 0 || resp.Status == 0x14)
			if success {
				result.Successes++
				smallSuccesses++
			} else {
				result.Failures++
			}

			var errorMsg string
			if err != nil {
				errorMsg = err.Error()
			} else if resp.Status != 0 && resp.Status != 0x14 {
				errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
			}

			metric := metrics.Metric{
				Timestamp:   time.Now(),
				Scenario:    "dpi_explicit:phase3_small",
				TargetType:  params.TargetType,
				Operation:   metrics.OperationRead,
				TargetName:  asm.name,
				ServiceCode: fmt.Sprintf("0x%02X", uint8(spec.CIPServiceGetAttributeSingle)),
				Success:     success,
				RTTMs:       rtt,
				Status:      resp.Status,
				Error:       errorMsg,
			}
			params.MetricsSink.Record(metric)

			time.Sleep(30 * time.Millisecond)
		}
	}

	// Part B: Larger batched reads (Get Attribute All or MSP with many services)
	for i := 0; i < 5; i++ {
		result.TotalRequests++
		largeTotal++

		// Build a larger MSP request
		var requests []protocol.CIPRequest
		for _, asm := range assemblies {
			requests = append(requests, protocol.CIPRequest{
				Service: spec.CIPServiceGetAttributeAll,
				Path: protocol.CIPPath{
					Class:    asm.class,
					Instance: asm.instance,
					Name:     asm.name,
				},
			})
		}
		// Add identity reads to increase payload
		requests = append(requests, protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeAll,
			Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Name: "identity"},
		})

		// Build the MSP request
		mspReq, err := client.BuildMultipleServiceRequest(requests)
		if err != nil {
			result.Failures++
			continue
		}

		start := time.Now()
		mspResp, err := c.InvokeService(ctx, mspReq)
		rtt := time.Since(start).Seconds() * 1000
		rtts = append(rtts, rtt)

		// Success if MSP itself worked (sub-request failures are expected for missing objects)
		success := err == nil && (mspResp.Status == 0 || len(mspResp.Payload) > 0)

		if success {
			result.Successes++
			largeSuccesses++
		} else {
			result.Failures++
		}

		var errorMsg string
		if err != nil {
			errorMsg = err.Error()
		} else if mspResp.Status != 0 {
			errorMsg = fmt.Sprintf("CIP status: 0x%02X", mspResp.Status)
		}

		metric := metrics.Metric{
			Timestamp:   time.Now(),
			Scenario:    "dpi_explicit:phase3_large",
			TargetType:  params.TargetType,
			Operation:   metrics.OperationCustom,
			TargetName:  "large_msp_batch",
			ServiceCode: fmt.Sprintf("0x%02X", uint8(spec.CIPServiceMultipleService)),
			Success:     success,
			RTTMs:       rtt,
			Error:       errorMsg,
		}
		params.MetricsSink.Record(metric)

		time.Sleep(100 * time.Millisecond)
	}

	// Calculate RTT stats
	if len(rtts) > 0 {
		result.AvgRTTMs = avgFloat64(rtts)
		result.P95RTTMs = percentileFloat64(rtts, 95)
	}

	// Analyze fragmentation behavior
	smallRate := float64(smallSuccesses) / float64(smallTotal) * 100
	largeRate := float64(largeSuccesses) / float64(largeTotal) * 100

	if smallRate > 80 && largeRate < 50 {
		result.Notes = append(result.Notes, "Small payloads pass but large payloads fail - possible reassembly issue")
	}

	result.Notes = append(result.Notes, fmt.Sprintf("Small: %.1f%%, Large batched: %.1f%%", smallRate, largeRate))

	return result, nil
}

// Phase 4: Realistic Violations
func runPhase4RealisticViolations(ctx context.Context, c client.Client, cfg *config.Config, params ScenarioParams, rng *rand.Rand) (*dpiPhaseResult, error) {
	result := &dpiPhaseResult{Phase: "phase4"}
	var rtts []float64

	// Test plausible protocol deviations
	violations := []struct {
		name        string
		service     protocol.CIPServiceCode
		path        protocol.CIPPath
		description string
		expectError bool
	}{
		{
			name:        "invalid_class",
			service:     spec.CIPServiceGetAttributeSingle,
			path:        protocol.CIPPath{Class: 0xFFFF, Instance: 0x01, Attribute: 0x01},
			description: "Read from non-existent class",
			expectError: true,
		},
		{
			name:        "invalid_instance",
			service:     spec.CIPServiceGetAttributeSingle,
			path:        protocol.CIPPath{Class: 0x01, Instance: 0xFFFF, Attribute: 0x01},
			description: "Read from non-existent instance",
			expectError: true,
		},
		{
			name:        "invalid_attribute",
			service:     spec.CIPServiceGetAttributeSingle,
			path:        protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0xFF},
			description: "Read non-existent attribute",
			expectError: true,
		},
		{
			name:        "reserved_service",
			service:     protocol.CIPServiceCode(0x7F), // Reserved service code
			path:        protocol.CIPPath{Class: 0x01, Instance: 0x01},
			description: "Use reserved service code",
			expectError: true,
		},
		{
			name:        "zero_class",
			service:     spec.CIPServiceGetAttributeSingle,
			path:        protocol.CIPPath{Class: 0x00, Instance: 0x01, Attribute: 0x01},
			description: "Read from class 0 (message router)",
			expectError: false, // This might actually work on some devices
		},
	}

	clearErrors := 0
	silentDrops := 0
	resets := 0

	for _, v := range violations {
		result.TotalRequests++

		req := protocol.CIPRequest{
			Service: v.service,
			Path:    v.path,
		}

		start := time.Now()
		resp, err := c.InvokeService(ctx, req)
		rtt := time.Since(start).Seconds() * 1000
		rtts = append(rtts, rtt)

		// Classify the outcome
		var outcome string
		var success bool

		if err != nil {
			if isTimeoutError(err) {
				outcome = "timeout"
				silentDrops++
			} else if isResetError(err) {
				outcome = "reset"
				resets++
			} else {
				outcome = "error"
			}
			result.Failures++
		} else if resp.Status != 0 {
			outcome = "cip_error"
			clearErrors++
			success = true // Error response is a valid response
			result.Successes++
		} else {
			outcome = "success"
			success = true
			result.Successes++
		}

		var errorMsg string
		if err != nil {
			errorMsg = err.Error()
		} else if resp.Status != 0 {
			errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
		}

		metric := metrics.Metric{
			Timestamp:       time.Now(),
			Scenario:        "dpi_explicit:phase4_violations",
			TargetType:      params.TargetType,
			Operation:       metrics.OperationCustom,
			TargetName:      v.name,
			ServiceCode:     fmt.Sprintf("0x%02X", uint8(v.service)),
			Success:         success,
			RTTMs:           rtt,
			Status:          resp.Status,
			Error:           errorMsg,
			Outcome:         outcome,
			ExpectedOutcome: "error",
		}
		params.MetricsSink.Record(metric)

		time.Sleep(100 * time.Millisecond)
	}

	// Calculate RTT stats
	if len(rtts) > 0 {
		result.AvgRTTMs = avgFloat64(rtts)
		result.P95RTTMs = percentileFloat64(rtts, 95)
	}

	// Analyze error handling consistency
	result.Notes = append(result.Notes, fmt.Sprintf("Clear errors: %d, Silent drops: %d, Resets: %d",
		clearErrors, silentDrops, resets))

	if silentDrops > 0 {
		result.Notes = append(result.Notes, "WARNING: Silent drops detected - may indicate DPI filtering without clear feedback")
	}
	if resets > len(violations)/2 {
		result.Notes = append(result.Notes, "WARNING: High reset rate - aggressive DPI termination behavior")
	}

	return result, nil
}

// Phase 5: Allowlist Granularity Precision
func runPhase5AllowlistPrecision(ctx context.Context, c client.Client, cfg *config.Config, params ScenarioParams, rng *rand.Rand) (*dpiPhaseResult, error) {
	result := &dpiPhaseResult{Phase: "phase5"}
	var rtts []float64

	// Test precise filtering granularity
	// Mix allowed and closely-related disallowed combinations
	testCases := []struct {
		name          string
		service       protocol.CIPServiceCode
		path          protocol.CIPPath
		expectAllowed bool
		description   string
	}{
		// Typically allowed - basic identity reads
		{
			name:          "identity_read",
			service:       spec.CIPServiceGetAttributeSingle,
			path:          protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x01},
			expectAllowed: true,
			description:   "Standard identity read (usually allowed)",
		},
		// Typically restricted - reset service
		{
			name:          "identity_reset",
			service:       spec.CIPServiceReset,
			path:          protocol.CIPPath{Class: 0x01, Instance: 0x01},
			expectAllowed: false,
			description:   "Reset service on identity (usually restricted)",
		},
		// TCP/IP object - often allowed for read
		{
			name:          "tcpip_read",
			service:       spec.CIPServiceGetAttributeSingle,
			path:          protocol.CIPPath{Class: 0xF5, Instance: 0x01, Attribute: 0x05},
			expectAllowed: true,
			description:   "TCP/IP object read (network config)",
		},
		// TCP/IP object - write should be restricted
		{
			name:          "tcpip_write",
			service:       spec.CIPServiceSetAttributeSingle,
			path:          protocol.CIPPath{Class: 0xF5, Instance: 0x01, Attribute: 0x05},
			expectAllowed: false,
			description:   "TCP/IP object write (network config change)",
		},
		// Connection Manager - ForwardOpen related
		{
			name:          "connmgr_read",
			service:       spec.CIPServiceGetAttributeSingle,
			path:          protocol.CIPPath{Class: 0x06, Instance: 0x01, Attribute: 0x01},
			expectAllowed: true,
			description:   "Connection Manager read",
		},
		// File object - potentially sensitive
		{
			name:          "file_read",
			service:       spec.CIPServiceGetAttributeSingle,
			path:          protocol.CIPPath{Class: 0x37, Instance: 0x01, Attribute: 0x01},
			expectAllowed: false,
			description:   "File object access (firmware/config)",
		},
	}

	allowedPass := 0
	allowedFail := 0
	restrictedPass := 0
	restrictedFail := 0

	for _, tc := range testCases {
		result.TotalRequests++

		req := protocol.CIPRequest{
			Service: tc.service,
			Path:    tc.path,
		}

		start := time.Now()
		resp, err := c.InvokeService(ctx, req)
		rtt := time.Since(start).Seconds() * 1000
		rtts = append(rtts, rtt)

		// Determine if request "passed" (got a response, even if error)
		passed := err == nil
		success := err == nil && resp.Status == 0

		if tc.expectAllowed {
			if passed {
				allowedPass++
				result.Successes++
			} else {
				allowedFail++
				result.Failures++
			}
		} else {
			if passed {
				restrictedPass++
				result.Successes++ // Got a response, even if restricted traffic
			} else {
				restrictedFail++
				result.Failures++
			}
		}

		var errorMsg string
		if err != nil {
			errorMsg = err.Error()
		} else if resp.Status != 0 {
			errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
		}

		metric := metrics.Metric{
			Timestamp:       time.Now(),
			Scenario:        "dpi_explicit:phase5_allowlist",
			TargetType:      params.TargetType,
			Operation:       metrics.OperationCustom,
			TargetName:      tc.name,
			ServiceCode:     fmt.Sprintf("0x%02X", uint8(tc.service)),
			Success:         success,
			RTTMs:           rtt,
			Status:          resp.Status,
			Error:           errorMsg,
			ExpectedOutcome: map[bool]string{true: "allowed", false: "blocked"}[tc.expectAllowed],
			Outcome:         map[bool]string{true: "passed", false: "blocked"}[passed],
		}
		params.MetricsSink.Record(metric)

		time.Sleep(100 * time.Millisecond)
	}

	// Calculate RTT stats
	if len(rtts) > 0 {
		result.AvgRTTMs = avgFloat64(rtts)
		result.P95RTTMs = percentileFloat64(rtts, 95)
	}

	// Analyze allowlist precision
	result.Notes = append(result.Notes, fmt.Sprintf("Expected-allowed: %d pass / %d fail", allowedPass, allowedFail))
	result.Notes = append(result.Notes, fmt.Sprintf("Expected-restricted: %d pass / %d fail", restrictedPass, restrictedFail))

	if allowedFail > 0 {
		result.Notes = append(result.Notes, "FALSE POSITIVE: Allowed traffic was blocked")
	}
	if restrictedPass > 0 {
		result.Notes = append(result.Notes, "FALSE NEGATIVE: Restricted traffic was allowed through")
	}

	return result, nil
}

// Helper functions

func avgFloat64(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func percentileFloat64(values []float64, pct int) float64 {
	if len(values) == 0 {
		return 0
	}
	// Simple percentile - sort and pick
	sorted := make([]float64, len(values))
	copy(sorted, values)
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	idx := (pct * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded")
}

func isResetError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "reset") || strings.Contains(errStr, "RST") || strings.Contains(errStr, "connection refused")
}
