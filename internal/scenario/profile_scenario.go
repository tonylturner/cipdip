package scenario

import (
	"context"
	"fmt"
	"math"
	"time"

	cipclient "github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/metrics"
	"github.com/tturner/cipdip/internal/profile"
	"github.com/tturner/cipdip/internal/profile/engine"
	"github.com/tturner/cipdip/internal/progress"
)

// ProfileScenario runs client behavior based on a process profile.
type ProfileScenario struct {
	Profile *profile.Profile
	Role    string
}

// Run executes the profile scenario.
func (s *ProfileScenario) Run(ctx context.Context, client cipclient.Client, cfg *config.Config, params ScenarioParams) error {
	params.Logger.Info("Starting profile scenario: %s (role: %s)", s.Profile.Metadata.Name, s.Role)

	// Create client engine
	clientEngine, err := engine.NewClientEngine(s.Profile, s.Role)
	if err != nil {
		return fmt.Errorf("create client engine: %w", err)
	}

	params.Logger.Verbose("  Poll interval: %v", clientEngine.PollInterval())
	params.Logger.Verbose("  Batch size: %d", clientEngine.BatchSize())
	params.Logger.Verbose("  Read tags: %d", len(clientEngine.GetAllReadTags()))
	params.Logger.Verbose("  Writable tags: %d", len(clientEngine.GetWritableTags()))

	// Connect to the device
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
	defer func() {
		params.Logger.Info("Disconnecting...")
		client.Disconnect(ctx)
	}()

	// Create deadline for duration
	deadline := time.Now().Add(params.Duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// Calculate total operations for progress bar
	pollInterval := clientEngine.PollInterval()
	totalOps := int64(params.Duration / pollInterval)
	if totalOps == 0 {
		totalOps = 1
	}
	progressBar := progress.NewProgressBar(totalOps, fmt.Sprintf("Profile: %s (%s)", s.Profile.Metadata.Name, s.Role))
	defer progressBar.Finish()

	loopCount := 0
	startTime := time.Now()
	lastTick := time.Now()

	// Reconnect settings
	const maxReconnectRetries = 3
	const reconnectDelay = 2 * time.Second
	reconnectCount := 0

	fmt.Printf("[CLIENT] Starting profile scenario: %s (role: %s)\n", s.Profile.Metadata.Name, s.Role)
	fmt.Printf("[CLIENT] Poll interval: %v, Batch size: %d\n", pollInterval, clientEngine.BatchSize())
	fmt.Printf("[CLIENT] Will run for %v or until interrupted\n\n", params.Duration)

	// Main loop
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			params.Logger.Info("Profile scenario completed (duration expired or cancelled)")
			fmt.Printf("[CLIENT] Scenario completed after %d polls\n", loopCount)
			return nil

		case now := <-ticker.C:
			// Check deadline
			if now.After(deadline) {
				params.Logger.Info("Profile scenario completed: %d polls in %v", loopCount, time.Since(startTime))
				return nil
			}

			// Ensure connection
			if !client.IsConnected() {
				reconnectCount++
				fmt.Printf("[CLIENT] Connection lost, attempting reconnect (%d)...\n", reconnectCount)
				if err := ensureConnected(ctx, client, params.IP, port, maxReconnectRetries, reconnectDelay); err != nil {
					return fmt.Errorf("connection lost and reconnect failed: %w", err)
				}
				fmt.Printf("[CLIENT] Reconnected successfully\n")
			}

			// Advance client engine
			dt := now.Sub(lastTick)
			lastTick = now
			clientEngine.Tick(dt)

			// Get read batch
			readBatch := clientEngine.GetNextReadBatch()

			// Execute reads (with MSP batching if batch size > 1)
			if len(readBatch) > 1 && clientEngine.BatchSize() > 1 {
				// Use Multiple Service Packet
				if err := s.executeBatchedReads(ctx, client, readBatch, params, clientEngine); err != nil {
					params.Logger.Verbose("Batched read error: %v", err)
				}
			} else {
				// Serial reads
				for _, req := range readBatch {
					s.executeSingleRead(ctx, client, req, params, clientEngine)
				}
			}

			// Execute pending writes
			writes := clientEngine.GetPendingWrites()
			for _, w := range writes {
				s.executeWrite(ctx, client, w, params, clientEngine)
			}

			loopCount++
			progressBar.Increment()
		}
	}
}

// executeBatchedReads performs a batched read using Multiple Service Packet.
func (s *ProfileScenario) executeBatchedReads(ctx context.Context, client cipclient.Client, batch []engine.ReadRequest, params ScenarioParams, clientEngine *engine.ClientEngine) error {
	// Build individual read requests
	requests := make([]protocol.CIPRequest, len(batch))
	for i, req := range batch {
		requests[i] = protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeSingle,
			Path:    s.resolveTagPath(req.TagName, clientEngine),
		}
	}

	// Build MSP request
	mspReq, err := cipclient.BuildMultipleServiceRequest(requests)
	if err != nil {
		return fmt.Errorf("build MSP request: %w", err)
	}

	// Execute
	start := time.Now()
	resp, err := client.InvokeService(ctx, mspReq)
	batchRTT := time.Since(start).Seconds() * 1000

	if err != nil {
		// Log batch failure
		params.Logger.LogOperation(
			"MSP_READ",
			fmt.Sprintf("batch(%d)", len(batch)),
			fmt.Sprintf("0x%02X", uint8(spec.CIPServiceMultipleService)),
			false,
			batchRTT,
			0,
			err,
		)
		return err
	}

	// Parse individual responses
	if resp.Status == 0 && len(resp.Payload) > 0 {
		responses, err := cipclient.ParseMultipleServiceResponsePayload(resp.Payload, resp.Path)
		if err != nil {
			params.Logger.Verbose("Failed to parse MSP response: %v", err)
		} else {
			// Record metrics for each response
			perTagRTT := batchRTT / float64(len(responses))
			for i, subResp := range responses {
				if i < len(batch) {
					success := subResp.Status == 0
					var errorMsg string
					if !success {
						errorMsg = fmt.Sprintf("CIP status: 0x%02X", subResp.Status)
					}

					metric := metrics.Metric{
						Timestamp:   time.Now(),
						Scenario:    "profile",
						TargetType:  params.TargetType,
						Operation:   metrics.OperationRead,
						TargetName:  batch[i].TagName,
						ServiceCode: fmt.Sprintf("0x%02X", uint8(spec.CIPServiceGetAttributeSingle)),
						Success:     success,
						RTTMs:       perTagRTT,
						Status:      subResp.Status,
						Error:       errorMsg,
					}
					params.MetricsSink.Record(metric)
				}
			}
		}
	}

	// Log batch success
	fmt.Printf("[CLIENT] MSP Read batch(%d): RTT=%.2fms status=0x%02X\n",
		len(batch), batchRTT, resp.Status)

	return nil
}

// executeSingleRead performs a single tag read.
func (s *ProfileScenario) executeSingleRead(ctx context.Context, client cipclient.Client, req engine.ReadRequest, params ScenarioParams, clientEngine *engine.ClientEngine) {
	path := s.resolveTagPath(req.TagName, clientEngine)

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

	// Record metric
	metric := metrics.Metric{
		Timestamp:   time.Now(),
		Scenario:    "profile",
		TargetType:  params.TargetType,
		Operation:   metrics.OperationRead,
		TargetName:  req.TagName,
		ServiceCode: fmt.Sprintf("0x%02X", uint8(spec.CIPServiceGetAttributeSingle)),
		Success:     success,
		RTTMs:       rtt,
		Status:      resp.Status,
		Error:       errorMsg,
	}
	params.MetricsSink.Record(metric)

	if success {
		fmt.Printf("[CLIENT] Read %s: status=0x%02X RTT=%.2fms\n", req.TagName, resp.Status, rtt)
	} else {
		fmt.Printf("[CLIENT] Read %s FAILED: %s\n", req.TagName, errorMsg)
	}
}

// executeWrite performs a tag write.
func (s *ProfileScenario) executeWrite(ctx context.Context, client cipclient.Client, req engine.WriteRequest, params ScenarioParams, clientEngine *engine.ClientEngine) {
	path := s.resolveTagPath(req.TagName, clientEngine)

	// Encode value
	value := encodeValue(req.Value, req.TagType)

	start := time.Now()
	resp, err := client.WriteAttribute(ctx, path, value)
	rtt := time.Since(start).Seconds() * 1000

	success := err == nil && resp.Status == 0
	var errorMsg string
	if err != nil {
		errorMsg = err.Error()
	} else if resp.Status != 0 {
		errorMsg = fmt.Sprintf("CIP status: 0x%02X", resp.Status)
	}

	// Record metric
	metric := metrics.Metric{
		Timestamp:   time.Now(),
		Scenario:    "profile",
		TargetType:  params.TargetType,
		Operation:   metrics.OperationWrite,
		TargetName:  req.TagName,
		ServiceCode: fmt.Sprintf("0x%02X", uint8(spec.CIPServiceSetAttributeSingle)),
		Success:     success,
		RTTMs:       rtt,
		Status:      resp.Status,
		Error:       errorMsg,
	}
	params.MetricsSink.Record(metric)

	if success {
		fmt.Printf("[CLIENT] Write %s=%v: status=0x%02X RTT=%.2fms\n", req.TagName, req.Value, resp.Status, rtt)
	} else {
		fmt.Printf("[CLIENT] Write %s FAILED: %s\n", req.TagName, errorMsg)
	}
}

// resolveTagPath converts a tag name to a CIP path.
// For logix-like profiles, this uses symbolic addressing.
// For adapter profiles with field mappings, this uses class/instance/attribute.
func (s *ProfileScenario) resolveTagPath(tagName string, clientEngine *engine.ClientEngine) protocol.CIPPath {
	// Check if this is an adapter profile with field mappings
	if clientEngine.IsAdapterProfile() {
		if resolved := clientEngine.ResolveTag(tagName); resolved != nil {
			return protocol.CIPPath{
				Class:     resolved.Class,
				Instance:  resolved.Instance,
				Attribute: resolved.Attribute,
				Name:      tagName, // Keep name for logging
			}
		}
	}

	// Fall back to symbolic path for logix_like profiles or unmapped tags
	return protocol.CIPPath{
		Name: tagName,
	}
}

// encodeValue encodes a value to bytes based on type.
func encodeValue(value interface{}, tagType string) []byte {
	// Use the engine's encoding
	data, _ := encodeTagValue(value, tagType)
	return data
}

// encodeTagValue encodes a value to bytes (duplicated from engine for now).
func encodeTagValue(value interface{}, tagType string) ([]byte, error) {
	switch tagType {
	case "BOOL":
		b := make([]byte, 1)
		if toBool(value) {
			b[0] = 1
		}
		return b, nil

	case "SINT":
		return []byte{byte(toInt(value))}, nil

	case "INT":
		b := make([]byte, 2)
		putUint16LE(b, uint16(toInt(value)))
		return b, nil

	case "DINT":
		b := make([]byte, 4)
		putUint32LE(b, uint32(toInt(value)))
		return b, nil

	case "REAL":
		b := make([]byte, 4)
		putFloat32LE(b, float32(toFloat(value)))
		return b, nil

	default:
		b := make([]byte, 4)
		putUint32LE(b, uint32(toInt(value)))
		return b, nil
	}
}

func toBool(v interface{}) bool {
	switch val := v.(type) {
	case bool:
		return val
	case int:
		return val != 0
	case int64:
		return val != 0
	case float64:
		return val != 0
	}
	return false
}

func toInt(v interface{}) int64 {
	switch val := v.(type) {
	case int:
		return int64(val)
	case int32:
		return int64(val)
	case int64:
		return val
	case float32:
		return int64(val)
	case float64:
		return int64(val)
	case bool:
		if val {
			return 1
		}
		return 0
	}
	return 0
}

func toFloat(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case float32:
		return float64(val)
	case int:
		return float64(val)
	case int64:
		return float64(val)
	}
	return 0
}

func putUint16LE(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}

func putUint32LE(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func putFloat32LE(b []byte, v float32) {
	bits := math.Float32bits(v)
	b[0] = byte(bits)
	b[1] = byte(bits >> 8)
	b[2] = byte(bits >> 16)
	b[3] = byte(bits >> 24)
}
