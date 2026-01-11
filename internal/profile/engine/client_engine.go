package engine

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/tturner/cipdip/internal/profile"
)

// ReadRequest represents a tag read request.
type ReadRequest struct {
	TagName string
	TagType string
}

// WriteRequest represents a tag write request.
type WriteRequest struct {
	TagName string
	TagType string
	Value   interface{}
}

// ClientEngine manages role behavior for the client.
type ClientEngine struct {
	profile  *profile.Profile
	role     *profile.Role
	roleName string
	rng      *rand.Rand

	// Observed server state (updated from tag reads if available)
	serverState string

	// Polling state
	pollInterval    time.Duration
	batchSize       int
	readTags        []ReadRequest
	currentBatchIdx int

	// Write scheduling
	writeEvents       []scheduledWriteEvent
	pendingWrites     []WriteRequest
	writeEventTimers  map[int]time.Duration // Event index -> accumulated time
	writeEventFired   map[int]bool          // Track "once" style triggers
	stateWritesFired  map[string]map[int]bool // State -> event index -> fired

	// Stats
	totalReads      int64
	totalWrites     int64
	totalBatches    int64
	readsByTag      map[string]int64
	writesByTag     map[string]int64

	mu sync.Mutex
}

type scheduledWriteEvent struct {
	TriggerType  string      // "state", "timer", "random"
	TriggerValue string      // State name, duration, or probability
	TagName      string
	TagType      string
	Value        interface{}
	Condition    string      // Optional additional condition
	parsed       Condition   // Parsed condition
}

// NewClientEngine creates a new client engine for a specific role.
func NewClientEngine(p *profile.Profile, roleName string) (*ClientEngine, error) {
	role := p.GetRole(roleName)
	if role == nil {
		return nil, fmt.Errorf("role %q not found in profile", roleName)
	}

	seed := p.Metadata.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}

	pollInterval, err := role.PollInterval.Parse()
	if err != nil {
		return nil, fmt.Errorf("invalid poll_interval: %w", err)
	}
	if pollInterval <= 0 {
		pollInterval = 500 * time.Millisecond
	}

	batchSize := role.BatchSize
	if batchSize <= 0 {
		batchSize = 1 // No batching
	}

	// Build read request list
	readTags := make([]ReadRequest, 0, len(role.ReadTags))
	for _, tagName := range role.ReadTags {
		tag := p.GetTagByName(tagName)
		tagType := "DINT" // Default
		if tag != nil {
			tagType = tag.Type
		}
		readTags = append(readTags, ReadRequest{
			TagName: tagName,
			TagType: tagType,
		})
	}

	// Build write event list
	writeEvents := make([]scheduledWriteEvent, 0, len(role.WriteEvents))
	for _, we := range role.WriteEvents {
		tagType := "DINT"
		if tag := p.GetTagByName(we.Tag); tag != nil {
			tagType = tag.Type
		}

		evt := scheduledWriteEvent{
			TagName: we.Tag,
			TagType: tagType,
			Value:   we.Value,
		}

		// Parse trigger
		triggerStr := we.Trigger
		if len(triggerStr) > 6 && triggerStr[:6] == "state:" {
			evt.TriggerType = "state"
			evt.TriggerValue = triggerStr[6:]
		} else if len(triggerStr) > 6 && triggerStr[:6] == "timer:" {
			evt.TriggerType = "timer"
			evt.TriggerValue = triggerStr[6:]
		} else if len(triggerStr) > 7 && triggerStr[:7] == "random:" {
			evt.TriggerType = "random"
			evt.TriggerValue = triggerStr[7:]
		}

		// Parse condition if present
		if we.Condition != "" {
			evt.Condition = we.Condition
			evt.parsed = ParseCondition(we.Condition)
		}

		writeEvents = append(writeEvents, evt)
	}

	return &ClientEngine{
		profile:          p,
		role:             role,
		roleName:         roleName,
		rng:              rand.New(rand.NewSource(seed)),
		pollInterval:     pollInterval,
		batchSize:        batchSize,
		readTags:         readTags,
		writeEvents:      writeEvents,
		pendingWrites:    make([]WriteRequest, 0),
		writeEventTimers: make(map[int]time.Duration),
		writeEventFired:  make(map[int]bool),
		stateWritesFired: make(map[string]map[int]bool),
		readsByTag:       make(map[string]int64),
		writesByTag:      make(map[string]int64),
	}, nil
}

// RoleName returns the name of the role this engine is running.
func (e *ClientEngine) RoleName() string {
	return e.roleName
}

// PollInterval returns the configured poll interval.
func (e *ClientEngine) PollInterval() time.Duration {
	return e.pollInterval
}

// BatchSize returns the configured batch size for MSP.
func (e *ClientEngine) BatchSize() int {
	return e.batchSize
}

// GetNextReadBatch returns the next batch of tags to read.
// Returns up to BatchSize tags, cycling through all read tags.
func (e *ClientEngine) GetNextReadBatch() []ReadRequest {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.readTags) == 0 {
		return nil
	}

	// Calculate batch
	batchSize := e.batchSize
	if batchSize > len(e.readTags) {
		batchSize = len(e.readTags)
	}

	// For simplicity, return all tags up to batch size
	// In a more sophisticated implementation, we could cycle through
	batch := make([]ReadRequest, 0, batchSize)
	for i := 0; i < batchSize && i < len(e.readTags); i++ {
		idx := (e.currentBatchIdx + i) % len(e.readTags)
		batch = append(batch, e.readTags[idx])
	}

	// Advance batch index for next call
	e.currentBatchIdx = (e.currentBatchIdx + batchSize) % len(e.readTags)

	// Update stats
	e.totalBatches++
	for _, req := range batch {
		e.totalReads++
		e.readsByTag[req.TagName]++
	}

	return batch
}

// GetAllReadTags returns all tags this role reads.
func (e *ClientEngine) GetAllReadTags() []ReadRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	result := make([]ReadRequest, len(e.readTags))
	copy(result, e.readTags)
	return result
}

// GetPendingWrites returns writes to perform this cycle and clears the queue.
func (e *ClientEngine) GetPendingWrites() []WriteRequest {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.pendingWrites) == 0 {
		return nil
	}

	result := e.pendingWrites
	e.pendingWrites = make([]WriteRequest, 0)

	// Update stats
	for _, w := range result {
		e.totalWrites++
		e.writesByTag[w.TagName]++
	}

	return result
}

// UpdateServerState updates the observed server state.
// This is typically derived from reading a "Phase" or "State" tag.
func (e *ClientEngine) UpdateServerState(state string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if state != e.serverState {
		// State changed - reset state-specific write tracking
		e.serverState = state
		e.stateWritesFired[state] = make(map[int]bool)
	}
}

// GetServerState returns the last observed server state.
func (e *ClientEngine) GetServerState() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.serverState
}

// Tick advances the engine by dt, scheduling writes as needed.
func (e *ClientEngine) Tick(dt time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	ctx := &ConditionContext{
		TimeInState: dt, // Simplified - would need actual time tracking
		TagValues:   make(map[string]interface{}),
		Events:      make(map[string]bool),
		RNG:         e.rng,
	}

	for i, evt := range e.writeEvents {
		shouldFire := false

		switch evt.TriggerType {
		case "state":
			// Fire when server is in specified state
			if e.serverState == evt.TriggerValue {
				// Check if already fired for this state
				if e.stateWritesFired[e.serverState] == nil {
					e.stateWritesFired[e.serverState] = make(map[int]bool)
				}

				// Check condition
				if evt.parsed != nil {
					if !e.writeEventFired[i] && evt.parsed.Evaluate(ctx) {
						shouldFire = true
						e.writeEventFired[i] = true
					}
				} else if !e.stateWritesFired[e.serverState][i] {
					shouldFire = true
					e.stateWritesFired[e.serverState][i] = true
				}
			}

		case "timer":
			// Fire after duration
			dur, err := time.ParseDuration(evt.TriggerValue)
			if err == nil {
				e.writeEventTimers[i] += dt
				if e.writeEventTimers[i] >= dur && !e.writeEventFired[i] {
					shouldFire = true
					e.writeEventFired[i] = true
					e.writeEventTimers[i] = 0 // Reset for next cycle
				}
			}

		case "random":
			// Fire with probability
			prob := 0.0
			fmt.Sscanf(evt.TriggerValue, "%f", &prob)
			if e.rng.Float64() < prob {
				shouldFire = true
			}
		}

		if shouldFire {
			value := e.resolveWriteValue(evt.Value)
			e.pendingWrites = append(e.pendingWrites, WriteRequest{
				TagName: evt.TagName,
				TagType: evt.TagType,
				Value:   value,
			})
		}
	}
}

// resolveWriteValue resolves a write value, handling special formats.
func (e *ClientEngine) resolveWriteValue(v interface{}) interface{} {
	if s, ok := v.(string); ok {
		// Check for random value
		if len(s) > 7 && s[:7] == "random:" {
			parts := splitParams(s[7:])
			if len(parts) >= 2 {
				min, _ := parseFloatStr(parts[0])
				max, _ := parseFloatStr(parts[1])
				return min + e.rng.Float64()*(max-min)
			}
		}
	}
	return v
}

// ResetTimers resets all timer-based write events.
func (e *ClientEngine) ResetTimers() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.writeEventTimers = make(map[int]time.Duration)
	e.writeEventFired = make(map[int]bool)
}

// GetStats returns engine statistics.
func (e *ClientEngine) GetStats() ClientEngineStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return ClientEngineStats{
		TotalReads:   e.totalReads,
		TotalWrites:  e.totalWrites,
		TotalBatches: e.totalBatches,
		ReadsByTag:   copyMap(e.readsByTag),
		WritesByTag:  copyMap(e.writesByTag),
	}
}

// ClientEngineStats contains engine statistics.
type ClientEngineStats struct {
	TotalReads   int64
	TotalWrites  int64
	TotalBatches int64
	ReadsByTag   map[string]int64
	WritesByTag  map[string]int64
}

func copyMap(m map[string]int64) map[string]int64 {
	result := make(map[string]int64, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

// CanWrite returns true if this role can write to the specified tag.
func (e *ClientEngine) CanWrite(tagName string) bool {
	for _, t := range e.role.WriteTags {
		if t == tagName {
			return true
		}
	}
	return false
}

// GetWritableTags returns the list of tags this role can write to.
func (e *ClientEngine) GetWritableTags() []string {
	result := make([]string, len(e.role.WriteTags))
	copy(result, e.role.WriteTags)
	return result
}

// ScheduleWrite manually schedules a write for the next cycle.
func (e *ClientEngine) ScheduleWrite(tagName string, value interface{}) error {
	if !e.CanWrite(tagName) {
		return fmt.Errorf("role %q cannot write to tag %q", e.roleName, tagName)
	}

	tagType := "DINT"
	if tag := e.profile.GetTagByName(tagName); tag != nil {
		tagType = tag.Type
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.pendingWrites = append(e.pendingWrites, WriteRequest{
		TagName: tagName,
		TagType: tagType,
		Value:   value,
	})

	return nil
}
