// Package engine implements the profile execution engines for server and client.
package engine

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/tturner/cipdip/internal/profile"
)

// EventRecord logs an event occurrence.
type EventRecord struct {
	Timestamp time.Time `json:"timestamp"`
	State     string    `json:"state"`
	Event     string    `json:"event"`
	Message   string    `json:"message,omitempty"`
}

// StateRecord logs a state transition.
type StateRecord struct {
	Timestamp time.Time     `json:"timestamp"`
	FromState string        `json:"from_state"`
	ToState   string        `json:"to_state"`
	Duration  time.Duration `json:"duration_in_state"`
	Trigger   string        `json:"trigger"`
}

// ServerEngine manages profile state for the server.
type ServerEngine struct {
	profile *profile.Profile
	rng     *rand.Rand

	// State machine
	currentState   string
	stateStartTime time.Time
	timeInState    time.Duration

	// Tag values and rules
	tagValues map[string]interface{}
	tagRules  map[string]UpdateRule
	tagTypes  map[string]string

	// Assembly data
	assemblyData map[string][]byte

	// State-specific overrides (active while in state)
	activeOverrides map[string]UpdateRule

	// Events and transitions
	eventLog    []EventRecord
	stateLog    []StateRecord
	firedEvents map[string]bool // Events that have fired in current state

	// Parsed conditions for performance
	transitionConditions map[string][]parsedTransition
	eventConditions      map[string][]parsedEvent

	mu sync.RWMutex
}

type parsedTransition struct {
	ToState   string
	Condition Condition
	Priority  int
}

type parsedEvent struct {
	Name      string
	Trigger   Condition
	Actions   []profile.Action
}

// NewServerEngine creates a new server engine from a profile.
func NewServerEngine(p *profile.Profile) (*ServerEngine, error) {
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid profile: %w", err)
	}

	seed := p.Metadata.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}

	e := &ServerEngine{
		profile:              p,
		rng:                  rand.New(rand.NewSource(seed)),
		currentState:         p.StateMachine.InitialState,
		stateStartTime:       time.Now(),
		tagValues:            make(map[string]interface{}),
		tagRules:             make(map[string]UpdateRule),
		tagTypes:             make(map[string]string),
		assemblyData:         make(map[string][]byte),
		activeOverrides:      make(map[string]UpdateRule),
		eventLog:             make([]EventRecord, 0),
		stateLog:             make([]StateRecord, 0),
		firedEvents:          make(map[string]bool),
		transitionConditions: make(map[string][]parsedTransition),
		eventConditions:      make(map[string][]parsedEvent),
	}

	// Initialize tags
	for _, tag := range p.DataModel.Tags {
		e.tagValues[tag.Name] = tag.InitialValue
		e.tagRules[tag.Name] = ParseUpdateRule(tag.UpdateRule, tag.UpdateParams)
		e.tagTypes[tag.Name] = tag.Type
	}

	// Initialize assemblies
	for _, asm := range p.DataModel.Assemblies {
		e.assemblyData[asm.Name] = make([]byte, asm.SizeBytes)
	}

	// Parse conditions for all states
	for stateName, state := range p.StateMachine.States {
		// Parse transitions
		var transitions []parsedTransition
		for _, trans := range state.Transitions {
			cond := ParseCondition(trans.Condition)
			if cond != nil {
				transitions = append(transitions, parsedTransition{
					ToState:   trans.To,
					Condition: cond,
					Priority:  trans.Priority,
				})
			}
		}
		e.transitionConditions[stateName] = transitions

		// Parse events
		var events []parsedEvent
		for _, evt := range state.Events {
			trigger := ParseCondition(evt.Trigger)
			if trigger != nil {
				events = append(events, parsedEvent{
					Name:    evt.Name,
					Trigger: trigger,
					Actions: evt.Actions,
				})
			}
		}
		e.eventConditions[stateName] = events
	}

	// Apply initial state overrides
	e.applyStateOverrides(p.StateMachine.InitialState)

	return e, nil
}

// CurrentState returns the current state name.
func (e *ServerEngine) CurrentState() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.currentState
}

// TimeInState returns how long the engine has been in the current state.
func (e *ServerEngine) TimeInState() time.Duration {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.timeInState
}

// GetTagValue returns the current value of a tag.
func (e *ServerEngine) GetTagValue(name string) (interface{}, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	v, ok := e.tagValues[name]
	return v, ok
}

// GetTagValues returns a copy of all tag values.
func (e *ServerEngine) GetTagValues() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[string]interface{}, len(e.tagValues))
	for k, v := range e.tagValues {
		result[k] = v
	}
	return result
}

// ResolveRead returns the value for a tag read request.
func (e *ServerEngine) ResolveRead(name string) ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Check if it's a tag
	if value, ok := e.tagValues[name]; ok {
		tagType := e.tagTypes[name]
		return encodeTagValue(value, tagType)
	}

	// Check if it's an assembly
	if data, ok := e.assemblyData[name]; ok {
		result := make([]byte, len(data))
		copy(result, data)
		return result, nil
	}

	return nil, fmt.Errorf("unknown tag or assembly: %s", name)
}

// ApplyWrite handles a write request.
// Returns true if the write was accepted, false if denied.
func (e *ServerEngine) ApplyWrite(name string, value []byte) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Check if it's a writable tag
	tag := e.profile.GetTagByName(name)
	if tag != nil {
		if !tag.Writable {
			return false, nil
		}

		// Decode and apply the value
		decoded, err := decodeTagValue(value, tag.Type)
		if err != nil {
			return false, err
		}
		e.tagValues[name] = decoded
		return true, nil
	}

	// Check if it's a writable assembly
	asm := e.profile.GetAssemblyByName(name)
	if asm != nil {
		if !asm.Writable {
			return false, nil
		}
		if len(value) > asm.SizeBytes {
			value = value[:asm.SizeBytes]
		}
		copy(e.assemblyData[name], value)
		return true, nil
	}

	return false, fmt.Errorf("unknown tag or assembly: %s", name)
}

// Tick advances the engine state by the given duration.
func (e *ServerEngine) Tick(dt time.Duration) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.timeInState += dt

	// Update tag values
	for name, rule := range e.tagRules {
		// Check for active overrides
		if override, ok := e.activeOverrides[name]; ok {
			e.tagValues[name] = override.Update(e.tagValues[name], dt, e.rng)
		} else {
			e.tagValues[name] = rule.Update(e.tagValues[name], dt, e.rng)
		}
	}

	// Build condition context
	ctx := &ConditionContext{
		TimeInState: e.timeInState,
		TagValues:   e.tagValues,
		Events:      e.firedEvents,
		RNG:         e.rng,
	}

	// Check events
	for _, evt := range e.eventConditions[e.currentState] {
		if !e.firedEvents[evt.Name] && evt.Trigger.Evaluate(ctx) {
			e.firedEvents[evt.Name] = true
			e.executeActions(evt.Actions)
			e.eventLog = append(e.eventLog, EventRecord{
				Timestamp: time.Now(),
				State:     e.currentState,
				Event:     evt.Name,
			})
		}
	}

	// Check transitions (in priority order)
	transitions := e.transitionConditions[e.currentState]
	var bestTransition *parsedTransition
	for i := range transitions {
		trans := &transitions[i]
		if trans.Condition.Evaluate(ctx) {
			if bestTransition == nil || trans.Priority < bestTransition.Priority {
				bestTransition = trans
			}
		}
	}

	if bestTransition != nil {
		e.transitionTo(bestTransition.ToState, bestTransition.Condition)
	}

	return nil
}

// transitionTo changes to a new state.
func (e *ServerEngine) transitionTo(newState string, trigger Condition) {
	oldState := e.currentState

	// Log state transition
	e.stateLog = append(e.stateLog, StateRecord{
		Timestamp: time.Now(),
		FromState: oldState,
		ToState:   newState,
		Duration:  e.timeInState,
		Trigger:   fmt.Sprintf("%T", trigger),
	})

	// Clear state-specific data
	e.firedEvents = make(map[string]bool)
	e.activeOverrides = make(map[string]UpdateRule)

	// Reset conditions for new state
	for _, trans := range e.transitionConditions[newState] {
		trans.Condition.Reset()
	}
	for _, evt := range e.eventConditions[newState] {
		evt.Trigger.Reset()
	}

	// Apply new state
	e.currentState = newState
	e.stateStartTime = time.Now()
	e.timeInState = 0

	// Apply new state overrides
	e.applyStateOverrides(newState)
}

// applyStateOverrides applies tag overrides for a state.
func (e *ServerEngine) applyStateOverrides(stateName string) {
	state, ok := e.profile.StateMachine.States[stateName]
	if !ok {
		return
	}

	for tagName, overrideStr := range state.TagOverrides {
		override := ParseOverrideRule(overrideStr)
		e.activeOverrides[tagName] = override

		// For static overrides, apply immediately
		if static, ok := override.(*StaticRule); ok && static.Value != nil {
			e.tagValues[tagName] = static.Value
		}
	}
}

// executeActions executes a list of actions.
func (e *ServerEngine) executeActions(actions []profile.Action) {
	for _, action := range actions {
		switch action.Type {
		case "set_tag":
			if value := parseActionValue(action.Value, e.tagValues, e.rng); value != nil {
				e.tagValues[action.Target] = value
			}
		case "log":
			// Log message - add to event log
			msg := ""
			if s, ok := action.Value.(string); ok {
				msg = s
			}
			e.eventLog = append(e.eventLog, EventRecord{
				Timestamp: time.Now(),
				State:     e.currentState,
				Event:     "log",
				Message:   msg,
			})
		case "trigger_transition":
			// Force a transition
			if action.Target != "" {
				e.transitionTo(action.Target, &AlwaysTrueCondition{})
			}
		}
	}
}

// parseActionValue parses an action value.
func parseActionValue(v interface{}, tagValues map[string]interface{}, rng *rand.Rand) interface{} {
	if s, ok := v.(string); ok {
		// Check for special formats
		if s == "increment" {
			return nil // Handled specially
		}
		if len(s) > 7 && s[:7] == "random:" {
			// Format: "random:min:max"
			parts := splitParams(s[7:])
			if len(parts) >= 2 {
				min, _ := parseFloatStr(parts[0])
				max, _ := parseFloatStr(parts[1])
				return min + rng.Float64()*(max-min)
			}
		}
		if len(s) > 4 && s[:4] == "tag:" {
			// Reference another tag
			tagName := s[4:]
			if val, ok := tagValues[tagName]; ok {
				return val
			}
		}
	}
	return v
}

// GetEventLog returns a copy of the event log.
func (e *ServerEngine) GetEventLog() []EventRecord {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]EventRecord, len(e.eventLog))
	copy(result, e.eventLog)
	return result
}

// GetStateLog returns a copy of the state transition log.
func (e *ServerEngine) GetStateLog() []StateRecord {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]StateRecord, len(e.stateLog))
	copy(result, e.stateLog)
	return result
}

// GetStatesCovered returns the set of states that have been visited.
func (e *ServerEngine) GetStatesCovered() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	seen := make(map[string]bool)
	seen[e.profile.StateMachine.InitialState] = true
	for _, rec := range e.stateLog {
		seen[rec.ToState] = true
	}

	result := make([]string, 0, len(seen))
	for state := range seen {
		result = append(result, state)
	}
	return result
}

// encodeTagValue encodes a value to bytes based on CIP type.
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
		binary.LittleEndian.PutUint16(b, uint16(toInt(value)))
		return b, nil

	case "DINT":
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(toInt(value)))
		return b, nil

	case "REAL":
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, math.Float32bits(float32(toFloat64(value))))
		return b, nil

	case "LREAL":
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, math.Float64bits(toFloat64(value)))
		return b, nil

	default:
		// Default to 4 bytes
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(toInt(value)))
		return b, nil
	}
}

// decodeTagValue decodes bytes to a value based on CIP type.
func decodeTagValue(data []byte, tagType string) (interface{}, error) {
	switch tagType {
	case "BOOL":
		if len(data) < 1 {
			return false, nil
		}
		return data[0] != 0, nil

	case "SINT":
		if len(data) < 1 {
			return int8(0), nil
		}
		return int8(data[0]), nil

	case "INT":
		if len(data) < 2 {
			return int16(0), nil
		}
		return int16(binary.LittleEndian.Uint16(data)), nil

	case "DINT":
		if len(data) < 4 {
			return int32(0), nil
		}
		return int32(binary.LittleEndian.Uint32(data)), nil

	case "REAL":
		if len(data) < 4 {
			return float32(0), nil
		}
		return math.Float32frombits(binary.LittleEndian.Uint32(data)), nil

	case "LREAL":
		if len(data) < 8 {
			return float64(0), nil
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(data)), nil

	default:
		if len(data) < 4 {
			return int32(0), nil
		}
		return int32(binary.LittleEndian.Uint32(data)), nil
	}
}

func toInt(v interface{}) int64 {
	switch val := v.(type) {
	case int:
		return int64(val)
	case int8:
		return int64(val)
	case int16:
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
