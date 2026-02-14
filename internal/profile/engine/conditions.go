package engine

import (
	"math/rand"
	"strconv"
	"strings"
	"time"
)

// Condition evaluates whether a state transition should occur.
type Condition interface {
	// Evaluate returns true if the condition is met.
	Evaluate(ctx *ConditionContext) bool
	// Reset resets any internal state (e.g., timers).
	Reset()
}

// ConditionContext provides access to engine state for condition evaluation.
type ConditionContext struct {
	TimeInState time.Duration
	TagValues   map[string]interface{}
	Events      map[string]bool // Events that have occurred
	RNG         *rand.Rand
}

// TimerCondition triggers after a duration in the current state.
type TimerCondition struct {
	Duration time.Duration
}

func (c *TimerCondition) Evaluate(ctx *ConditionContext) bool {
	return ctx.TimeInState >= c.Duration
}

func (c *TimerCondition) Reset() {}

// TagCondition compares a tag value.
type TagCondition struct {
	TagName  string
	Operator string // "==", "!=", ">", "<", ">=", "<="
	Value    interface{}
	TagRef   string // If comparing to another tag
}

func (c *TagCondition) Evaluate(ctx *ConditionContext) bool {
	tagValue, ok := ctx.TagValues[c.TagName]
	if !ok {
		return false
	}

	compareValue := c.Value
	if c.TagRef != "" {
		if refValue, ok := ctx.TagValues[c.TagRef]; ok {
			compareValue = refValue
		} else {
			return false
		}
	}

	return compareValues(tagValue, c.Operator, compareValue)
}

func (c *TagCondition) Reset() {}

// RandomCondition triggers with a probability on each evaluation.
type RandomCondition struct {
	Probability float64
}

func (c *RandomCondition) Evaluate(ctx *ConditionContext) bool {
	return ctx.RNG.Float64() < c.Probability
}

func (c *RandomCondition) Reset() {}

// EventCondition triggers when a named event has occurred.
type EventCondition struct {
	EventName string
}

func (c *EventCondition) Evaluate(ctx *ConditionContext) bool {
	return ctx.Events[c.EventName]
}

func (c *EventCondition) Reset() {}

// OnceCondition triggers once and then never again until reset.
type OnceCondition struct {
	Triggered bool
}

func (c *OnceCondition) Evaluate(ctx *ConditionContext) bool {
	if c.Triggered {
		return false
	}
	c.Triggered = true
	return true
}

func (c *OnceCondition) Reset() {
	c.Triggered = false
}

// ParseCondition parses a condition string.
// Formats:
//   - "timer:30s" - After 30 seconds in state
//   - "tag:AlarmAck==true" - When tag equals value
//   - "tag:TankLevel>10" - When tag is greater than value
//   - "tag:Temperature>=tag:TempSetpoint" - Compare two tags
//   - "random:0.1" - 10% chance per tick
//   - "event:alarm_triggered" - When event has occurred
//   - "once" - Triggers once per state entry
func ParseCondition(condStr string) Condition {
	condStr = strings.TrimSpace(condStr)

	if condStr == "once" {
		return &OnceCondition{}
	}

	colonIdx := strings.Index(condStr, ":")
	if colonIdx == -1 {
		return nil
	}

	condType := condStr[:colonIdx]
	condValue := condStr[colonIdx+1:]

	switch condType {
	case "timer":
		dur, err := time.ParseDuration(condValue)
		if err != nil {
			return nil
		}
		return &TimerCondition{Duration: dur}

	case "tag":
		return parseTagCondition(condValue)

	case "random":
		prob, err := strconv.ParseFloat(condValue, 64)
		if err != nil {
			return nil
		}
		return &RandomCondition{Probability: prob}

	case "event":
		return &EventCondition{EventName: condValue}

	case "state":
		// "state:running" - Not really a condition, but used in write events
		// For now, treat as always true (handled at a higher level)
		return &AlwaysTrueCondition{}

	default:
		return nil
	}
}

// parseTagCondition parses "TagName==value" or "TagName>=tag:OtherTag".
func parseTagCondition(s string) *TagCondition {
	// Find operator
	operators := []string{">=", "<=", "!=", "==", ">", "<"}
	opIdx := -1
	var op string

	for _, o := range operators {
		idx := strings.Index(s, o)
		if idx != -1 && (opIdx == -1 || idx < opIdx) {
			opIdx = idx
			op = o
		}
	}

	if opIdx == -1 {
		return nil
	}

	tagName := strings.TrimSpace(s[:opIdx])
	valueStr := strings.TrimSpace(s[opIdx+len(op):])

	cond := &TagCondition{
		TagName:  tagName,
		Operator: op,
	}

	// Check if comparing to another tag
	if strings.HasPrefix(valueStr, "tag:") {
		cond.TagRef = valueStr[4:]
	} else {
		cond.Value = parseValue(valueStr)
	}

	return cond
}

// parseValue parses a value string into the appropriate type.
func parseValue(s string) interface{} {
	s = strings.TrimSpace(s)

	// Boolean
	if s == "true" {
		return true
	}
	if s == "false" {
		return false
	}

	// Integer
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i
	}

	// Float
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}

	// String
	return s
}

// compareValues compares two values with the given operator.
func compareValues(a interface{}, op string, b interface{}) bool {
	// Handle boolean comparison
	if aBool, ok := a.(bool); ok {
		bBool, ok := b.(bool)
		if !ok {
			// Try to convert b
			switch v := b.(type) {
			case string:
				bBool = v == "true"
			case int64:
				bBool = v != 0
			case float64:
				bBool = v != 0
			default:
				return false
			}
		}
		switch op {
		case "==":
			return aBool == bBool
		case "!=":
			return aBool != bBool
		}
		return false
	}

	// Convert both to float64 for numeric comparison
	aFloat := toFloat64(a)
	bFloat := toFloat64(b)

	switch op {
	case "==":
		return aFloat == bFloat
	case "!=":
		return aFloat != bFloat
	case ">":
		return aFloat > bFloat
	case "<":
		return aFloat < bFloat
	case ">=":
		return aFloat >= bFloat
	case "<=":
		return aFloat <= bFloat
	}

	return false
}

// toFloat64 converts a value to float64.
func toFloat64(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case float32:
		return float64(val)
	case int:
		return float64(val)
	case int32:
		return float64(val)
	case int64:
		return float64(val)
	case bool:
		if val {
			return 1
		}
		return 0
	case string:
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			return f
		}
	}
	return 0
}

// AlwaysTrueCondition always returns true.
type AlwaysTrueCondition struct{}

func (c *AlwaysTrueCondition) Evaluate(ctx *ConditionContext) bool { return true }
func (c *AlwaysTrueCondition) Reset()                              {}

// AlwaysFalseCondition always returns false.
type AlwaysFalseCondition struct{}

func (c *AlwaysFalseCondition) Evaluate(ctx *ConditionContext) bool { return false }
func (c *AlwaysFalseCondition) Reset()                              {}
