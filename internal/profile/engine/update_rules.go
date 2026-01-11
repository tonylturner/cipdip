package engine

import (
	"math"
	"math/rand"
	"time"
)

// UpdateRule defines how a tag value changes over time.
type UpdateRule interface {
	// Update returns the new value based on elapsed time and current value.
	Update(current interface{}, dt time.Duration, rng *rand.Rand) interface{}
}

// StaticRule returns the same value (no change).
type StaticRule struct {
	Value interface{}
}

func (r *StaticRule) Update(current interface{}, dt time.Duration, rng *rand.Rand) interface{} {
	if r.Value != nil {
		return r.Value
	}
	return current
}

// CounterRule increments a value at a fixed interval.
type CounterRule struct {
	Increment   int64
	Interval    time.Duration
	Accumulated time.Duration
}

func (r *CounterRule) Update(current interface{}, dt time.Duration, rng *rand.Rand) interface{} {
	if r.Interval <= 0 {
		return current
	}

	r.Accumulated += dt

	// Count how many intervals have passed
	increments := int64(r.Accumulated / r.Interval)
	if increments > 0 {
		r.Accumulated = r.Accumulated % r.Interval

		switch v := current.(type) {
		case int:
			return int(int64(v) + increments*r.Increment)
		case int32:
			return int32(int64(v) + increments*r.Increment)
		case int64:
			return v + increments*r.Increment
		case float64:
			return v + float64(increments*r.Increment)
		}
	}
	return current
}

// RampRule linearly changes a value between min and max.
type RampRule struct {
	Min       float64
	Max       float64
	Rate      float64 // units per second
	Direction int     // 1 = up, -1 = down
}

func (r *RampRule) Update(current interface{}, dt time.Duration, rng *rand.Rand) interface{} {
	var val float64
	switch v := current.(type) {
	case float64:
		val = v
	case float32:
		val = float64(v)
	case int:
		val = float64(v)
	case int32:
		val = float64(v)
	case int64:
		val = float64(v)
	default:
		return current
	}

	delta := r.Rate * dt.Seconds() * float64(r.Direction)
	val += delta

	// Bounce at limits
	if val >= r.Max {
		val = r.Max
		r.Direction = -1
	} else if val <= r.Min {
		val = r.Min
		r.Direction = 1
	}

	return val
}

// SineRule produces a sinusoidal wave.
type SineRule struct {
	Amplitude float64
	Offset    float64
	Period    time.Duration
	Phase     float64 // accumulated phase in radians
}

func (r *SineRule) Update(current interface{}, dt time.Duration, rng *rand.Rand) interface{} {
	if r.Period <= 0 {
		return current
	}

	// Advance phase
	r.Phase += 2 * math.Pi * dt.Seconds() / r.Period.Seconds()
	if r.Phase > 2*math.Pi {
		r.Phase -= 2 * math.Pi
	}

	return r.Offset + r.Amplitude*math.Sin(r.Phase)
}

// ToggleRule alternates a boolean at a fixed interval.
type ToggleRule struct {
	Interval    time.Duration
	Accumulated time.Duration
}

func (r *ToggleRule) Update(current interface{}, dt time.Duration, rng *rand.Rand) interface{} {
	if r.Interval <= 0 {
		return current
	}

	r.Accumulated += dt

	if r.Accumulated >= r.Interval {
		r.Accumulated = 0
		switch v := current.(type) {
		case bool:
			return !v
		}
	}
	return current
}

// LatchRule holds a value until explicitly set.
type LatchRule struct {
	Value    interface{}
	HasValue bool
}

func (r *LatchRule) Update(current interface{}, dt time.Duration, rng *rand.Rand) interface{} {
	if r.HasValue {
		return r.Value
	}
	return current
}

func (r *LatchRule) Set(value interface{}) {
	r.Value = value
	r.HasValue = true
}

func (r *LatchRule) Clear() {
	r.HasValue = false
}

// RandomRule produces random values in a range.
type RandomRule struct {
	Min float64
	Max float64
}

func (r *RandomRule) Update(current interface{}, dt time.Duration, rng *rand.Rand) interface{} {
	return r.Min + rng.Float64()*(r.Max-r.Min)
}

// ParseUpdateRule creates an UpdateRule from a rule string and parameters.
func ParseUpdateRule(rule string, params map[string]interface{}) UpdateRule {
	switch rule {
	case "static":
		return &StaticRule{}

	case "counter":
		increment := int64(1)
		interval := time.Second

		if v, ok := params["increment"]; ok {
			switch i := v.(type) {
			case int:
				increment = int64(i)
			case float64:
				increment = int64(i)
			}
		}
		if v, ok := params["interval"]; ok {
			if s, ok := v.(string); ok {
				if d, err := time.ParseDuration(s); err == nil {
					interval = d
				}
			}
		}
		return &CounterRule{Increment: increment, Interval: interval}

	case "ramp":
		min := 0.0
		max := 100.0
		rate := 1.0

		if v, ok := params["min"]; ok {
			if f, ok := v.(float64); ok {
				min = f
			}
		}
		if v, ok := params["max"]; ok {
			if f, ok := v.(float64); ok {
				max = f
			}
		}
		if v, ok := params["rate"]; ok {
			if f, ok := v.(float64); ok {
				rate = f
			}
		}
		return &RampRule{Min: min, Max: max, Rate: rate, Direction: 1}

	case "sine":
		amplitude := 1.0
		offset := 0.0
		period := time.Minute

		if v, ok := params["amplitude"]; ok {
			if f, ok := v.(float64); ok {
				amplitude = f
			}
		}
		if v, ok := params["offset"]; ok {
			if f, ok := v.(float64); ok {
				offset = f
			}
		}
		if v, ok := params["period"]; ok {
			if s, ok := v.(string); ok {
				if d, err := time.ParseDuration(s); err == nil {
					period = d
				}
			}
		}
		return &SineRule{Amplitude: amplitude, Offset: offset, Period: period}

	case "toggle":
		interval := 3 * time.Second
		if v, ok := params["interval"]; ok {
			if s, ok := v.(string); ok {
				if d, err := time.ParseDuration(s); err == nil {
					interval = d
				}
			}
		}
		return &ToggleRule{Interval: interval}

	case "latch":
		return &LatchRule{}

	case "random":
		min := 0.0
		max := 100.0
		if v, ok := params["min"]; ok {
			if f, ok := v.(float64); ok {
				min = f
			}
		}
		if v, ok := params["max"]; ok {
			if f, ok := v.(float64); ok {
				max = f
			}
		}
		return &RandomRule{Min: min, Max: max}

	default:
		return &StaticRule{}
	}
}

// ParseOverrideRule parses a state tag override string like "static:false" or "ramp:0:100:2".
func ParseOverrideRule(override string) UpdateRule {
	// Format: "rule_type:param1:param2:..."
	// Examples: "static:false", "static:true", "static:0", "ramp:0:100:2"

	if len(override) == 0 {
		return &StaticRule{}
	}

	// Find the rule type
	colonIdx := -1
	for i, c := range override {
		if c == ':' {
			colonIdx = i
			break
		}
	}

	if colonIdx == -1 {
		// No parameters, just rule type
		return ParseUpdateRule(override, nil)
	}

	ruleType := override[:colonIdx]
	paramStr := override[colonIdx+1:]

	switch ruleType {
	case "static":
		// Parse the value
		var value interface{}
		switch paramStr {
		case "true":
			value = true
		case "false":
			value = false
		default:
			// Try to parse as number
			var f float64
			if _, err := parseFloat(paramStr, &f); err == nil {
				value = f
			} else {
				value = paramStr
			}
		}
		return &StaticRule{Value: value}

	case "ramp":
		// Format: "ramp:min:max:rate"
		params := splitParams(paramStr)
		p := make(map[string]interface{})
		if len(params) >= 1 {
			if f, err := parseFloatStr(params[0]); err == nil {
				p["min"] = f
			}
		}
		if len(params) >= 2 {
			if f, err := parseFloatStr(params[1]); err == nil {
				p["max"] = f
			}
		}
		if len(params) >= 3 {
			if f, err := parseFloatStr(params[2]); err == nil {
				p["rate"] = f
			}
		}
		return ParseUpdateRule("ramp", p)

	case "random":
		// Format: "random:min:max"
		params := splitParams(paramStr)
		p := make(map[string]interface{})
		if len(params) >= 1 {
			if f, err := parseFloatStr(params[0]); err == nil {
				p["min"] = f
			}
		}
		if len(params) >= 2 {
			if f, err := parseFloatStr(params[1]); err == nil {
				p["max"] = f
			}
		}
		return ParseUpdateRule("random", p)

	default:
		return ParseUpdateRule(ruleType, nil)
	}
}

func splitParams(s string) []string {
	var result []string
	current := ""
	for _, c := range s {
		if c == ':' {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func parseFloat(s string, f *float64) (int, error) {
	var n int
	_, err := scanFloat(s, f, &n)
	return n, err
}

func parseFloatStr(s string) (float64, error) {
	var f float64
	_, err := scanFloat(s, &f, nil)
	return f, err
}

func scanFloat(s string, f *float64, n *int) (string, error) {
	// Simple float parser
	negative := false
	idx := 0

	if idx < len(s) && s[idx] == '-' {
		negative = true
		idx++
	}

	var intPart int64
	for idx < len(s) && s[idx] >= '0' && s[idx] <= '9' {
		intPart = intPart*10 + int64(s[idx]-'0')
		idx++
	}

	var fracPart float64
	if idx < len(s) && s[idx] == '.' {
		idx++
		divisor := 10.0
		for idx < len(s) && s[idx] >= '0' && s[idx] <= '9' {
			fracPart += float64(s[idx]-'0') / divisor
			divisor *= 10
			idx++
		}
	}

	result := float64(intPart) + fracPart
	if negative {
		result = -result
	}

	*f = result
	if n != nil {
		*n = idx
	}

	if idx == 0 || (idx == 1 && negative) {
		return s, &parseError{"invalid float"}
	}

	return s[idx:], nil
}

type parseError struct {
	msg string
}

func (e *parseError) Error() string {
	return e.msg
}
