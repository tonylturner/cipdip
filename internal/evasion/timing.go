package evasion

// Timing-based DPI evasion techniques.
//
// DPI engines often have timeouts for TCP stream reassembly and protocol
// state tracking. Manipulating packet timing can cause the DPI engine
// to expire its state before the complete protocol exchange is visible.

import (
	"math/rand"
	"time"
)

// TimingPlan describes how to pace the delivery of data.
type TimingPlan struct {
	Steps []TimingStep
}

// TimingStep is a single step in a timing plan.
type TimingStep struct {
	Data     []byte
	Delay    time.Duration // Delay before sending this step
	Label    string
}

// PlanSlowRate creates a timing plan that sends one byte at a time
// with a fixed delay between each byte.
func PlanSlowRate(payload []byte, interval time.Duration) *TimingPlan {
	plan := &TimingPlan{}
	for i, b := range payload {
		delay := interval
		if i == 0 {
			delay = 0 // No delay before first byte
		}
		plan.Steps = append(plan.Steps, TimingStep{
			Data:  []byte{b},
			Delay: delay,
			Label: "byte",
		})
	}
	return plan
}

// PlanVariableTiming creates a timing plan that sends chunks of data
// with random delays between them.
func PlanVariableTiming(payload []byte, cfg TimingConfig) *TimingPlan {
	plan := &TimingPlan{}
	chunkSize := 16 // Send 16 bytes per chunk
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for offset := 0; offset < len(payload); offset += chunkSize {
		end := offset + chunkSize
		if end > len(payload) {
			end = len(payload)
		}

		var delay time.Duration
		if offset > 0 {
			delayRange := cfg.MaxDelay - cfg.MinDelay
			if delayRange > 0 {
				delay = cfg.MinDelay + time.Duration(rng.Int63n(int64(delayRange)))
			} else {
				delay = cfg.MinDelay
			}
		}

		plan.Steps = append(plan.Steps, TimingStep{
			Data:  cloneSlice(payload[offset:end]),
			Delay: delay,
			Label: "chunk",
		})
	}
	return plan
}

// PlanKeepaliveAbuse creates a timing plan that intersperses the payload
// with TCP keepalive-style zero-length segments at high frequency.
func PlanKeepaliveAbuse(payload []byte, cfg TimingConfig) *TimingPlan {
	plan := &TimingPlan{}
	chunkSize := 64
	keepaliveData := []byte{} // Empty "keepalive"

	for offset := 0; offset < len(payload); offset += chunkSize {
		end := offset + chunkSize
		if end > len(payload) {
			end = len(payload)
		}

		// Send keepalive before each real chunk
		if offset > 0 {
			plan.Steps = append(plan.Steps, TimingStep{
				Data:  keepaliveData,
				Delay: cfg.KeepaliveInterval,
				Label: "keepalive",
			})
		}

		plan.Steps = append(plan.Steps, TimingStep{
			Data:  cloneSlice(payload[offset:end]),
			Delay: 0, // No delay for real data
			Label: "data",
		})
	}
	return plan
}

// TotalDelay calculates the total delay for a timing plan.
func (p *TimingPlan) TotalDelay() time.Duration {
	var total time.Duration
	for _, step := range p.Steps {
		total += step.Delay
	}
	return total
}

// TotalBytes returns the total payload size across all steps.
func (p *TimingPlan) TotalBytes() int {
	total := 0
	for _, step := range p.Steps {
		total += len(step.Data)
	}
	return total
}
