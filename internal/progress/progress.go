package progress

import (
	"fmt"
	"io"
	"os"
	"time"
)

// ProgressBar provides a simple progress indicator
type ProgressBar struct {
	total       int64
	current     int64
	startTime   time.Time
	lastUpdate  time.Time
	output      io.Writer
	enabled     bool
	description string
}

// NewProgressBar creates a new progress bar
func NewProgressBar(total int64, description string) *ProgressBar {
	return &ProgressBar{
		total:       total,
		current:     0,
		startTime:   time.Now(),
		lastUpdate:  time.Now(),
		output:      os.Stderr, // Use stderr so it doesn't interfere with stdout
		enabled:     true,
		description: description,
	}
}

// Disable disables the progress bar
func (p *ProgressBar) Disable() {
	p.enabled = false
}

// Enable enables the progress bar
func (p *ProgressBar) Enable() {
	p.enabled = true
}

// Update updates the progress bar
func (p *ProgressBar) Update(n int64) {
	p.current += n
	p.render()
}

// Set sets the current progress
func (p *ProgressBar) Set(n int64) {
	p.current = n
	p.render()
}

// Increment increments the progress by 1
func (p *ProgressBar) Increment() {
	p.current++
	p.render()
}

// render renders the progress bar
func (p *ProgressBar) render() {
	if !p.enabled {
		return
	}

	// Throttle updates to avoid too much output
	now := time.Now()
	if now.Sub(p.lastUpdate) < 100*time.Millisecond && p.current < p.total {
		return
	}
	p.lastUpdate = now

	// Calculate percentage
	var percent float64
	if p.total > 0 {
		percent = float64(p.current) / float64(p.total) * 100
	} else {
		percent = 0
	}

	// Calculate elapsed time
	elapsed := time.Since(p.startTime)

	// Calculate ETA
	var eta time.Duration
	if p.current > 0 && p.total > 0 {
		rate := float64(p.current) / elapsed.Seconds()
		if rate > 0 {
			remaining := float64(p.total-p.current) / rate
			eta = time.Duration(remaining) * time.Second
		}
	}

	// Build progress bar (50 characters wide)
	barWidth := 50
	filled := int(float64(barWidth) * percent / 100)
	if filled > barWidth {
		filled = barWidth
	}

	bar := make([]byte, barWidth)
	for i := 0; i < filled; i++ {
		bar[i] = '='
	}
	if filled < barWidth {
		bar[filled] = '>'
		for i := filled + 1; i < barWidth; i++ {
			bar[i] = '-'
		}
	}

	// Format output
	var output string
	if p.description != "" {
		output = fmt.Sprintf("\r%s [%s] %d/%d (%.1f%%) | Elapsed: %s", p.description, string(bar), p.current, p.total, percent, formatDuration(elapsed))
	} else {
		output = fmt.Sprintf("\r[%s] %d/%d (%.1f%%) | Elapsed: %s", string(bar), p.current, p.total, percent, formatDuration(elapsed))
	}

	if eta > 0 && p.current < p.total {
		output += fmt.Sprintf(" | ETA: %s", formatDuration(eta))
	}

	fmt.Fprint(p.output, output)
}

// Finish finishes the progress bar
func (p *ProgressBar) Finish() {
	if !p.enabled {
		return
	}

	p.current = p.total
	p.render()
	fmt.Fprint(p.output, "\n") // New line after completion
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm%ds", minutes, seconds)
}

// SimpleProgress provides a simple progress indicator without a bar
type SimpleProgress struct {
	output      io.Writer
	enabled     bool
	description string
	lastUpdate  time.Time
	interval    time.Duration
}

// NewSimpleProgress creates a new simple progress indicator
func NewSimpleProgress(description string, updateInterval time.Duration) *SimpleProgress {
	return &SimpleProgress{
		output:      os.Stderr,
		enabled:     true,
		description: description,
		lastUpdate:  time.Now(),
		interval:    updateInterval,
	}
}

// Update updates the progress with a count
func (s *SimpleProgress) Update(count int64, message string) {
	if !s.enabled {
		return
	}

	now := time.Now()
	if now.Sub(s.lastUpdate) < s.interval {
		return
	}
	s.lastUpdate = now

	var output string
	if s.description != "" {
		output = fmt.Sprintf("\r%s: %d operations", s.description, count)
	} else {
		output = fmt.Sprintf("\r%d operations", count)
	}

	if message != "" {
		output += fmt.Sprintf(" | %s", message)
	}

	fmt.Fprint(s.output, output)
}

// Finish finishes the progress indicator
func (s *SimpleProgress) Finish() {
	if !s.enabled {
		return
	}
	fmt.Fprint(s.output, "\n")
}
