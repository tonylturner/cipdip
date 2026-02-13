package progress

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestNewProgressBar(t *testing.T) {
	pb := NewProgressBar(100, "test")
	if pb.total != 100 {
		t.Errorf("total = %d, want 100", pb.total)
	}
	if pb.current != 0 {
		t.Errorf("current = %d, want 0", pb.current)
	}
	if !pb.enabled {
		t.Error("should be enabled by default")
	}
	if pb.description != "test" {
		t.Errorf("description = %q, want %q", pb.description, "test")
	}
}

func TestProgressBar_EnableDisable(t *testing.T) {
	pb := NewProgressBar(100, "test")
	var buf bytes.Buffer
	pb.output = &buf

	pb.Disable()
	if pb.enabled {
		t.Error("should be disabled")
	}

	// Disabled bar produces no output
	pb.lastUpdate = time.Time{} // force render
	pb.Set(50)
	if buf.Len() > 0 {
		t.Error("disabled bar should not produce output")
	}

	pb.Enable()
	if !pb.enabled {
		t.Error("should be enabled")
	}
}

func TestProgressBar_Update(t *testing.T) {
	pb := NewProgressBar(10, "")
	var buf bytes.Buffer
	pb.output = &buf
	pb.lastUpdate = time.Time{} // force render

	pb.Update(3)
	if pb.current != 3 {
		t.Errorf("current = %d, want 3", pb.current)
	}

	pb.lastUpdate = time.Time{} // force render
	pb.Update(2)
	if pb.current != 5 {
		t.Errorf("current = %d, want 5", pb.current)
	}
}

func TestProgressBar_Set(t *testing.T) {
	pb := NewProgressBar(10, "")
	var buf bytes.Buffer
	pb.output = &buf
	pb.lastUpdate = time.Time{}

	pb.Set(7)
	if pb.current != 7 {
		t.Errorf("current = %d, want 7", pb.current)
	}
}

func TestProgressBar_Increment(t *testing.T) {
	pb := NewProgressBar(10, "")
	var buf bytes.Buffer
	pb.output = &buf
	pb.lastUpdate = time.Time{}

	pb.Increment()
	if pb.current != 1 {
		t.Errorf("current = %d, want 1", pb.current)
	}
}

func TestProgressBar_Render(t *testing.T) {
	pb := NewProgressBar(100, "Loading")
	var buf bytes.Buffer
	pb.output = &buf
	pb.lastUpdate = time.Time{} // force render

	pb.Set(50)
	output := buf.String()

	if !strings.Contains(output, "Loading") {
		t.Errorf("output should contain description, got: %q", output)
	}
	if !strings.Contains(output, "50/100") {
		t.Errorf("output should contain progress count, got: %q", output)
	}
	if !strings.Contains(output, "50.0%") {
		t.Errorf("output should contain percentage, got: %q", output)
	}
	if !strings.Contains(output, "Elapsed:") {
		t.Errorf("output should contain elapsed time, got: %q", output)
	}
}

func TestProgressBar_RenderNoDescription(t *testing.T) {
	pb := NewProgressBar(100, "")
	var buf bytes.Buffer
	pb.output = &buf
	pb.lastUpdate = time.Time{}

	pb.Set(25)
	output := buf.String()

	if !strings.Contains(output, "[") {
		t.Errorf("output should contain bar brackets, got: %q", output)
	}
	if !strings.Contains(output, "25/100") {
		t.Errorf("output should contain progress count, got: %q", output)
	}
}

func TestProgressBar_RenderZeroTotal(t *testing.T) {
	pb := NewProgressBar(0, "")
	var buf bytes.Buffer
	pb.output = &buf
	pb.lastUpdate = time.Time{}

	pb.Set(5)
	output := buf.String()
	if !strings.Contains(output, "0.0%") {
		t.Errorf("zero total should show 0%%, got: %q", output)
	}
}

func TestProgressBar_RenderShowsETA(t *testing.T) {
	pb := NewProgressBar(100, "")
	var buf bytes.Buffer
	pb.output = &buf

	// Simulate some time passing
	pb.startTime = time.Now().Add(-5 * time.Second)
	pb.lastUpdate = time.Time{}

	pb.Set(50)
	output := buf.String()

	if !strings.Contains(output, "ETA:") {
		t.Errorf("should show ETA when partially complete, got: %q", output)
	}
}

func TestProgressBar_RenderNoETAWhenComplete(t *testing.T) {
	pb := NewProgressBar(100, "")
	var buf bytes.Buffer
	pb.output = &buf

	pb.startTime = time.Now().Add(-5 * time.Second)
	pb.lastUpdate = time.Time{}

	pb.Set(100)
	output := buf.String()

	if strings.Contains(output, "ETA:") {
		t.Errorf("should not show ETA when complete, got: %q", output)
	}
}

func TestProgressBar_Throttle(t *testing.T) {
	pb := NewProgressBar(100, "")
	var buf bytes.Buffer
	pb.output = &buf

	// First render — will produce output (lastUpdate is Now from constructor, but set it to past)
	pb.lastUpdate = time.Time{}
	pb.Set(10)
	first := buf.Len()
	if first == 0 {
		t.Error("first render should produce output")
	}

	// Immediate second render — throttled (< 100ms since last)
	buf.Reset()
	pb.Set(20)
	if buf.Len() > 0 {
		t.Error("throttled render should produce no output")
	}
}

func TestProgressBar_Finish(t *testing.T) {
	pb := NewProgressBar(100, "Done")
	var buf bytes.Buffer
	pb.output = &buf

	pb.Finish()

	if pb.current != pb.total {
		t.Errorf("Finish should set current = total, got %d", pb.current)
	}
	output := buf.String()
	if !strings.HasSuffix(output, "\n") {
		t.Error("Finish should end with newline")
	}
}

func TestProgressBar_FinishDisabled(t *testing.T) {
	pb := NewProgressBar(100, "")
	var buf bytes.Buffer
	pb.output = &buf

	pb.Disable()
	pb.Finish()

	if buf.Len() > 0 {
		t.Error("disabled Finish should produce no output")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{500 * time.Millisecond, "500ms"},
		{0, "0ms"},
		{1500 * time.Millisecond, "1.5s"},
		{30 * time.Second, "30.0s"},
		{90 * time.Second, "1m30s"},
		{5*time.Minute + 15*time.Second, "5m15s"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatDuration(tt.d)
			if got != tt.want {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestNewSimpleProgress(t *testing.T) {
	sp := NewSimpleProgress("Processing", 500*time.Millisecond)
	if !sp.enabled {
		t.Error("should be enabled by default")
	}
	if sp.description != "Processing" {
		t.Errorf("description = %q, want %q", sp.description, "Processing")
	}
	if sp.interval != 500*time.Millisecond {
		t.Errorf("interval = %v, want 500ms", sp.interval)
	}
}

func TestSimpleProgress_Update(t *testing.T) {
	sp := NewSimpleProgress("Test", 0)
	var buf bytes.Buffer
	sp.output = &buf
	sp.lastUpdate = time.Time{} // force render

	sp.Update(42, "working")
	output := buf.String()

	if !strings.Contains(output, "Test") {
		t.Errorf("should contain description, got: %q", output)
	}
	if !strings.Contains(output, "42 operations") {
		t.Errorf("should contain count, got: %q", output)
	}
	if !strings.Contains(output, "working") {
		t.Errorf("should contain message, got: %q", output)
	}
}

func TestSimpleProgress_UpdateNoDescription(t *testing.T) {
	sp := NewSimpleProgress("", 0)
	var buf bytes.Buffer
	sp.output = &buf
	sp.lastUpdate = time.Time{}

	sp.Update(10, "")
	output := buf.String()

	if !strings.Contains(output, "10 operations") {
		t.Errorf("should contain count, got: %q", output)
	}
	if strings.Contains(output, "|") {
		t.Errorf("empty message should not have separator, got: %q", output)
	}
}

func TestSimpleProgress_Disabled(t *testing.T) {
	sp := NewSimpleProgress("Test", 0)
	var buf bytes.Buffer
	sp.output = &buf
	sp.enabled = false
	sp.lastUpdate = time.Time{}

	sp.Update(5, "msg")
	if buf.Len() > 0 {
		t.Error("disabled progress should produce no output")
	}
}

func TestSimpleProgress_Throttle(t *testing.T) {
	sp := NewSimpleProgress("Test", time.Hour)
	var buf bytes.Buffer
	sp.output = &buf
	// lastUpdate is Now, so interval (1 hour) won't have elapsed

	sp.Update(1, "")
	if buf.Len() > 0 {
		t.Error("throttled update should produce no output")
	}
}

func TestSimpleProgress_Finish(t *testing.T) {
	sp := NewSimpleProgress("Done", 0)
	var buf bytes.Buffer
	sp.output = &buf

	sp.Finish()
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Error("Finish should end with newline")
	}
}

func TestSimpleProgress_FinishDisabled(t *testing.T) {
	sp := NewSimpleProgress("Done", 0)
	var buf bytes.Buffer
	sp.output = &buf
	sp.enabled = false

	sp.Finish()
	if buf.Len() > 0 {
		t.Error("disabled Finish should produce no output")
	}
}
