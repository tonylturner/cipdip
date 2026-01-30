package modbus

import (
	"testing"
	"time"
)

func TestPipelineSendAndComplete(t *testing.T) {
	pt := NewPipelineTracker(10, 5*time.Second)

	if err := pt.Send(0x0001, FcReadCoils); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if pt.Outstanding() != 1 {
		t.Errorf("Outstanding = %d, want 1", pt.Outstanding())
	}

	req, rtt, err := pt.Complete(0x0001)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if req.TransactionID != 0x0001 {
		t.Errorf("TransactionID = 0x%04X, want 0x0001", req.TransactionID)
	}
	if req.Function != FcReadCoils {
		t.Errorf("Function = 0x%02X, want 0x%02X", req.Function, FcReadCoils)
	}
	if rtt < 0 {
		t.Errorf("RTT = %v, want >= 0", rtt)
	}
	if pt.Outstanding() != 0 {
		t.Errorf("Outstanding after complete = %d, want 0", pt.Outstanding())
	}
}

func TestPipelineFullRejectsNew(t *testing.T) {
	pt := NewPipelineTracker(2, 5*time.Second)

	if err := pt.Send(1, FcReadCoils); err != nil {
		t.Fatal(err)
	}
	if err := pt.Send(2, FcReadCoils); err != nil {
		t.Fatal(err)
	}
	// Pipeline full
	err := pt.Send(3, FcReadCoils)
	if err == nil {
		t.Fatal("expected error for full pipeline")
	}
}

func TestPipelineCompleteUnknown(t *testing.T) {
	pt := NewPipelineTracker(10, 5*time.Second)

	_, _, err := pt.Complete(0xFFFF)
	if err == nil {
		t.Fatal("expected error for unknown transaction ID")
	}
}

func TestPipelineTimeout(t *testing.T) {
	pt := NewPipelineTracker(10, 10*time.Millisecond)

	if err := pt.Send(1, FcReadCoils); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)

	removed := pt.Cleanup()
	if removed != 1 {
		t.Errorf("Cleanup removed = %d, want 1", removed)
	}
	if pt.Outstanding() != 0 {
		t.Errorf("Outstanding after cleanup = %d, want 0", pt.Outstanding())
	}

	stats := pt.Stats()
	if stats.TotalTimedOut != 1 {
		t.Errorf("TotalTimedOut = %d, want 1", stats.TotalTimedOut)
	}
}

func TestPipelineTimeoutOnSend(t *testing.T) {
	// Timeout cleanup happens automatically when Send is called.
	pt := NewPipelineTracker(1, 10*time.Millisecond)

	if err := pt.Send(1, FcReadCoils); err != nil {
		t.Fatal(err)
	}
	// Pipeline is full
	if err := pt.Send(2, FcReadCoils); err == nil {
		t.Fatal("expected full pipeline error")
	}

	// Wait for timeout
	time.Sleep(20 * time.Millisecond)

	// Send should now succeed (timeout cleans up stale entry)
	if err := pt.Send(2, FcReadCoils); err != nil {
		t.Fatalf("Send after timeout: %v", err)
	}
}

func TestPipelineStats(t *testing.T) {
	pt := NewPipelineTracker(10, 5*time.Second)

	for i := uint16(1); i <= 5; i++ {
		if err := pt.Send(i, FcReadHoldingRegisters); err != nil {
			t.Fatal(err)
		}
	}
	for i := uint16(1); i <= 3; i++ {
		if _, _, err := pt.Complete(i); err != nil {
			t.Fatal(err)
		}
	}

	stats := pt.Stats()
	if stats.Outstanding != 2 {
		t.Errorf("Outstanding = %d, want 2", stats.Outstanding)
	}
	if stats.TotalSent != 5 {
		t.Errorf("TotalSent = %d, want 5", stats.TotalSent)
	}
	if stats.TotalCompleted != 3 {
		t.Errorf("TotalCompleted = %d, want 3", stats.TotalCompleted)
	}
	if stats.MaxOutstanding != 10 {
		t.Errorf("MaxOutstanding = %d, want 10", stats.MaxOutstanding)
	}
}

func TestPipelineUnlimited(t *testing.T) {
	pt := NewPipelineTracker(0, 0) // unlimited

	for i := uint16(0); i < 100; i++ {
		if err := pt.Send(i, FcReadCoils); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	if pt.Outstanding() != 100 {
		t.Errorf("Outstanding = %d, want 100", pt.Outstanding())
	}
}

func TestPipelineReset(t *testing.T) {
	pt := NewPipelineTracker(10, 5*time.Second)

	for i := uint16(1); i <= 5; i++ {
		_ = pt.Send(i, FcReadCoils)
	}
	pt.Reset()

	if pt.Outstanding() != 0 {
		t.Errorf("Outstanding after reset = %d, want 0", pt.Outstanding())
	}
	stats := pt.Stats()
	if stats.TotalSent != 0 {
		t.Errorf("TotalSent after reset = %d, want 0", stats.TotalSent)
	}
}

func TestPipelineNoTimeout(t *testing.T) {
	pt := NewPipelineTracker(10, 0) // no timeout

	if err := pt.Send(1, FcReadCoils); err != nil {
		t.Fatal(err)
	}
	removed := pt.Cleanup()
	if removed != 0 {
		t.Errorf("Cleanup removed = %d, want 0 (no timeout)", removed)
	}
}
