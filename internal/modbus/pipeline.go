package modbus

// Pipeline tracker for Modbus TCP transaction pipelining.
//
// Modbus TCP allows multiple outstanding requests keyed by TransactionID.
// PipelineTracker correlates requests with responses and enforces limits.

import (
	"fmt"
	"sync"
	"time"
)

// PipelineTracker manages outstanding Modbus TCP transactions.
type PipelineTracker struct {
	mu             sync.Mutex
	pending        map[uint16]*PendingRequest
	maxOutstanding int
	timeout        time.Duration

	// Metrics
	totalSent      int64
	totalCompleted int64
	totalTimedOut  int64
	totalLatencyUs int64 // cumulative microseconds for completed requests
}

// PendingRequest represents an in-flight Modbus request.
type PendingRequest struct {
	TransactionID uint16
	Function      FunctionCode
	SentAt        time.Time
}

// PipelineStats contains pipeline performance metrics.
type PipelineStats struct {
	Outstanding    int
	MaxOutstanding int
	TotalSent      int64
	TotalCompleted int64
	TotalTimedOut  int64
	AvgLatencyUs   float64
}

// NewPipelineTracker creates a tracker with the given limits.
// maxOutstanding is the maximum number of concurrent pending requests (0 = unlimited).
// timeout is the expiry duration for stale transactions (0 = no timeout).
func NewPipelineTracker(maxOutstanding int, timeout time.Duration) *PipelineTracker {
	return &PipelineTracker{
		pending:        make(map[uint16]*PendingRequest),
		maxOutstanding: maxOutstanding,
		timeout:        timeout,
	}
}

// Send registers a new outgoing request. Returns an error if the pipeline
// is full (maxOutstanding exceeded).
func (pt *PipelineTracker) Send(txID uint16, fc FunctionCode) error {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	// Clean up timed-out entries first.
	pt.cleanupLocked()

	if pt.maxOutstanding > 0 && len(pt.pending) >= pt.maxOutstanding {
		return fmt.Errorf("pipeline full: %d/%d outstanding", len(pt.pending), pt.maxOutstanding)
	}

	pt.pending[txID] = &PendingRequest{
		TransactionID: txID,
		Function:      fc,
		SentAt:        time.Now(),
	}
	pt.totalSent++
	return nil
}

// Complete marks a transaction as completed and returns the original request
// info plus the round-trip time. Returns an error if the transaction ID is
// not found (possibly already timed out or never sent).
func (pt *PipelineTracker) Complete(txID uint16) (*PendingRequest, time.Duration, error) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	req, ok := pt.pending[txID]
	if !ok {
		return nil, 0, fmt.Errorf("unknown transaction ID: 0x%04X", txID)
	}
	delete(pt.pending, txID)

	rtt := time.Since(req.SentAt)
	pt.totalCompleted++
	pt.totalLatencyUs += rtt.Microseconds()
	return req, rtt, nil
}

// Outstanding returns the number of currently pending transactions.
func (pt *PipelineTracker) Outstanding() int {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	return len(pt.pending)
}

// Stats returns a snapshot of pipeline performance metrics.
func (pt *PipelineTracker) Stats() PipelineStats {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	var avgUs float64
	if pt.totalCompleted > 0 {
		avgUs = float64(pt.totalLatencyUs) / float64(pt.totalCompleted)
	}
	return PipelineStats{
		Outstanding:    len(pt.pending),
		MaxOutstanding: pt.maxOutstanding,
		TotalSent:      pt.totalSent,
		TotalCompleted: pt.totalCompleted,
		TotalTimedOut:  pt.totalTimedOut,
		AvgLatencyUs:   avgUs,
	}
}

// Cleanup removes timed-out transactions. Safe to call periodically.
func (pt *PipelineTracker) Cleanup() int {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	return pt.cleanupLocked()
}

// cleanupLocked removes timed-out entries while holding the lock.
func (pt *PipelineTracker) cleanupLocked() int {
	if pt.timeout <= 0 {
		return 0
	}
	cutoff := time.Now().Add(-pt.timeout)
	removed := 0
	for txID, req := range pt.pending {
		if req.SentAt.Before(cutoff) {
			delete(pt.pending, txID)
			pt.totalTimedOut++
			removed++
		}
	}
	return removed
}

// Reset clears all pending transactions and resets metrics.
func (pt *PipelineTracker) Reset() {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.pending = make(map[uint16]*PendingRequest)
	pt.totalSent = 0
	pt.totalCompleted = 0
	pt.totalTimedOut = 0
	pt.totalLatencyUs = 0
}
