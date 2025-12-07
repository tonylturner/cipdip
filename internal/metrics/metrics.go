package metrics

// Metrics collection for CIP operations

import (
	"sync"
	"time"
)

// TargetType represents the type of target device
type TargetType string

const (
	TargetTypeClick          TargetType = "click"
	TargetTypeEmulatorAdapter TargetType = "emulator_adapter"
	TargetTypeEmulatorLogix  TargetType = "emulator_logix"
	TargetTypePCAPReplay     TargetType = "pcap_replay"
)

// OperationType represents the type of operation
type OperationType string

const (
	OperationRead          OperationType = "READ"
	OperationWrite         OperationType = "WRITE"
	OperationCustom        OperationType = "CUSTOM"
	OperationOTToTSend     OperationType = "O_TO_T_SEND"
	OperationTToORecv      OperationType = "T_TO_O_RECV"
	OperationForwardOpen   OperationType = "FORWARD_OPEN"
	OperationForwardClose  OperationType = "FORWARD_CLOSE"
)

// Metric represents a single operation metric
type Metric struct {
	Timestamp   time.Time
	Scenario    string
	TargetType  TargetType
	Operation   OperationType
	TargetName  string
	ServiceCode string
	Success     bool
	RTTMs       float64
	Status      uint8
	Error       string
}

// Sink collects and aggregates metrics
type Sink struct {
	mu       sync.RWMutex
	metrics  []Metric
	summary  *Summary
}

// Summary contains aggregated statistics
type Summary struct {
	TotalOperations    int
	SuccessfulOps      int
	FailedOps          int
	TimeoutCount       int
	ConnectionFailures int
	MinRTT             float64
	MaxRTT             float64
	AvgRTT             float64
	RTTByOperation     map[OperationType]*OperationStats
	RTTByScenario      map[string]*ScenarioStats
}

// OperationStats contains statistics for a specific operation type
type OperationStats struct {
	Count   int
	Success int
	Failed  int
	MinRTT  float64
	MaxRTT  float64
	AvgRTT  float64
	SumRTT  float64
}

// ScenarioStats contains statistics for a specific scenario
type ScenarioStats struct {
	Count   int
	Success int
	Failed  int
	MinRTT  float64
	MaxRTT  float64
	AvgRTT  float64
	SumRTT  float64
}

// NewSink creates a new metrics sink
func NewSink() *Sink {
	return &Sink{
		metrics: make([]Metric, 0),
		summary: &Summary{
			RTTByOperation: make(map[OperationType]*OperationStats),
			RTTByScenario:  make(map[string]*ScenarioStats),
		},
	}
}

// Record records a new metric
func (s *Sink) Record(m Metric) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.metrics = append(s.metrics, m)
	s.updateSummary(m)
}

// GetMetrics returns a copy of all recorded metrics
func (s *Sink) GetMetrics() []Metric {
	s.mu.RLock()
	defer s.mu.RUnlock()

	metrics := make([]Metric, len(s.metrics))
	copy(metrics, s.metrics)
	return metrics
}

// GetSummary returns the aggregated summary
func (s *Sink) GetSummary() *Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Create a deep copy of the summary
	summary := &Summary{
		TotalOperations:    s.summary.TotalOperations,
		SuccessfulOps:      s.summary.SuccessfulOps,
		FailedOps:          s.summary.FailedOps,
		TimeoutCount:       s.summary.TimeoutCount,
		ConnectionFailures: s.summary.ConnectionFailures,
		MinRTT:             s.summary.MinRTT,
		MaxRTT:             s.summary.MaxRTT,
		AvgRTT:             s.summary.AvgRTT,
		RTTByOperation:     make(map[OperationType]*OperationStats),
		RTTByScenario:      make(map[string]*ScenarioStats),
	}

	// Copy operation stats
	for op, stats := range s.summary.RTTByOperation {
		summary.RTTByOperation[op] = &OperationStats{
			Count:   stats.Count,
			Success: stats.Success,
			Failed:  stats.Failed,
			MinRTT:  stats.MinRTT,
			MaxRTT:  stats.MaxRTT,
			AvgRTT:  stats.AvgRTT,
			SumRTT:  stats.SumRTT,
		}
	}

	// Copy scenario stats
	for scenario, stats := range s.summary.RTTByScenario {
		summary.RTTByScenario[scenario] = &ScenarioStats{
			Count:   stats.Count,
			Success: stats.Success,
			Failed:  stats.Failed,
			MinRTT:  stats.MinRTT,
			MaxRTT:  stats.MaxRTT,
			AvgRTT:  stats.AvgRTT,
			SumRTT:  stats.SumRTT,
		}
	}

	return summary
}

// updateSummary updates the summary statistics with a new metric
func (s *Sink) updateSummary(m Metric) {
	s.summary.TotalOperations++

	if m.Success {
		s.summary.SuccessfulOps++
	} else {
		s.summary.FailedOps++
		if m.Error != "" {
			if m.Error == "timeout" || contains(m.Error, "timeout") {
				s.summary.TimeoutCount++
			}
			if contains(m.Error, "connection") || contains(m.Error, "connect") {
				s.summary.ConnectionFailures++
			}
		}
	}

	// Update RTT statistics
	if m.Success && m.RTTMs > 0 {
		if s.summary.MinRTT == 0 || m.RTTMs < s.summary.MinRTT {
			s.summary.MinRTT = m.RTTMs
		}
		if m.RTTMs > s.summary.MaxRTT {
			s.summary.MaxRTT = m.RTTMs
		}

		// Calculate average RTT
		totalRTT := s.summary.AvgRTT * float64(s.summary.SuccessfulOps-1)
		totalRTT += m.RTTMs
		s.summary.AvgRTT = totalRTT / float64(s.summary.SuccessfulOps)
	}

	// Update operation-specific stats
	opStats, exists := s.summary.RTTByOperation[m.Operation]
	if !exists {
		opStats = &OperationStats{}
		s.summary.RTTByOperation[m.Operation] = opStats
	}
	opStats.Count++
	if m.Success {
		opStats.Success++
		if m.RTTMs > 0 {
			if opStats.MinRTT == 0 || m.RTTMs < opStats.MinRTT {
				opStats.MinRTT = m.RTTMs
			}
			if m.RTTMs > opStats.MaxRTT {
				opStats.MaxRTT = m.RTTMs
			}
			opStats.SumRTT += m.RTTMs
			opStats.AvgRTT = opStats.SumRTT / float64(opStats.Success)
		}
	} else {
		opStats.Failed++
	}

	// Update scenario-specific stats
	scenarioStats, exists := s.summary.RTTByScenario[m.Scenario]
	if !exists {
		scenarioStats = &ScenarioStats{}
		s.summary.RTTByScenario[m.Scenario] = scenarioStats
	}
	scenarioStats.Count++
	if m.Success {
		scenarioStats.Success++
		if m.RTTMs > 0 {
			if scenarioStats.MinRTT == 0 || m.RTTMs < scenarioStats.MinRTT {
				scenarioStats.MinRTT = m.RTTMs
			}
			if m.RTTMs > scenarioStats.MaxRTT {
				scenarioStats.MaxRTT = m.RTTMs
			}
			scenarioStats.SumRTT += m.RTTMs
			scenarioStats.AvgRTT = scenarioStats.SumRTT / float64(scenarioStats.Success)
		}
	} else {
		scenarioStats.Failed++
	}
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || 
		(len(s) > len(substr) && 
			(s[:len(substr)] == substr || 
			 s[len(s)-len(substr):] == substr ||
			 containsMiddle(s, substr))))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
