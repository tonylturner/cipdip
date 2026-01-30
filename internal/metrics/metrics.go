package metrics

// Metrics collection for CIP operations

import (
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// TargetType represents the type of target device
type TargetType string

const (
	TargetTypeClick           TargetType = "click"
	TargetTypeEmulatorAdapter TargetType = "emulator_adapter"
	TargetTypeEmulatorLogix   TargetType = "emulator_logix"
	TargetTypePCAPReplay      TargetType = "pcap_replay"
)

// OperationType represents the type of operation
type OperationType string

const (
	OperationRead         OperationType = "READ"
	OperationWrite        OperationType = "WRITE"
	OperationCustom       OperationType = "CUSTOM"
	OperationOTToTSend    OperationType = "O_TO_T_SEND"
	OperationTToORecv     OperationType = "T_TO_O_RECV"
	OperationForwardOpen  OperationType = "FORWARD_OPEN"
	OperationForwardClose OperationType = "FORWARD_CLOSE"
)

// Metric represents a single operation metric
type Metric struct {
	Timestamp       time.Time
	Scenario        string
	TargetType      TargetType
	Operation       OperationType
	TargetName      string
	ServiceCode     string
	Success         bool
	RTTMs           float64
	JitterMs        float64
	Status          uint8
	Error           string
	Outcome         string
	ExpectedOutcome string
}

// Sink collects and aggregates metrics
type Sink struct {
	mu      sync.RWMutex
	metrics []Metric
	summary *Summary
}

func newSummary() *Summary {
	return &Summary{
		RTTBuckets:     make(map[string]int),
		JitterBuckets:  make(map[string]int),
		RTTByOperation: make(map[OperationType]*OperationStats),
		RTTByScenario:  make(map[string]*ScenarioStats),
	}
}

// Summary contains aggregated statistics
type Summary struct {
	TotalOperations    int
	SuccessfulOps      int
	FailedOps          int
	TimeoutCount       int
	ConnectionFailures int
	Misclassifications int
	MinRTT             float64
	MaxRTT             float64
	AvgRTT             float64
	P50RTT             float64
	P90RTT             float64
	P95RTT             float64
	P99RTT             float64
	MinJitter          float64
	MaxJitter          float64
	AvgJitter          float64
	P50Jitter          float64
	P90Jitter          float64
	P95Jitter          float64
	P99Jitter          float64
	jitterCount        int
	RTTBuckets         map[string]int
	JitterBuckets      map[string]int
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
		summary: newSummary(),
	}
}

// Record records a new metric
func (s *Sink) Record(m Metric) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.metrics = append(s.metrics, m)
	s.updateSummary(m)
}

// RelabelScenario overwrites scenario names on all metrics and rebuilds summary stats.
func (s *Sink) RelabelScenario(label string) {
	if label == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.metrics {
		s.metrics[i].Scenario = label
	}

	s.summary = newSummary()
	for _, m := range s.metrics {
		s.updateSummary(m)
	}
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
		Misclassifications: s.summary.Misclassifications,
		MinRTT:             s.summary.MinRTT,
		MaxRTT:             s.summary.MaxRTT,
		AvgRTT:             s.summary.AvgRTT,
		P50RTT:             s.summary.P50RTT,
		P90RTT:             s.summary.P90RTT,
		P95RTT:             s.summary.P95RTT,
		P99RTT:             s.summary.P99RTT,
		MinJitter:          s.summary.MinJitter,
		MaxJitter:          s.summary.MaxJitter,
		AvgJitter:          s.summary.AvgJitter,
		P50Jitter:          s.summary.P50Jitter,
		P90Jitter:          s.summary.P90Jitter,
		P95Jitter:          s.summary.P95Jitter,
		P99Jitter:          s.summary.P99Jitter,
		RTTBuckets:         make(map[string]int),
		JitterBuckets:      make(map[string]int),
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

	rttPercentiles, jitterPercentiles, rttBuckets, jitterBuckets := summarizeDistributions(s.metrics)
	summary.P50RTT = rttPercentiles[0]
	summary.P90RTT = rttPercentiles[1]
	summary.P95RTT = rttPercentiles[2]
	summary.P99RTT = rttPercentiles[3]
	summary.P50Jitter = jitterPercentiles[0]
	summary.P90Jitter = jitterPercentiles[1]
	summary.P95Jitter = jitterPercentiles[2]
	summary.P99Jitter = jitterPercentiles[3]
	for k, v := range rttBuckets {
		summary.RTTBuckets[k] = v
	}
	for k, v := range jitterBuckets {
		summary.JitterBuckets[k] = v
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
			if m.Error == "timeout" || strings.Contains(m.Error, "timeout") {
				s.summary.TimeoutCount++
			}
			if strings.Contains(m.Error, "connection") || strings.Contains(m.Error, "connect") {
				s.summary.ConnectionFailures++
			}
		}
	}

	if m.ExpectedOutcome != "" && m.Outcome != "" && m.ExpectedOutcome != "any" && m.ExpectedOutcome != m.Outcome {
		s.summary.Misclassifications++
	}

	if m.JitterMs > 0 {
		if s.summary.MinJitter == 0 || m.JitterMs < s.summary.MinJitter {
			s.summary.MinJitter = m.JitterMs
		}
		if m.JitterMs > s.summary.MaxJitter {
			s.summary.MaxJitter = m.JitterMs
		}
		s.summary.jitterCount++
		totalJitter := s.summary.AvgJitter * float64(s.summary.jitterCount-1)
		totalJitter += m.JitterMs
		s.summary.AvgJitter = totalJitter / float64(s.summary.jitterCount)
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

func summarizeDistributions(metrics []Metric) ([4]float64, [4]float64, map[string]int, map[string]int) {
	rtts := make([]float64, 0, len(metrics))
	jitters := make([]float64, 0, len(metrics))
	rttBuckets := make(map[string]int)
	jitterBuckets := make(map[string]int)

	for _, m := range metrics {
		if m.Success && m.RTTMs > 0 {
			rtts = append(rtts, m.RTTMs)
			incrementBucket(rttBuckets, m.RTTMs)
		}
		if m.JitterMs > 0 {
			jitters = append(jitters, m.JitterMs)
			incrementBucket(jitterBuckets, m.JitterMs)
		}
	}

	return computePercentiles(rtts), computePercentiles(jitters), rttBuckets, jitterBuckets
}

func incrementBucket(buckets map[string]int, value float64) {
	switch {
	case value < 1:
		buckets["lt_1ms"]++
	case value < 5:
		buckets["1_5ms"]++
	case value < 10:
		buckets["5_10ms"]++
	case value < 50:
		buckets["10_50ms"]++
	case value < 100:
		buckets["50_100ms"]++
	case value < 500:
		buckets["100_500ms"]++
	default:
		buckets["gt_500ms"]++
	}
}

func computePercentiles(values []float64) [4]float64 {
	var result [4]float64
	if len(values) == 0 {
		return result
	}
	sort.Float64s(values)
	result[0] = percentile(values, 0.50)
	result[1] = percentile(values, 0.90)
	result[2] = percentile(values, 0.95)
	result[3] = percentile(values, 0.99)
	return result
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p*float64(len(sorted)))) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

