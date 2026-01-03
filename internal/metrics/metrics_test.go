package metrics

import "testing"

func TestMetricsSummaryAndRelabel(t *testing.T) {
	sink := NewSink()
	sink.Record(Metric{
		Scenario:  "baseline",
		Operation: OperationRead,
		Success:   true,
		RTTMs:     5,
		JitterMs:  1,
	})
	sink.Record(Metric{
		Scenario:  "baseline",
		Operation: OperationRead,
		Success:   true,
		RTTMs:     10,
		JitterMs:  2,
	})
	sink.Record(Metric{
		Scenario:        "baseline",
		Operation:       OperationWrite,
		Success:         false,
		Error:           "timeout",
		Outcome:         "timeout",
		ExpectedOutcome: "success",
	})

	summary := sink.GetSummary()
	if summary.TotalOperations != 3 {
		t.Fatalf("expected total ops 3, got %d", summary.TotalOperations)
	}
	if summary.SuccessfulOps != 2 || summary.FailedOps != 1 {
		t.Fatalf("unexpected success/fail counts: %d/%d", summary.SuccessfulOps, summary.FailedOps)
	}
	if summary.TimeoutCount != 1 {
		t.Fatalf("expected timeout count 1, got %d", summary.TimeoutCount)
	}
	if summary.Misclassifications != 1 {
		t.Fatalf("expected misclassification count 1, got %d", summary.Misclassifications)
	}
	if summary.P50RTT == 0 || summary.P90RTT == 0 {
		t.Fatalf("expected RTT percentiles to be set")
	}
	if summary.P50Jitter == 0 || summary.P90Jitter == 0 {
		t.Fatalf("expected jitter percentiles to be set")
	}

	sink.RelabelScenario("replayed")
	metrics := sink.GetMetrics()
	for _, m := range metrics {
		if m.Scenario != "replayed" {
			t.Fatalf("expected relabeled scenario, got %s", m.Scenario)
		}
	}
}
