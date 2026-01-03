package server

import (
	"testing"

	"github.com/tturner/cipdip/internal/config"
)

func TestFaultPolicyActions(t *testing.T) {
	cfg := createTestServerConfig()
	cfg.Faults = config.ServerFaultConfig{
		Enable: true,
		Latency: config.ServerFaultLatencyConfig{
			BaseDelayMs:  5,
			JitterMs:     0,
			SpikeEveryN:  2,
			SpikeDelayMs: 10,
		},
		Reliability: config.ServerFaultReliabilityConfig{
			DropResponseEveryN:    2,
			DropResponsePct:       0,
			CloseConnectionEveryN: 3,
		},
		TCP: config.ServerFaultTCPConfig{
			ChunkWrites: true,
			ChunkMin:    2,
			ChunkMax:    2,
		},
	}

	srv, err := NewServer(cfg, createTestLogger())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	action1 := srv.nextResponseFaultAction()
	if action1.drop || action1.close {
		t.Fatalf("unexpected action1: drop=%t close=%t", action1.drop, action1.close)
	}
	if action1.delay.Milliseconds() != 5 {
		t.Fatalf("expected delay 5ms, got %dms", action1.delay.Milliseconds())
	}

	action2 := srv.nextResponseFaultAction()
	if !action2.drop {
		t.Fatalf("expected drop on action2")
	}
	if action2.delay.Milliseconds() != 15 {
		t.Fatalf("expected delay 15ms, got %dms", action2.delay.Milliseconds())
	}

	action3 := srv.nextResponseFaultAction()
	if !action3.close {
		t.Fatalf("expected close on action3")
	}
	if !action3.chunked {
		t.Fatalf("expected chunked writes enabled")
	}
}
