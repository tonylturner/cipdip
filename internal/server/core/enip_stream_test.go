package core

import (
	"net"
	"testing"
	"time"

	"github.com/tturner/cipdip/internal/enip"
)

func TestParseENIPStreamSplitAndCoalesce(t *testing.T) {
	logger := createTestLogger()
	frame1 := enip.BuildListIdentity([8]byte{0x01})
	frame2 := enip.BuildRegisterSession([8]byte{0x02})

	// Split frame1 across two reads, frame2 coalesced.
	buf := append([]byte{}, frame1[:10]...)
	frames, rem := parseENIPStream(buf, logger)
	if len(frames) != 0 || len(rem) != len(buf) {
		t.Fatalf("expected no frames yet")
	}

	buf = append(rem, frame1[10:]...)
	buf = append(buf, frame2...)

	frames, rem = parseENIPStream(buf, logger)
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	if len(rem) != 0 {
		t.Fatalf("expected no remainder, got %d bytes", len(rem))
	}
	if frames[0].Command != enip.ENIPCommandListIdentity {
		t.Fatalf("expected ListIdentity first, got 0x%04X", frames[0].Command)
	}
	if frames[1].Command != enip.ENIPCommandRegisterSession {
		t.Fatalf("expected RegisterSession second, got 0x%04X", frames[1].Command)
	}
}

func TestParseSendRRDataCPFStrictness(t *testing.T) {
	cfg := createTestServerConfig()
	cfg.ENIP.CPF.Strict = boolPtr(false)
	cfg.ENIP.CPF.AllowMissingItems = boolPtr(true)
	srv, err := NewServer(cfg, createTestLogger())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	cipPayload := []byte{0x0E, 0x00, 0x20, 0x04, 0x24, 0x01, 0x30, 0x01}
	legacy := append(make([]byte, 6), cipPayload...)
	out, err := srv.parseSendRRData(legacy)
	if err != nil {
		t.Fatalf("parseSendRRData failed: %v", err)
	}
	if len(out) != len(legacy[6:]) {
		t.Fatalf("expected legacy payload passthrough")
	}
}

func TestParseSendUnitDataCPFStrictness(t *testing.T) {
	cfg := createTestServerConfig()
	cfg.ENIP.CPF.Strict = boolPtr(false)
	cfg.ENIP.CPF.AllowMissingItems = boolPtr(true)
	srv, err := NewServer(cfg, createTestLogger())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	payload := []byte{0x78, 0x56, 0x34, 0x12, 0x01, 0x02}
	connID, cipData, err := srv.parseSendUnitData(payload)
	if err != nil {
		t.Fatalf("parseSendUnitData failed: %v", err)
	}
	if connID != 0x12345678 {
		t.Fatalf("unexpected connID: 0x%08X", connID)
	}
	if len(cipData) != 2 {
		t.Fatalf("unexpected cip data length: %d", len(cipData))
	}
}

func TestSessionIdleTimeout(t *testing.T) {
	cfg := createTestServerConfig()
	cfg.ENIP.Session.IdleTimeoutMs = 10
	srv, err := NewServer(cfg, createTestLogger())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	sessionID := uint32(0x1234)
	srv.sessionsMu.Lock()
	srv.sessions[sessionID] = &Session{ID: sessionID, RemoteIP: net.IPv4(127, 0, 0, 1).String(), LastActivity: time.Now().Add(-1 * time.Second)}
	srv.sessionsMu.Unlock()

	if _, ok := srv.requireSession(sessionID, "127.0.0.1:1234"); ok {
		t.Fatalf("expected session to expire")
	}
}

func boolPtr(value bool) *bool {
	return &value
}
