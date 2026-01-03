package server

import (
	"testing"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
)

func TestHandleSendUnitDataInvalidSession(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()

	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	encap := cipclient.ENIPEncapsulation{
		Command:   cipclient.ENIPCommandSendUnitData,
		SessionID: 0x9999,
		Status:    0,
		Options:   0,
		Data:      nil,
	}

	resp := srv.handleSendUnitData(encap, "127.0.0.1:1111")
	decoded, err := cipclient.DecodeENIP(resp)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}
	if decoded.Status != cipclient.ENIPStatusInvalidSessionHandle {
		t.Fatalf("expected invalid session status, got 0x%08X", decoded.Status)
	}
}

func TestHandleSendUnitDataInactiveConnection(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()

	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	sessionID := uint32(0x1234)
	srv.sessionsMu.Lock()
	srv.sessions[sessionID] = &Session{ID: sessionID}
	srv.sessionsMu.Unlock()

	cipPayload := []byte{0x01, 0x02}
	sendData := cipclient.BuildSendUnitDataPayload(0xABCDEF01, cipPayload)
	encap := cipclient.ENIPEncapsulation{
		Command:   cipclient.ENIPCommandSendUnitData,
		Length:    uint16(len(sendData)),
		SessionID: sessionID,
		Status:    0,
		Options:   0,
		Data:      sendData,
	}

	resp := srv.handleSendUnitData(encap, "127.0.0.1:1111")
	decoded, err := cipclient.DecodeENIP(resp)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}
	if decoded.Status != cipclient.ENIPStatusInvalidSessionHandle {
		t.Fatalf("expected invalid session status, got 0x%08X", decoded.Status)
	}
}

func TestHandleSendUnitDataActiveConnection(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()

	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	sessionID := uint32(0x1234)
	connID := uint32(0xABCDEF01)
	srv.sessionsMu.Lock()
	srv.sessions[sessionID] = &Session{ID: sessionID}
	srv.sessionsMu.Unlock()
	srv.trackConnection(connID, sessionID, "127.0.0.1:1111")

	cipPayload := []byte{0x01, 0x02, 0x03}
	sendData := cipclient.BuildSendUnitDataPayload(connID, cipPayload)
	encap := cipclient.ENIPEncapsulation{
		Command:   cipclient.ENIPCommandSendUnitData,
		Length:    uint16(len(sendData)),
		SessionID: sessionID,
		Status:    0,
		Options:   0,
		Data:      sendData,
	}

	resp := srv.handleSendUnitData(encap, "127.0.0.1:1111")
	decoded, err := cipclient.DecodeENIP(resp)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}
	if decoded.Status != cipclient.ENIPStatusSuccess {
		t.Fatalf("expected success status, got 0x%08X", decoded.Status)
	}
	_, payload, err := cipclient.ParseSendUnitDataResponse(decoded.Data)
	if err != nil {
		t.Fatalf("ParseSendUnitDataResponse failed: %v", err)
	}
	if string(payload) != string(cipPayload) {
		t.Fatalf("unexpected payload: %v", payload)
	}
}

func TestConnectionTimeoutExpiry(t *testing.T) {
	cfg := createTestServerConfig()
	cfg.Server.ConnectionTimeoutMs = 1
	logger := createTestLogger()

	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	sessionID := uint32(0x1234)
	connID := uint32(0x1111)
	srv.sessionsMu.Lock()
	srv.sessions[sessionID] = &Session{ID: sessionID}
	srv.sessionsMu.Unlock()
	srv.trackConnection(connID, sessionID, "127.0.0.1:1111")

	srv.connectionsMu.Lock()
	if state, ok := srv.connections[connID]; ok {
		state.LastActivity = time.Now().Add(-5 * time.Millisecond)
	}
	srv.connectionsMu.Unlock()

	if srv.isConnectionActive(connID, sessionID) {
		t.Fatalf("expected connection to be inactive due to timeout")
	}
}

func TestHandleForwardOpenTracksConnections(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()

	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	sessionID := uint32(0x1234)
	encap := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandSendRRData,
		SessionID:     sessionID,
		Status:        0,
		SenderContext: [8]byte{0x01},
		Options:       0,
		Data:          nil,
	}

	resp := srv.handleForwardOpen(encap, []byte{}, "127.0.0.1:1111")
	respEncap, err := cipclient.DecodeENIP(resp)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}
	cipPayload, err := cipclient.ParseSendRRDataResponse(respEncap.Data)
	if err != nil {
		t.Fatalf("ParseSendRRDataResponse failed: %v", err)
	}
	connID, oToT, tToO, err := cipclient.ParseForwardOpenResponse(cipPayload)
	if err != nil {
		t.Fatalf("ParseForwardOpenResponse failed: %v", err)
	}
	if connID == 0 || oToT == 0 || tToO == 0 {
		t.Fatalf("expected non-zero connection IDs")
	}

	srv.connectionsMu.RLock()
	_, okOToT := srv.connections[oToT]
	_, okTToO := srv.connections[tToO]
	srv.connectionsMu.RUnlock()
	if !okOToT || !okTToO {
		t.Fatalf("expected both connections tracked (oToT=%t tToO=%t)", okOToT, okTToO)
	}
}

func TestHandleForwardCloseUntracksConnection(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()

	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	connID := uint32(0x11223344)
	sessionID := uint32(0x1234)
	srv.trackConnection(connID, sessionID, "127.0.0.1:1111")

	cipData := []byte{0x34, 0x44, 0x33, 0x22, 0x11}
	encap := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandSendRRData,
		SessionID:     sessionID,
		Status:        0,
		SenderContext: [8]byte{0x01},
		Options:       0,
		Data:          nil,
	}
	_ = srv.handleForwardClose(encap, cipData)

	srv.connectionsMu.RLock()
	_, ok := srv.connections[connID]
	srv.connectionsMu.RUnlock()
	if ok {
		t.Fatalf("expected connection to be removed after ForwardClose")
	}
}
