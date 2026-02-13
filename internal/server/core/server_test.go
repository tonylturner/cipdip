package core

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
	"github.com/tonylturner/cipdip/internal/config"
	"github.com/tonylturner/cipdip/internal/enip"
	"github.com/tonylturner/cipdip/internal/logging"
)

// createTestServerConfig creates a minimal test server config
func createTestServerConfig() *config.ServerConfig {
	return &config.ServerConfig{
		Server: config.ServerConfigSection{
			Name:        "Test Server",
			Personality: "adapter",
			ListenIP:    "127.0.0.1",
			TCPPort:     0, // Use 0 to get random port
			UDPIOPort:   2222,
			EnableUDPIO: false,
		},
		AdapterAssemblies: []config.AdapterAssemblyConfig{
			{
				Name:          "TestAssembly",
				Class:         0x04,
				Instance:      0x65,
				Attribute:     0x03,
				SizeBytes:     16,
				Writable:      true,
				UpdatePattern: "counter",
			},
		},
	}
}

// createTestLogger creates a test logger
func createTestLogger() *logging.Logger {
	logger, _ := logging.NewLogger(logging.LogLevelError, "")
	return logger
}

// TestNewServer tests server creation
func TestNewServer(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()

	server, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if server == nil {
		t.Fatal("NewServer returned nil")
	}

	if server.config != cfg {
		t.Error("Server config not set correctly")
	}

	if server.logger != logger {
		t.Error("Server logger not set correctly")
	}

	if server.handlers == nil {
		t.Error("Server handler registry not set")
	} else {
		req := protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeSingle,
			Path: protocol.CIPPath{
				Class:     spec.CIPClassAssembly,
				Instance:  0x65,
				Attribute: 0x03,
			},
		}
		_, handled, _ := server.handlers.Handle(context.Background(), req)
		if !handled {
			t.Error("Expected assembly handler to be registered")
		}
	}

	if len(server.sessions) != 0 {
		t.Error("Sessions map should be empty initially")
	}

	if server.nextSessionID != 1 {
		t.Errorf("Expected nextSessionID to be 1, got %d", server.nextSessionID)
	}
}

// TestNewServerInvalidPersonality tests server creation with invalid personality
func TestNewServerInvalidPersonality(t *testing.T) {
	cfg := createTestServerConfig()
	cfg.Server.Personality = "invalid"
	logger := createTestLogger()

	server, err := NewServer(cfg, logger)
	if err == nil {
		t.Fatal("NewServer should fail with invalid personality")
	}

	if server != nil {
		t.Error("NewServer should return nil on error")
	}
}

// TestServerStartStop tests server start and stop
func TestServerStartStop(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()

	server, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Start server
	err = server.Start()
	if err != nil {
		t.Fatalf("Server.Start failed: %v", err)
	}

	// Verify TCP listener is created
	if server.tcpListener == nil {
		t.Error("TCP listener should be created")
	}

	// Get the actual port
	addr := server.tcpListener.Addr().(*net.TCPAddr)
	if addr.Port == 0 {
		t.Error("Server should be listening on a valid port")
	}

	// Stop server
	err = server.Stop()
	if err != nil {
		t.Fatalf("Server.Stop failed: %v", err)
	}

	// Wait for goroutines to finish
	done := make(chan bool)
	go func() {
		server.wg.Wait()
		done <- true
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("Server did not stop within timeout")
	}
}

// TestServerStartStopMultiple tests multiple start/stop cycles
func TestServerStartStopMultiple(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()

	server, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Start and stop multiple times
	for i := 0; i < 3; i++ {
		err = server.Start()
		if err != nil {
			t.Fatalf("Server.Start (cycle %d) failed: %v", i, err)
		}

		time.Sleep(10 * time.Millisecond)

		err = server.Stop()
		if err != nil {
			t.Fatalf("Server.Stop (cycle %d) failed: %v", i, err)
		}

		// Wait for cleanup
		time.Sleep(50 * time.Millisecond)
	}
}

// TestServerStopWithoutStart tests stopping a server that was never started
func TestServerStopWithoutStart(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()

	server, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Stop without starting should not panic
	err = server.Stop()
	if err != nil {
		t.Errorf("Server.Stop should not fail if server was never started: %v", err)
	}
}

// TestServerSessionManagement tests session registration through RegisterSession command
func TestServerSessionManagement(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()

	server, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Create RegisterSession request per ODVA spec
	// RegisterSession request: Protocol Version (2 bytes) + Options Flags (2 bytes)
	registerData := []byte{0x01, 0x00, 0x00, 0x00} // Protocol version 1.0, no flags
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	encap := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandRegisterSession,
		Length:        uint16(len(registerData)),
		SessionID:     0, // Session ID is 0 for RegisterSession
		Status:        0,
		SenderContext: senderContext,
		Options:       0,
		Data:          registerData,
	}

	// Handle RegisterSession
	resp := server.handleRegisterSession(encap, "127.0.0.1:1234")
	if resp == nil {
		t.Fatal("handleRegisterSession returned nil")
	}

	// Decode response
	respEncap, err := enip.DecodeENIP(resp)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	// Verify response per ODVA spec
	if respEncap.Command != enip.ENIPCommandRegisterSession {
		t.Errorf("Expected command 0x%04X (RegisterSession), got 0x%04X", enip.ENIPCommandRegisterSession, respEncap.Command)
	}

	if respEncap.Status != enip.ENIPStatusSuccess {
		t.Errorf("Expected status 0x%08X (success), got 0x%08X", enip.ENIPStatusSuccess, respEncap.Status)
	}

	if respEncap.SessionID == 0 {
		t.Error("Session ID should not be 0 in response")
	}

	// Verify session exists
	server.sessionsMu.RLock()
	session, exists := server.sessions[respEncap.SessionID]
	server.sessionsMu.RUnlock()

	if !exists {
		t.Error("Session should exist after registration")
	}

	if session == nil {
		t.Fatal("Session should not be nil")
	}

	// Verify response data matches request (echo protocol version and flags per ODVA spec)
	if len(respEncap.Data) != len(registerData) {
		t.Errorf("Response data length mismatch: got %d, want %d", len(respEncap.Data), len(registerData))
	}

	// Test UnregisterSession
	unregisterEncap := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandUnregisterSession,
		Length:        0,
		SessionID:     respEncap.SessionID,
		Status:        0,
		SenderContext: senderContext,
		Options:       0,
		Data:          nil,
	}

	unregisterResp := server.handleUnregisterSession(unregisterEncap)
	if unregisterResp == nil {
		t.Fatal("handleUnregisterSession returned nil")
	}

	unregisterRespEncap, err := enip.DecodeENIP(unregisterResp)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	if unregisterRespEncap.Status != enip.ENIPStatusSuccess {
		t.Errorf("Expected status 0x%08X (success), got 0x%08X", enip.ENIPStatusSuccess, unregisterRespEncap.Status)
	}

	// Verify session is removed
	server.sessionsMu.RLock()
	_, exists = server.sessions[respEncap.SessionID]
	server.sessionsMu.RUnlock()

	if exists {
		t.Error("Session should be removed after unregistration")
	}
}

// TestServerContextCancellation tests that server stops when context is cancelled
func TestServerContextCancellation(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()

	server, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	err = server.Start()
	if err != nil {
		t.Fatalf("Server.Start failed: %v", err)
	}

	// Cancel context
	server.cancel()

	// Wait a bit for cancellation to propagate
	time.Sleep(50 * time.Millisecond)

	// Stop should still work
	err = server.Stop()
	if err != nil {
		t.Errorf("Server.Stop failed after context cancellation: %v", err)
	}
}
