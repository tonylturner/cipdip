package client

// Integration tests against server mode
// These tests require a running server instance

import (
	"context"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"testing"
	"time"
)

// TestClientServerIntegration tests basic client-server communication
// This test requires a server to be running, so it's skipped by default
// Run with: go test -tags=integration ./internal/cipclient/...
func TestClientServerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if integration tests are enabled
	if !hasIntegrationTag() {
		t.Skip("Skipping integration test (use -tags=integration to enable)")
	}

	// Test against localhost server
	client := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Connect to server
	err := client.Connect(ctx, "127.0.0.1", 44818)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Disconnect(ctx)

	// Test ReadAttribute
	path := protocol.CIPPath{
		Class:     0x04,
		Instance:  0x65,
		Attribute: 0x03,
		Name:      "TestAssembly",
	}

	resp, err := client.ReadAttribute(ctx, path)
	if err != nil {
		t.Fatalf("ReadAttribute failed: %v", err)
	}

	// Verify response
	if resp.Status != 0x00 {
		t.Errorf("ReadAttribute status: got 0x%02X, want 0x00", resp.Status)
	}

	// Verify we got some data back
	if len(resp.Payload) == 0 {
		t.Error("ReadAttribute returned empty payload")
	}
}

// TestForwardOpenIntegration tests ForwardOpen against server
func TestForwardOpenIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	if !hasIntegrationTag() {
		t.Skip("Skipping integration test (use -tags=integration to enable)")
	}

	client := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect
	err := client.Connect(ctx, "127.0.0.1", 44818)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Disconnect(ctx)

	// ForwardOpen
	params := ConnectionParams{
		Name:                  "TestConnection",
		OToTRPIMs:             20,
		TToORPIMs:             20,
		OToTSizeBytes:         8,
		TToOSizeBytes:         8,
		Priority:              "scheduled",
		TransportClassTrigger: 3,
		Class:                 0x04,
		Instance:              0x65,
	}

	conn, err := client.ForwardOpen(ctx, params)
	if err != nil {
		t.Fatalf("ForwardOpen failed: %v", err)
	}

	if conn == nil {
		t.Fatal("ForwardOpen returned nil connection")
	}

	if conn.ID == 0 {
		t.Error("ForwardOpen returned connection with ID 0")
	}

	// ForwardClose
	err = client.ForwardClose(ctx, conn)
	if err != nil {
		t.Errorf("ForwardClose failed: %v", err)
	}
}

// TestSendIODataIntegration tests I/O data exchange
func TestSendIODataIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	if !hasIntegrationTag() {
		t.Skip("Skipping integration test (use -tags=integration to enable)")
	}

	client := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect
	err := client.Connect(ctx, "127.0.0.1", 44818)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Disconnect(ctx)

	// ForwardOpen
	params := ConnectionParams{
		Name:                  "TestIO",
		OToTRPIMs:             20,
		TToORPIMs:             20,
		OToTSizeBytes:         8,
		TToOSizeBytes:         8,
		Priority:              "scheduled",
		TransportClassTrigger: 3,
		Class:                 0x04,
		Instance:              0x65,
	}

	conn, err := client.ForwardOpen(ctx, params)
	if err != nil {
		t.Fatalf("ForwardOpen failed: %v", err)
	}
	defer client.ForwardClose(ctx, conn)

	// Send I/O data
	testData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	err = client.SendIOData(ctx, conn, testData)
	if err != nil {
		t.Errorf("SendIOData failed: %v", err)
	}

	// Receive I/O data (with timeout)
	ctxRecv, cancelRecv := context.WithTimeout(ctx, 2*time.Second)
	defer cancelRecv()

	recvData, err := client.ReceiveIOData(ctxRecv, conn)
	if err != nil {
		// ReceiveIOData may timeout or fail, which is acceptable for this test
		t.Logf("ReceiveIOData failed (may be expected): %v", err)
	} else if len(recvData) > 0 {
		t.Logf("Received I/O data: %d bytes", len(recvData))
	}
}

// hasIntegrationTag checks if integration tag is set
// This is a simple check - in a real implementation, you'd use build tags
func hasIntegrationTag() bool {
	// For now, we'll skip integration tests by default
	// Users can enable them by setting an environment variable or using build tags
	return false // Change to true or check env var to enable
}

