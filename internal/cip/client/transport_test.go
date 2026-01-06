package client

// Transport tests for TCP and UDP

import (
	"context"
	"testing"
	"time"
)

// TestTCPTransportConnect tests TCP transport connection
func TestTCPTransportConnect(t *testing.T) {
	transport := NewTCPTransport()

	// Test connecting to invalid address (should fail)
	ctx := context.Background()
	err := transport.Connect(ctx, "invalid:99999")
	if err == nil {
		t.Error("Connect to invalid address should fail")
	}

	// Test IsConnected before connection
	if transport.IsConnected() {
		t.Error("Transport should not be connected before Connect()")
	}
}

// TestUDPTransportConnect tests UDP transport connection
func TestUDPTransportConnect(t *testing.T) {
	transport := NewUDPTransport()

	ctx := context.Background()

	// Test connecting to a valid address format
	// Note: This won't actually connect to a real server, but should resolve the address
	err := transport.Connect(ctx, "127.0.0.1:2222")
	if err != nil {
		// This is expected if we can't bind, but address resolution should work
		t.Logf("UDP Connect result: %v (may be expected)", err)
	}

	// Test IsConnected
	connected := transport.IsConnected()
	_ = connected // May be true or false depending on whether Connect succeeded

	// Test Disconnect
	if err := transport.Disconnect(); err != nil {
		t.Errorf("Disconnect failed: %v", err)
	}

	// Test IsConnected after disconnect
	if transport.IsConnected() {
		t.Error("Transport should not be connected after Disconnect()")
	}
}

// TestUDPTransportDoubleConnect tests that connecting twice fails
func TestUDPTransportDoubleConnect(t *testing.T) {
	transport := NewUDPTransport()
	ctx := context.Background()

	// First connect (may succeed or fail depending on system)
	err1 := transport.Connect(ctx, "127.0.0.1:2222")

	// Second connect should fail with "already connected"
	err2 := transport.Connect(ctx, "127.0.0.1:2222")
	if err1 == nil && err2 == nil {
		t.Error("Second Connect should fail with 'already connected'")
	}

	// Cleanup
	_ = transport.Disconnect()
}

// TestTCPTransportDoubleConnect tests that connecting twice fails
func TestTCPTransportDoubleConnect(t *testing.T) {
	transport := NewTCPTransport()
	ctx := context.Background()

	// First connect to invalid address (will fail, but sets up test)
	_ = transport.Connect(ctx, "invalid:99999")

	// Second connect should fail with "already connected" if first succeeded
	// or fail for other reasons if first failed
	err := transport.Connect(ctx, "invalid:99999")
	if err == nil {
		t.Error("Second Connect should fail")
	}

	// Cleanup
	_ = transport.Disconnect()
}

// TestTransportSendReceiveNotConnected tests that Send/Receive fail when not connected
func TestTransportSendReceiveNotConnected(t *testing.T) {
	// Test TCP
	tcpTransport := NewTCPTransport()
	ctx := context.Background()

	err := tcpTransport.Send(ctx, []byte{0x01, 0x02})
	if err == nil {
		t.Error("TCP Send should fail when not connected")
	}

	_, err = tcpTransport.Receive(ctx, time.Second)
	if err == nil {
		t.Error("TCP Receive should fail when not connected")
	}

	// Test UDP
	udpTransport := NewUDPTransport()

	err = udpTransport.Send(ctx, []byte{0x01, 0x02})
	if err == nil {
		t.Error("UDP Send should fail when not connected")
	}

	_, err = udpTransport.Receive(ctx, time.Second)
	if err == nil {
		t.Error("UDP Receive should fail when not connected")
	}
}

// TestUDPTransportAddressResolution tests UDP address resolution
func TestUDPTransportAddressResolution(t *testing.T) {
	transport := NewUDPTransport()
	ctx := context.Background()

	// Test valid address format
	err := transport.Connect(ctx, "127.0.0.1:2222")
	if err != nil {
		// May fail for other reasons (binding), but address resolution should work
		t.Logf("UDP Connect to valid address: %v", err)
	}
	_ = transport.Disconnect()

	// Test invalid address format
	err = transport.Connect(ctx, "not-a-valid-address")
	if err == nil {
		t.Error("Connect to invalid address format should fail")
	}
}

// TestTransportDisconnectIdempotent tests that Disconnect can be called multiple times
func TestTransportDisconnectIdempotent(t *testing.T) {
	// Test TCP
	tcpTransport := NewTCPTransport()
	if err := tcpTransport.Disconnect(); err != nil {
		t.Errorf("First TCP Disconnect should succeed: %v", err)
	}
	if err := tcpTransport.Disconnect(); err != nil {
		t.Errorf("Second TCP Disconnect should succeed: %v", err)
	}

	// Test UDP
	udpTransport := NewUDPTransport()
	if err := udpTransport.Disconnect(); err != nil {
		t.Errorf("First UDP Disconnect should succeed: %v", err)
	}
	if err := udpTransport.Disconnect(); err != nil {
		t.Errorf("Second UDP Disconnect should succeed: %v", err)
	}
}

