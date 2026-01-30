package client

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

func TestCIPMulticastAddress(t *testing.T) {
	tests := []struct {
		deviceIP string
		want     string
	}{
		{"10.0.0.1", "239.192.1.0"},   // (1-1)%32 = 0
		{"10.0.0.2", "239.192.1.1"},   // (2-1)%32 = 1
		{"10.0.0.33", "239.192.1.0"},  // (33-1)%32 = 0
		{"10.0.0.50", "239.192.1.17"}, // (50-1)%32 = 17
		{"192.168.1.100", "239.192.1.3"}, // (100-1)%32 = 3
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.deviceIP)
		got := CIPMulticastAddress(ip)
		if got.String() != tt.want {
			t.Errorf("CIPMulticastAddress(%s) = %s, want %s", tt.deviceIP, got, tt.want)
		}
	}
}

func TestCIPMulticastAddress_IPv6Fallback(t *testing.T) {
	// IPv6 address should return the base multicast address.
	ip := net.ParseIP("2001:db8::1")
	got := CIPMulticastAddress(ip)
	if got.String() != "239.192.1.0" {
		t.Errorf("CIPMulticastAddress(IPv6) = %s, want 239.192.1.0", got)
	}
}

func TestMulticastConfigDefaults(t *testing.T) {
	cfg := MulticastConfig{}
	cfg.applyDefaults()

	if cfg.GroupAddress != "239.192.1.0" {
		t.Errorf("GroupAddress = %q, want 239.192.1.0", cfg.GroupAddress)
	}
	if cfg.TTL != 32 {
		t.Errorf("TTL = %d, want 32", cfg.TTL)
	}
	if cfg.Port != 2222 {
		t.Errorf("Port = %d, want 2222", cfg.Port)
	}
}

func TestMulticastConfigPreserveExplicit(t *testing.T) {
	cfg := MulticastConfig{
		GroupAddress: "239.192.2.0",
		TTL:          64,
		Port:         3333,
	}
	cfg.applyDefaults()

	if cfg.GroupAddress != "239.192.2.0" {
		t.Errorf("GroupAddress = %q, want 239.192.2.0", cfg.GroupAddress)
	}
	if cfg.TTL != 64 {
		t.Errorf("TTL = %d, want 64", cfg.TTL)
	}
	if cfg.Port != 3333 {
		t.Errorf("Port = %d, want 3333", cfg.Port)
	}
}

func TestMulticastTransportNotConnected(t *testing.T) {
	mt := NewMulticastTransport(MulticastConfig{})

	if mt.IsConnected() {
		t.Error("new transport should not be connected")
	}

	ctx := context.Background()
	if err := mt.Send(ctx, []byte("hello")); err == nil {
		t.Error("Send on unconnected transport should error")
	}
	if _, err := mt.Receive(ctx, time.Second); err == nil {
		t.Error("Receive on unconnected transport should error")
	}

	// Disconnect on unconnected should be a no-op.
	if err := mt.Disconnect(); err != nil {
		t.Errorf("Disconnect on unconnected: %v", err)
	}
}

func TestMulticastTransportConnectDisconnect(t *testing.T) {
	if !multicastAvailable() {
		t.Skip("multicast not available on this host")
	}

	mt := NewMulticastTransport(MulticastConfig{
		GroupAddress: "239.192.1.0",
		Port:         0, // let OS pick port
	})

	ctx := context.Background()
	if err := mt.Connect(ctx, ""); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if !mt.IsConnected() {
		t.Error("transport should be connected after Connect")
	}

	// Double connect should error.
	if err := mt.Connect(ctx, ""); err == nil {
		t.Error("double Connect should error")
	}

	if err := mt.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}

	if mt.IsConnected() {
		t.Error("transport should not be connected after Disconnect")
	}
}

func TestMulticastTransportSendReceive(t *testing.T) {
	if !multicastAvailable() {
		t.Skip("multicast not available on this host")
	}

	// Use a high ephemeral port to avoid conflicts.
	port := 19222

	mt := NewMulticastTransport(MulticastConfig{
		GroupAddress: "239.192.1.0",
		Port:         port,
		TTL:          1,
	})

	ctx := context.Background()
	if err := mt.Connect(ctx, ""); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer mt.Disconnect()

	// Send data to the multicast group.
	payload := []byte("ENIP-IO-TEST")
	if err := mt.Send(ctx, payload); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Receive should get the loopback packet.
	got, err := mt.Receive(ctx, 2*time.Second)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}

	if string(got) != string(payload) {
		t.Errorf("Receive = %q, want %q", got, payload)
	}
}

func TestMulticastTransportInvalidGroup(t *testing.T) {
	mt := NewMulticastTransport(MulticastConfig{
		GroupAddress: "not-a-valid-ip",
		Port:         0,
	})

	ctx := context.Background()
	err := mt.Connect(ctx, "")
	if err == nil {
		mt.Disconnect()
		t.Fatal("Connect with invalid group should error")
	}
}

// multicastAvailable returns true if the host can join a multicast group.
func multicastAvailable() bool {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		return false
	}
	defer conn.Close()

	p := ipv4.NewPacketConn(conn)
	err = p.JoinGroup(nil, &net.UDPAddr{IP: net.ParseIP("239.192.1.0")})
	if err != nil {
		return false
	}
	_ = p.LeaveGroup(nil, &net.UDPAddr{IP: net.ParseIP("239.192.1.0")})
	return true
}
