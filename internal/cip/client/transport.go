package client

// Transport abstraction for TCP/UDP connections

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// TransportType represents the type of transport
type TransportType string

const (
	TransportTCP TransportType = "tcp"
	TransportUDP TransportType = "udp"
)

// Transport represents a network transport connection
type Transport interface {
	Connect(ctx context.Context, addr string) error
	Disconnect() error
	Send(ctx context.Context, data []byte) error
	Receive(ctx context.Context, timeout time.Duration) ([]byte, error)
	IsConnected() bool
}

// TCPTransport implements TCP transport
type TCPTransport struct {
	conn   *net.TCPConn
	addr   string
	connMu sync.RWMutex
}

var _ Transport = (*TCPTransport)(nil)

// NewTCPTransport creates a new TCP transport
func NewTCPTransport() *TCPTransport {
	return &TCPTransport{}
}

// Connect establishes a TCP connection
func (t *TCPTransport) Connect(ctx context.Context, addr string) error {
	t.connMu.Lock()
	defer t.connMu.Unlock()

	if t.conn != nil {
		return fmt.Errorf("already connected")
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return fmt.Errorf("resolve TCP address: %w", err)
	}

	dialer := net.Dialer{
		Timeout: 5 * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", tcpAddr.String())
	if err != nil {
		return fmt.Errorf("dial TCP: %w", err)
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return fmt.Errorf("not a TCP connection")
	}

	t.conn = tcpConn
	t.addr = addr

	// Set keep-alive
	if err := tcpConn.SetKeepAlive(true); err != nil {
		tcpConn.Close()
		t.conn = nil
		return fmt.Errorf("set keep-alive: %w", err)
	}

	return nil
}

// Disconnect closes the TCP connection
func (t *TCPTransport) Disconnect() error {
	t.connMu.Lock()
	defer t.connMu.Unlock()

	if t.conn == nil {
		return nil
	}

	err := t.conn.Close()
	t.conn = nil
	t.addr = ""

	return err
}

// Send sends data over TCP
func (t *TCPTransport) Send(ctx context.Context, data []byte) error {
	t.connMu.RLock()
	defer t.connMu.RUnlock()

	if t.conn == nil {
		return fmt.Errorf("not connected")
	}

	// Set write deadline
	if deadline, ok := ctx.Deadline(); ok {
		if err := t.conn.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("set write deadline: %w", err)
		}
	}

	_, err := t.conn.Write(data)
	return err
}

// Receive receives data from TCP
func (t *TCPTransport) Receive(ctx context.Context, timeout time.Duration) ([]byte, error) {
	t.connMu.RLock()
	defer t.connMu.RUnlock()

	if t.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Set read deadline
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := t.conn.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}

	// Read ENIP header first (24 bytes)
	header := make([]byte, 24)
	n, err := t.conn.Read(header)
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	if n < 24 {
		return nil, fmt.Errorf("incomplete header: %d bytes", n)
	}

	// Extract length from header (bytes 2-4, big-endian)
	order := currentENIPByteOrder()
	length := order.Uint16(header[2:4])

	// Read data field
	if length > 0 {
		data := make([]byte, length)
		n, err := t.conn.Read(data)
		if err != nil {
			return nil, fmt.Errorf("read data: %w", err)
		}
		if n < int(length) {
			return nil, fmt.Errorf("incomplete data: %d bytes, expected %d", n, length)
		}

		// Combine header and data
		return append(header, data...), nil
	}

	return header, nil
}

// IsConnected returns whether the transport is connected
func (t *TCPTransport) IsConnected() bool {
	t.connMu.RLock()
	defer t.connMu.RUnlock()
	return t.conn != nil
}

// UDPTransport implements UDP transport
type UDPTransport struct {
	conn   *net.UDPConn
	addr   *net.UDPAddr
	connMu sync.RWMutex
}

var _ Transport = (*UDPTransport)(nil)

// NewUDPTransport creates a new UDP transport
func NewUDPTransport() *UDPTransport {
	return &UDPTransport{}
}

// Connect binds a UDP socket (for listening) or sets target address (for sending)
func (t *UDPTransport) Connect(ctx context.Context, addr string) error {
	t.connMu.Lock()
	defer t.connMu.Unlock()

	if t.conn != nil {
		return fmt.Errorf("already connected")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve UDP address: %w", err)
	}

	// Bind to local address (use :0 to let OS choose port)
	localAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return fmt.Errorf("resolve local UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}

	t.conn = conn
	t.addr = udpAddr

	return nil
}

// Disconnect closes the UDP connection
func (t *UDPTransport) Disconnect() error {
	t.connMu.Lock()
	defer t.connMu.Unlock()

	if t.conn == nil {
		return nil
	}

	err := t.conn.Close()
	t.conn = nil
	t.addr = nil

	return err
}

// Send sends data over UDP
func (t *UDPTransport) Send(ctx context.Context, data []byte) error {
	t.connMu.RLock()
	defer t.connMu.RUnlock()

	if t.conn == nil || t.addr == nil {
		return fmt.Errorf("not connected")
	}

	// Set write deadline
	if deadline, ok := ctx.Deadline(); ok {
		if err := t.conn.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("set write deadline: %w", err)
		}
	}

	_, err := t.conn.WriteToUDP(data, t.addr)
	return err
}

// Receive receives data from UDP
func (t *UDPTransport) Receive(ctx context.Context, timeout time.Duration) ([]byte, error) {
	t.connMu.RLock()
	defer t.connMu.RUnlock()

	if t.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Set read deadline
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := t.conn.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}

	// UDP receives entire datagram at once
	// Allocate buffer large enough for ENIP header + max data
	buffer := make([]byte, 24+65535) // ENIP header (24) + max UDP payload
	n, addr, err := t.conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, fmt.Errorf("read UDP: %w", err)
	}
	if n < 24 {
		return nil, fmt.Errorf("incomplete packet: %d bytes (minimum 24)", n)
	}

	// Verify sender address matches expected (if set)
	if t.addr != nil && addr.String() != t.addr.String() {
		// Allow responses from different addresses for discovery
		// but log or handle as needed
	}

	// Return the received packet
	return buffer[:n], nil
}

// IsConnected returns whether the transport is connected
func (t *UDPTransport) IsConnected() bool {
	t.connMu.RLock()
	defer t.connMu.RUnlock()
	return t.conn != nil
}

