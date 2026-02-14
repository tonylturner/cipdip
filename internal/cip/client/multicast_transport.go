package client

// Multicast I/O transport for EtherNet/IP implicit messaging.
//
// EtherNet/IP uses multicast UDP for Target-to-Originator (T→O) I/O data.
// The ODVA-specified multicast address range starts at 239.192.1.0 and
// offsets by (last_octet - 1) % 32 for a given device IP.

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

// MulticastConfig configures multicast I/O transport parameters.
type MulticastConfig struct {
	GroupAddress string // multicast group, e.g. "239.192.1.0"
	Interface    string // network interface name, empty = default
	TTL          int    // multicast TTL, default 32
	Port         int    // destination port, default 2222
}

// multicastDefaults fills zero-value fields with ODVA defaults.
func (c *MulticastConfig) applyDefaults() {
	if c.GroupAddress == "" {
		c.GroupAddress = "239.192.1.0"
	}
	if c.TTL == 0 {
		c.TTL = 32
	}
	if c.Port == 0 {
		c.Port = 2222
	}
}

// MulticastTransport implements Transport for multicast I/O data.
type MulticastTransport struct {
	conn   *net.UDPConn
	group  *net.UDPAddr
	pconn  *ipv4.PacketConn
	config MulticastConfig
	connMu sync.RWMutex
}

var _ Transport = (*MulticastTransport)(nil)

// NewMulticastTransport creates a multicast transport with the given config.
func NewMulticastTransport(cfg MulticastConfig) *MulticastTransport {
	cfg.applyDefaults()
	return &MulticastTransport{config: cfg}
}

// CIPMulticastAddress computes the ODVA multicast address for a device IP.
// Per ODVA Volume 2, Chapter 2-4.6: base = 239.192.1.0, offset = (lastOctet - 1) % 32.
func CIPMulticastAddress(deviceIP net.IP) net.IP {
	ip4 := deviceIP.To4()
	if ip4 == nil {
		return net.ParseIP("239.192.1.0")
	}
	offset := (int(ip4[3]) - 1) % 32
	if offset < 0 {
		offset += 32
	}
	return net.IPv4(239, 192, 1, byte(offset))
}

// Connect joins the configured multicast group and prepares for send/receive.
func (t *MulticastTransport) Connect(_ context.Context, addr string) error {
	t.connMu.Lock()
	defer t.connMu.Unlock()

	if t.conn != nil {
		return fmt.Errorf("already connected")
	}

	groupIP := net.ParseIP(t.config.GroupAddress)
	if groupIP == nil {
		return fmt.Errorf("invalid multicast group address: %s", t.config.GroupAddress)
	}

	t.group = &net.UDPAddr{IP: groupIP, Port: t.config.Port}

	// Bind to the multicast port to receive group traffic.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: t.config.Port})
	if err != nil {
		return fmt.Errorf("listen UDP for multicast: %w", err)
	}

	p := ipv4.NewPacketConn(conn)

	var ifi *net.Interface
	if t.config.Interface != "" {
		ifi, err = net.InterfaceByName(t.config.Interface)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("interface %q: %w", t.config.Interface, err)
		}
	}

	if err := p.JoinGroup(ifi, &net.UDPAddr{IP: groupIP}); err != nil {
		_ = conn.Close()
		return fmt.Errorf("join multicast group %s: %w", groupIP, err)
	}

	if err := p.SetMulticastTTL(t.config.TTL); err != nil {
		_ = conn.Close()
		return fmt.Errorf("set multicast TTL: %w", err)
	}

	// Enable multicast loopback so tests on a single host work.
	if err := p.SetMulticastLoopback(true); err != nil {
		_ = conn.Close()
		return fmt.Errorf("set multicast loopback: %w", err)
	}

	t.conn = conn
	t.pconn = p

	return nil
}

// Disconnect leaves the multicast group and closes the socket.
func (t *MulticastTransport) Disconnect() error {
	t.connMu.Lock()
	defer t.connMu.Unlock()

	if t.conn == nil {
		return nil
	}

	if t.pconn != nil {
		var ifi *net.Interface
		if t.config.Interface != "" {
			ifi, _ = net.InterfaceByName(t.config.Interface)
		}
		groupIP := net.ParseIP(t.config.GroupAddress)
		if groupIP != nil {
			_ = t.pconn.LeaveGroup(ifi, &net.UDPAddr{IP: groupIP})
		}
	}

	err := t.conn.Close()
	t.conn = nil
	t.pconn = nil

	return err
}

// Send writes data to the multicast group address.
func (t *MulticastTransport) Send(ctx context.Context, data []byte) error {
	t.connMu.RLock()
	defer t.connMu.RUnlock()

	if t.conn == nil || t.group == nil {
		return fmt.Errorf("not connected")
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := t.conn.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("set write deadline: %w", err)
		}
	}

	_, err := t.conn.WriteToUDP(data, t.group)
	return err
}

// Receive reads a datagram from the multicast group.
func (t *MulticastTransport) Receive(_ context.Context, timeout time.Duration) ([]byte, error) {
	t.connMu.RLock()
	defer t.connMu.RUnlock()

	if t.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	deadline := time.Now().Add(timeout)
	if err := t.conn.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}

	buf := make([]byte, 65535)
	n, _, err := t.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("read multicast: %w", err)
	}

	return buf[:n], nil
}

// IsConnected returns whether the multicast socket is open.
func (t *MulticastTransport) IsConnected() bool {
	t.connMu.RLock()
	defer t.connMu.RUnlock()
	return t.conn != nil
}
