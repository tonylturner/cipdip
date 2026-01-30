package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/tturner/cipdip/internal/enip"
)

// Start starts the server.
func (s *Server) Start() error {
	if s.config.Metrics.Enable {
		if err := s.startMetricsListener(); err != nil {
			return err
		}
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", s.config.Server.ListenIP, s.config.Server.TCPPort))
	if err != nil {
		return fmt.Errorf("resolve TCP address: %w", err)
	}

	s.tcpListener, err = net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return fmt.Errorf("listen TCP: %w", err)
	}

	s.logger.Info("TCP server listening on %s:%d", s.config.Server.ListenIP, s.config.Server.TCPPort)
	fmt.Printf("[SERVER] TCP server listening on %s:%d\n", s.config.Server.ListenIP, s.config.Server.TCPPort)

	if s.config.Server.EnableUDPIO {
		udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", s.config.Server.ListenIP, s.config.Server.UDPIOPort))
		if err != nil {
			return fmt.Errorf("resolve UDP address: %w", err)
		}

		s.udpListener, err = net.ListenUDP("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("listen UDP: %w", err)
		}

		s.logger.Info("UDP I/O server listening on %s:%d", s.config.Server.ListenIP, s.config.Server.UDPIOPort)
		fmt.Printf("[SERVER] UDP I/O server listening on %s:%d\n", s.config.Server.ListenIP, s.config.Server.UDPIOPort)

		s.wg.Add(1)
		go s.handleUDP()

		// Join multicast group if configured (uses the UDP listener socket).
		if s.config.Server.MulticastGroup != "" {
			group := net.ParseIP(s.config.Server.MulticastGroup)
			if group != nil {
				p := ipv4.NewPacketConn(s.udpListener)
				var ifi *net.Interface
				if s.config.Server.MulticastInterface != "" {
					ifi, _ = net.InterfaceByName(s.config.Server.MulticastInterface)
				}
				if err := p.JoinGroup(ifi, &net.UDPAddr{IP: group}); err != nil {
					s.logger.Error("Failed to join multicast group %s: %v", s.config.Server.MulticastGroup, err)
				} else {
					s.multicastConn = p
					s.logger.Info("Joined multicast group %s for I/O data", s.config.Server.MulticastGroup)
					fmt.Printf("[SERVER] Joined multicast group %s\n", s.config.Server.MulticastGroup)
				}
			}
		}
	}

	s.wg.Add(1)
	go s.acceptLoop()

	// Emit server_ready event for orchestration controller readiness detection
	if s.tuiStats {
		readyEvent := map[string]interface{}{
			"event":     "server_ready",
			"listen":    fmt.Sprintf("%s:%d", s.config.Server.ListenIP, s.config.Server.TCPPort),
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		if data, err := json.Marshal(readyEvent); err == nil {
			fmt.Fprintf(os.Stdout, "%s\n", data)
			os.Stdout.Sync()
		}
	}

	return nil
}

// TCPAddr returns the bound TCP address after Start.
func (s *Server) TCPAddr() *net.TCPAddr {
	if s.tcpListener == nil {
		return nil
	}
	if addr, ok := s.tcpListener.Addr().(*net.TCPAddr); ok {
		return addr
	}
	return nil
}

// Stop stops the server.
func (s *Server) Stop() error {
	s.cancel()

	if s.tcpListener != nil {
		s.tcpListener.Close()
	}

	if s.metricsListener != nil {
		s.metricsListener.Close()
	}

	if s.multicastConn != nil {
		if s.config.Server.MulticastGroup != "" {
			group := net.ParseIP(s.config.Server.MulticastGroup)
			if group != nil {
				var ifi *net.Interface
				if s.config.Server.MulticastInterface != "" {
					ifi, _ = net.InterfaceByName(s.config.Server.MulticastInterface)
				}
				_ = s.multicastConn.LeaveGroup(ifi, &net.UDPAddr{IP: group})
			}
		}
		s.multicastConn = nil
	}

	if s.udpListener != nil {
		s.udpListener.Close()
	}

	s.sessionsMu.Lock()
	for _, session := range s.sessions {
		if session != nil && session.Conn != nil {
			session.Conn.Close()
		}
	}
	s.sessions = make(map[uint32]*Session)
	s.sessionsMu.Unlock()

	s.connectionsMu.Lock()
	s.connections = make(map[uint32]*ConnectionState)
	s.connectionsMu.Unlock()

	s.wg.Wait()

	s.logger.Info("Server stopped")
	fmt.Printf("[SERVER] Server stopped gracefully\n")
	return nil
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		s.tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		conn, err := s.tcpListener.AcceptTCP()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if s.ctx.Err() != nil {
				return
			}
			s.logger.Error("Accept error: %v", err)
			continue
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn *net.TCPConn) {
	defer s.wg.Done()
	defer func() {
		s.sessionsMu.Lock()
		for sessionID, session := range s.sessions {
			if session != nil && session.Conn == conn {
				delete(s.sessions, sessionID)
				s.dropConnectionsForSession(sessionID)
				break
			}
		}
		s.sessionsMu.Unlock()
		conn.Close()
	}()

	remoteAddr := conn.RemoteAddr().String()
	s.logger.Info("New connection from %s", remoteAddr)
	fmt.Printf("[SERVER] New connection from %s\n", remoteAddr)
	s.recordConnection(remoteAddr)

	buffer := make([]byte, 0, 8192)
	readBuf := make([]byte, 4096)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		n, err := conn.Read(readBuf)
		if err != nil {
			if err == io.EOF {
				s.logger.Info("Connection closed by client: %s", remoteAddr)
				fmt.Printf("[SERVER] Connection closed by client: %s\n", remoteAddr)
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			s.logger.Error("Read error from %s: %v", remoteAddr, err)
			return
		}
		if n == 0 {
			continue
		}

		buffer = append(buffer, readBuf[:n]...)

		frames, remaining := parseENIPStream(buffer, s.logger)
		buffer = remaining

		for _, encap := range frames {
			resp := s.handleENIPCommand(encap, remoteAddr)
			if resp != nil {
				if err := s.writeResponse(conn, remoteAddr, resp); err != nil {
					return
				}
			}

			if encap.SessionID != 0 {
				s.sessionsMu.Lock()
				session, ok := s.sessions[encap.SessionID]
				if ok && session != nil {
					if session.Conn == nil {
						session.Conn = conn
					}
					session.mu.Lock()
					session.LastActivity = time.Now()
					session.mu.Unlock()
				}
				s.sessionsMu.Unlock()
			}
		}
	}
}

func (s *Server) handleUDP() {
	defer s.wg.Done()
	buf := make([]byte, 4096)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		_ = s.udpListener.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := s.udpListener.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		encap, err := enip.DecodeENIP(data)
		if err != nil {
			s.logger.Debug("UDP decode ENIP error: %v", err)
			continue
		}

		if encap.Command == enip.ENIPCommandSendUnitData && s.enipSupport.sendUnitData {
			resp := s.handleSendUnitData(encap, addr.String())
			if resp != nil {
				// If multicast is configured and this is I/O data, send to multicast group
				if s.multicastConn != nil && s.config.Server.MulticastGroup != "" {
					if err := s.sendMulticastIOData(resp); err != nil {
						s.logger.Debug("Multicast send error: %v", err)
						// Fall back to unicast
						if _, err := s.udpListener.WriteToUDP(resp, addr); err != nil {
							s.logger.Error("UDP write error to %s: %v", addr.String(), err)
						}
					} else {
						s.logger.Debug("UDP I/O response sent to multicast group %s: %d bytes", s.config.Server.MulticastGroup, len(resp))
					}
				} else {
					if _, err := s.udpListener.WriteToUDP(resp, addr); err != nil {
						s.logger.Error("UDP write error to %s: %v", addr.String(), err)
					} else {
						s.logger.Debug("UDP I/O response sent to %s: %d bytes", addr.String(), len(resp))
					}
				}
			}
		} else if encap.Command == enip.ENIPCommandListIdentity && s.enipSupport.listIdentity {
			resp := s.handleListIdentity(encap, addr.String())
			if resp != nil {
				if _, err := s.udpListener.WriteToUDP(resp, addr); err != nil {
					s.logger.Error("UDP write error to %s: %v", addr.String(), err)
				}
			}
		} else {
			s.logger.Debug("UDP packet from %s: unsupported command 0x%04X", addr.String(), encap.Command)
		}
	}
}

// sendMulticastIOData sends I/O data to the configured multicast group.
func (s *Server) sendMulticastIOData(data []byte) error {
	if s.multicastConn == nil {
		return fmt.Errorf("multicast not configured")
	}

	group := net.ParseIP(s.config.Server.MulticastGroup)
	if group == nil {
		return fmt.Errorf("invalid multicast group: %s", s.config.Server.MulticastGroup)
	}

	port := s.config.Server.UDPIOPort
	if port == 0 {
		port = 2222
	}

	dst := &net.UDPAddr{IP: group, Port: port}
	_, err := s.multicastConn.WriteTo(data, nil, dst)
	return err
}

// SendMulticastIOData is the public method for sending I/O data to the multicast group.
// This can be called by connection state handlers to send T→O data.
func (s *Server) SendMulticastIOData(data []byte) error {
	return s.sendMulticastIOData(data)
}

func (s *Server) startMetricsListener() error {
	addr := fmt.Sprintf("%s:%d", s.config.Metrics.ListenIP, s.config.Metrics.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("start metrics listener: %w", err)
	}
	s.metricsListener = listener
	s.wg.Add(1)
	go s.metricsLoop()
	return nil
}

func (s *Server) metricsLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.metricsListener.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		fmt.Fprintf(conn, "cipdip_server_up 1\n")
		_ = conn.Close()
	}
}

// EnableTUIStats enables periodic JSON stats output for TUI consumption.
func (s *Server) EnableTUIStats() {
	s.tuiStats = true
	s.statsQuit = make(chan struct{})
	s.wg.Add(1)
	go s.statsLoop()
}

// statsLoop outputs JSON stats periodically when TUI stats are enabled.
func (s *Server) statsLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.statsQuit:
			return
		case <-ticker.C:
			s.outputStats()
		}
	}
}

// outputStats writes current stats as JSON to stdout.
func (s *Server) outputStats() {
	s.statsMu.RLock()
	stats := s.stats
	s.statsMu.RUnlock()

	// Get active session count
	s.sessionsMu.RLock()
	stats.ActiveConnections = len(s.sessions)
	s.sessionsMu.RUnlock()

	data, err := json.Marshal(map[string]interface{}{
		"type":  "stats",
		"stats": stats,
	})
	if err != nil {
		return
	}
	fmt.Fprintf(os.Stdout, "%s\n", data)
	os.Stdout.Sync()
}

// recordConnection increments connection stats.
func (s *Server) recordConnection(remoteAddr string) {
	s.statsMu.Lock()
	s.stats.TotalConnections++
	// Keep last 10 clients
	s.stats.RecentClients = append(s.stats.RecentClients, remoteAddr)
	if len(s.stats.RecentClients) > 10 {
		s.stats.RecentClients = s.stats.RecentClients[1:]
	}
	s.statsMu.Unlock()
}

// recordRequest increments request stats.
func (s *Server) recordRequest() {
	s.statsMu.Lock()
	s.stats.TotalRequests++
	s.statsMu.Unlock()
}

// recordError increments error stats.
func (s *Server) recordError() {
	s.statsMu.Lock()
	s.stats.TotalErrors++
	s.statsMu.Unlock()
}

// GetStats returns a copy of current stats.
func (s *Server) GetStats() ServerStats {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()
	stats := s.stats
	s.sessionsMu.RLock()
	stats.ActiveConnections = len(s.sessions)
	s.sessionsMu.RUnlock()
	return stats
}
