package core

import (
	"fmt"
	"io"
	"net"
	"time"

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
	}

	s.wg.Add(1)
	go s.acceptLoop()

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
				if _, err := s.udpListener.WriteToUDP(resp, addr); err != nil {
					s.logger.Error("UDP write error to %s: %v", addr.String(), err)
				} else {
					s.logger.Debug("UDP I/O response sent to %s: %d bytes", addr.String(), len(resp))
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
