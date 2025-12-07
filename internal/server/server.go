package server

// EtherNet/IP CIP Server implementation

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
)

// Server represents an EtherNet/IP CIP server
type Server struct {
	config       *config.ServerConfig
	logger       *logging.Logger
	tcpListener  *net.TCPListener
	udpListener  *net.UDPConn
	sessions     map[uint32]*Session
	sessionsMu   sync.RWMutex
	nextSessionID uint32
	personality  Personality
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
}

// Session represents an active EtherNet/IP session
type Session struct {
	ID            uint32
	Conn          *net.TCPConn
	CreatedAt     time.Time
	LastActivity  time.Time
	mu            sync.Mutex
}

// Personality interface for different server behaviors
type Personality interface {
	HandleCIPRequest(ctx context.Context, req cipclient.CIPRequest) (cipclient.CIPResponse, error)
	GetName() string
}

// NewServer creates a new CIP server
func NewServer(cfg *config.ServerConfig, logger *logging.Logger) (*Server, error) {
	// Create personality based on config
	var personality Personality
	var err error

	switch cfg.Server.Personality {
	case "adapter":
		personality, err = NewAdapterPersonality(cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("create adapter personality: %w", err)
		}
	case "logix_like":
		personality, err = NewLogixPersonality(cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("create logix personality: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown personality: %s", cfg.Server.Personality)
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		config:        cfg,
		logger:        logger,
		sessions:      make(map[uint32]*Session),
		nextSessionID: 1,
		personality:   personality,
		ctx:           ctx,
		cancel:        cancel,
	}

	return s, nil
}

// Start starts the server
func (s *Server) Start() error {
	// Start TCP listener
	tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", s.config.Server.ListenIP, s.config.Server.TCPPort))
	if err != nil {
		return fmt.Errorf("resolve TCP address: %w", err)
	}

	s.tcpListener, err = net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return fmt.Errorf("listen TCP: %w", err)
	}

	s.logger.Info("TCP server listening on %s:%d", s.config.Server.ListenIP, s.config.Server.TCPPort)

	// Start UDP listener if enabled
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

		// Start UDP handler
		s.wg.Add(1)
		go s.handleUDP()
	}

	// Start TCP accept loop
	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

// Stop stops the server
func (s *Server) Stop() error {
	s.cancel()

	// Close TCP listener
	if s.tcpListener != nil {
		s.tcpListener.Close()
	}

	// Close UDP listener
	if s.udpListener != nil {
		s.udpListener.Close()
	}

	// Close all sessions
	s.sessionsMu.Lock()
	for _, session := range s.sessions {
		session.Conn.Close()
	}
	s.sessions = make(map[uint32]*Session)
	s.sessionsMu.Unlock()

	// Wait for goroutines
	s.wg.Wait()

	s.logger.Info("Server stopped")
	return nil
}

// acceptLoop accepts new TCP connections
func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Set deadline for accept
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

		// Handle connection
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles a TCP connection
func (s *Server) handleConnection(conn *net.TCPConn) {
	defer s.wg.Done()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	s.logger.Info("New connection from %s", remoteAddr)

	// Read packets until connection closes
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Set read deadline
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// Read ENIP header (24 bytes)
		header := make([]byte, 24)
		if _, err := io.ReadFull(conn, header); err != nil {
			if err == io.EOF {
				s.logger.Info("Connection closed by client: %s", remoteAddr)
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			s.logger.Error("Read header error from %s: %v", remoteAddr, err)
			return
		}

		// Decode header
		encap, err := cipclient.DecodeENIP(header)
		if err != nil {
			s.logger.Error("Decode header error from %s: %v", remoteAddr, err)
			continue
		}

		// Read data if present
		if encap.Length > 0 {
			data := make([]byte, encap.Length)
			if _, err := io.ReadFull(conn, data); err != nil {
				s.logger.Error("Read data error from %s: %v", remoteAddr, err)
				continue
			}
			encap.Data = data
		}

		// Handle ENIP command
		resp := s.handleENIPCommand(encap, remoteAddr)

		// Send response
		if resp != nil {
			if _, err := conn.Write(resp); err != nil {
				s.logger.Error("Write response error to %s: %v", remoteAddr, err)
				return
			}
		}

		// Update session activity
		if encap.SessionID != 0 {
			s.sessionsMu.RLock()
			session, ok := s.sessions[encap.SessionID]
			s.sessionsMu.RUnlock()
			if ok {
				session.mu.Lock()
				session.LastActivity = time.Now()
				session.mu.Unlock()
			}
		}
	}
}

// handleENIPCommand handles an ENIP command and returns a response packet
func (s *Server) handleENIPCommand(encap cipclient.ENIPEncapsulation, remoteAddr string) []byte {
	switch encap.Command {
	case cipclient.ENIPCommandRegisterSession:
		return s.handleRegisterSession(encap)

	case cipclient.ENIPCommandUnregisterSession:
		return s.handleUnregisterSession(encap)

	case cipclient.ENIPCommandSendRRData:
		return s.handleSendRRData(encap, remoteAddr)

	case cipclient.ENIPCommandSendUnitData:
		return s.handleSendUnitData(encap, remoteAddr)

	default:
		s.logger.Error("Unsupported ENIP command 0x%04X from %s", encap.Command, remoteAddr)
		return s.buildErrorResponse(encap, cipclient.ENIPStatusUnsupportedCommand)
	}
}

// handleRegisterSession handles a RegisterSession request
func (s *Server) handleRegisterSession(encap cipclient.ENIPEncapsulation) []byte {
	// Validate request
	if len(encap.Data) < 4 {
		return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidLength)
	}

	// Generate session ID
	s.sessionsMu.Lock()
	sessionID := s.nextSessionID
	s.nextSessionID++
	s.sessionsMu.Unlock()

	// Create session
	session := &Session{
		ID:           sessionID,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}

	s.sessionsMu.Lock()
	s.sessions[sessionID] = session
	s.sessionsMu.Unlock()

	s.logger.Info("Registered session %d", sessionID)

	// Build response
	response := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandRegisterSession,
		Length:        4,
		SessionID:     sessionID,
		Status:        cipclient.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          encap.Data, // Echo back protocol version and flags
	}

	return cipclient.EncodeENIP(response)
}

// handleUnregisterSession handles an UnregisterSession request
func (s *Server) handleUnregisterSession(encap cipclient.ENIPEncapsulation) []byte {
	s.sessionsMu.Lock()
	delete(s.sessions, encap.SessionID)
	s.sessionsMu.Unlock()

	s.logger.Info("Unregistered session %d", encap.SessionID)

	// Build response
	response := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandUnregisterSession,
		Length:         0,
		SessionID:      encap.SessionID,
		Status:         cipclient.ENIPStatusSuccess,
		SenderContext:  encap.SenderContext,
		Options:        0,
		Data:           nil,
	}

	return cipclient.EncodeENIP(response)
}

// handleSendRRData handles a SendRRData request (UCMM)
func (s *Server) handleSendRRData(encap cipclient.ENIPEncapsulation, remoteAddr string) []byte {
	// Verify session exists
	s.sessionsMu.RLock()
	_, ok := s.sessions[encap.SessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		s.logger.Error("SendRRData with invalid session %d from %s", encap.SessionID, remoteAddr)
		return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidSessionHandle)
	}

	// Parse SendRRData structure
	if len(encap.Data) < 6 {
		return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidLength)
	}

	// Skip Interface Handle (4 bytes) and Timeout (2 bytes)
	cipData := encap.Data[6:]

	// Decode CIP request
	cipReq, err := cipclient.DecodeCIPRequest(cipData)
	if err != nil {
		s.logger.Error("Decode CIP request error: %v", err)
		return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidLength)
	}

	// Handle CIP request via personality
	cipResp, err := s.personality.HandleCIPRequest(s.ctx, cipReq)
	if err != nil {
		s.logger.Error("Handle CIP request error: %v", err)
		// Return CIP error response
		cipResp = cipclient.CIPResponse{
			Service: cipReq.Service,
			Status:  0x01, // General error
			Payload: nil,
		}
	}

	// Encode CIP response
	cipRespData, err := cipclient.EncodeCIPResponse(cipResp)
	if err != nil {
		s.logger.Error("Encode CIP response error: %v", err)
		return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidLength)
	}

	// Build SendRRData response
	var sendData []byte
	sendData = binary.BigEndian.AppendUint32(sendData, 0) // Interface Handle
	sendData = binary.BigEndian.AppendUint16(sendData, 0) // Timeout
	sendData = append(sendData, cipRespData...)

	response := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandSendRRData,
		Length:        uint16(len(sendData)),
		SessionID:     encap.SessionID,
		Status:        cipclient.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          sendData,
	}

	return cipclient.EncodeENIP(response)
}

// handleSendUnitData handles a SendUnitData request (connected messaging)
func (s *Server) handleSendUnitData(encap cipclient.ENIPEncapsulation, remoteAddr string) []byte {
	// Verify session exists
	s.sessionsMu.RLock()
	_, ok := s.sessions[encap.SessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		s.logger.Error("SendUnitData with invalid session %d from %s", encap.SessionID, remoteAddr)
		return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidSessionHandle)
	}

	// Parse SendUnitData structure
	if len(encap.Data) < 4 {
		return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidLength)
	}

	// Connection ID (4 bytes)
	connectionID := binary.BigEndian.Uint32(encap.Data[0:4])
	cipData := encap.Data[4:]

	s.logger.Debug("SendUnitData: connection %d, data length %d", connectionID, len(cipData))

	// For now, just acknowledge (I/O handling can be extended later)
	var sendData []byte
	sendData = binary.BigEndian.AppendUint32(sendData, connectionID)
	// Echo back data or generate response based on personality

	response := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandSendUnitData,
		Length:        uint16(len(sendData)),
		SessionID:     encap.SessionID,
		Status:        cipclient.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          sendData,
	}

	return cipclient.EncodeENIP(response)
}

// handleUDP handles UDP I/O packets
func (s *Server) handleUDP() {
	defer s.wg.Done()

	buffer := make([]byte, 1500)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		s.udpListener.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := s.udpListener.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if s.ctx.Err() != nil {
				return
			}
			s.logger.Error("UDP read error: %v", err)
			continue
		}

		s.logger.Debug("UDP I/O packet from %s: %d bytes", addr.String(), n)
		// Handle UDP I/O packet (can be extended based on personality)
	}
}

// buildErrorResponse builds an error response
func (s *Server) buildErrorResponse(encap cipclient.ENIPEncapsulation, status uint32) []byte {
	response := cipclient.ENIPEncapsulation{
		Command:       encap.Command,
		Length:        0,
		SessionID:     encap.SessionID,
		Status:        status,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          nil,
	}

	return cipclient.EncodeENIP(response)
}
