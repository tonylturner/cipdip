package server

// EtherNet/IP CIP Server implementation

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
)

// Server represents an EtherNet/IP CIP server
type Server struct {
	config         *config.ServerConfig
	logger         *logging.Logger
	tcpListener    *net.TCPListener
	udpListener    *net.UDPConn
	sessions       map[uint32]*Session
	sessionsMu     sync.RWMutex
	connections    map[uint32]*ConnectionState
	connectionsMu  sync.RWMutex
	nextSessionID  uint32
	personality    Personality
	genericStore   *genericAttributeStore
	profileClasses map[uint16]struct{}
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
}

// Session represents an active EtherNet/IP session
type Session struct {
	ID           uint32
	Conn         *net.TCPConn
	CreatedAt    time.Time
	LastActivity time.Time
	mu           sync.Mutex
}

// ConnectionState tracks ForwardOpen connection state.
type ConnectionState struct {
	ID           uint32
	SessionID    uint32
	CreatedAt    time.Time
	LastActivity time.Time
	RemoteAddr   string
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
		config:         cfg,
		logger:         logger,
		sessions:       make(map[uint32]*Session),
		connections:    make(map[uint32]*ConnectionState),
		nextSessionID:  1,
		personality:    personality,
		genericStore:   newGenericAttributeStore(),
		profileClasses: buildProfileClassSet(cfg.CIPProfiles, cfg.CIPProfileClasses),
		ctx:            ctx,
		cancel:         cancel,
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
	fmt.Printf("[SERVER] TCP server listening on %s:%d\n", s.config.Server.ListenIP, s.config.Server.TCPPort)

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
		fmt.Printf("[SERVER] UDP I/O server listening on %s:%d\n", s.config.Server.ListenIP, s.config.Server.UDPIOPort)

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
	// Cancel context to signal all goroutines to stop
	s.cancel()

	// Close TCP listener (this will cause acceptLoop to exit)
	if s.tcpListener != nil {
		s.tcpListener.Close()
	}

	// Close UDP listener
	if s.udpListener != nil {
		s.udpListener.Close()
	}

	// Close all active connections
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

	// Wait for all goroutines to finish
	s.wg.Wait()

	s.logger.Info("Server stopped")
	fmt.Printf("[SERVER] Server stopped gracefully\n")
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
	defer func() {
		// Remove session from map when connection closes
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
				fmt.Printf("[SERVER] Connection closed by client: %s\n", remoteAddr)
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

		// Update session activity and associate connection with session
		if encap.SessionID != 0 {
			s.sessionsMu.Lock()
			session, ok := s.sessions[encap.SessionID]
			if ok && session != nil {
				// Associate connection with session if not already set
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

	// Find the connection for this session
	// Note: We need to associate the session with the connection
	// For now, we'll store sessions without Conn, and handle connection cleanup separately
	session := &Session{
		ID:           sessionID,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		// Conn will be set when we handle the connection
		// For RegisterSession, we don't have the connection yet
	}

	s.sessionsMu.Lock()
	s.sessions[sessionID] = session
	s.sessionsMu.Unlock()

	s.logger.Info("Registered session %d", sessionID)
	fmt.Printf("[SERVER] Registered session %d\n", sessionID)

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
	fmt.Printf("[SERVER] Unregistered session %d\n", encap.SessionID)

	// Build response
	response := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandUnregisterSession,
		Length:        0,
		SessionID:     encap.SessionID,
		Status:        cipclient.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          nil,
	}

	return cipclient.EncodeENIP(response)
}

// handleSendRRData handles a SendRRData request (UCMM)
func (s *Server) handleSendRRData(encap cipclient.ENIPEncapsulation, remoteAddr string) []byte {
	// Verify session exists
	s.sessionsMu.RLock()
	session, ok := s.sessions[encap.SessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		s.logger.Error("SendRRData with invalid session %d from %s", encap.SessionID, remoteAddr)
		return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidSessionHandle)
	}

	// Update session activity
	if session != nil {
		session.mu.Lock()
		session.LastActivity = time.Now()
		session.mu.Unlock()
	}

	// Parse SendRRData structure
	if len(encap.Data) < 6 {
		return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidLength)
	}

	cipData, err := cipclient.ParseSendRRDataRequest(encap.Data)
	if err != nil {
		s.logger.Error("Parse SendRRData error: %v", err)
		return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidLength)
	}

	// Check if this is a ForwardOpen request (service 0x54)
	if len(cipData) > 0 && cipclient.CIPServiceCode(cipData[0]) == cipclient.CIPServiceForwardOpen {
		// Handle ForwardOpen specially (it doesn't follow standard CIP request format)
		return s.handleForwardOpen(encap, cipData, remoteAddr)
	}

	// Check if this is a ForwardClose request (service 0x4E)
	if len(cipData) > 0 && cipclient.CIPServiceCode(cipData[0]) == cipclient.CIPServiceForwardClose {
		// Handle ForwardClose specially (it doesn't follow standard CIP request format)
		return s.handleForwardClose(encap, cipData)
	}

	// Decode CIP request
	cipReq, err := cipclient.DecodeCIPRequest(cipData)
	if err != nil {
		s.logger.Error("Decode CIP request error: %v", err)
		return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidLength)
	}

	// Log incoming request
	fmt.Printf("[SERVER] Received CIP request: service=0x%02X class=0x%04X instance=0x%04X attribute=0x%02X\n",
		uint8(cipReq.Service), cipReq.Path.Class, cipReq.Path.Instance, cipReq.Path.Attribute)

	if cipReq.Service == cipclient.CIPServiceUnconnectedSend {
		return s.handleUnconnectedSend(encap, cipReq)
	}
	if cipReq.Service == cipclient.CIPServiceMultipleService {
		return s.handleMultipleService(encap, cipReq)
	}

	if identityResp, ok := s.handleIdentityRequest(cipReq); ok {
		cipRespData, err := cipclient.EncodeCIPResponse(identityResp)
		if err != nil {
			s.logger.Error("Encode CIP response error: %v", err)
			return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidLength)
		}
		return s.buildCIPResponse(encap, cipRespData)
	}

	if genericResp, ok := s.handleGenericRequest(cipReq); ok {
		cipRespData, err := cipclient.EncodeCIPResponse(genericResp)
		if err != nil {
			s.logger.Error("Encode CIP response error: %v", err)
			return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidLength)
		}
		return s.buildCIPResponse(encap, cipRespData)
	}

	// Handle CIP request via personality
	cipResp, err := s.personality.HandleCIPRequest(s.ctx, cipReq)
	if err != nil {
		s.logger.Error("Handle CIP request error: %v", err)
		fmt.Printf("[SERVER] Request failed: %v\n", err)
		// Return CIP error response
		cipResp = cipclient.CIPResponse{
			Service: cipReq.Service,
			Status:  0x01, // General error
			Payload: nil,
		}
	} else {
		// Log successful response
		payloadSize := 0
		if cipResp.Payload != nil {
			payloadSize = len(cipResp.Payload)
		}
		fmt.Printf("[SERVER] Responded: service=0x%02X status=0x%02X payload=%d bytes\n",
			uint8(cipResp.Service), cipResp.Status, payloadSize)
	}

	// Encode CIP response
	cipRespData, err := cipclient.EncodeCIPResponse(cipResp)
	if err != nil {
		s.logger.Error("Encode CIP response error: %v", err)
		return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidLength)
	}

	return s.buildCIPResponse(encap, cipRespData)
}

// handleForwardOpen handles a ForwardOpen request (I/O connection establishment)
func (s *Server) handleForwardOpen(encap cipclient.ENIPEncapsulation, cipData []byte, remoteAddr string) []byte {
	fmt.Printf("[SERVER] Received ForwardOpen request\n")

	// ForwardOpen response structure:
	// - General status (1 byte) = 0x00 (success)
	// - Additional status size (1 byte) = 0x00
	// - O->T connection ID (4 bytes)
	// - T->O connection ID (4 bytes)
	// - Connection serial number (2 bytes) = 0x0000
	// - Originator vendor ID (2 bytes) = 0x0000
	// - Originator serial number (4 bytes) = 0x00000000
	// - Connection timeout multiplier (1 byte) = 0x01

	// Generate connection IDs (simple incrementing for now)
	s.sessionsMu.Lock()
	oToTConnID := uint32(0x10000000 + s.nextSessionID*2)
	tToOConnID := uint32(0x10000000 + s.nextSessionID*2 + 1)
	s.nextSessionID++
	s.sessionsMu.Unlock()

	// Build ForwardOpen response
	order := cipclient.CurrentProtocolProfile().CIPByteOrder
	var respData []byte
	respData = append(respData, 0x00) // General status (success)
	respData = append(respData, 0x00) // Additional status size
	respData = append(respData, make([]byte, 4)...)
	order.PutUint32(respData[len(respData)-4:], oToTConnID) // O->T connection ID
	respData = append(respData, make([]byte, 4)...)
	order.PutUint32(respData[len(respData)-4:], tToOConnID) // T->O connection ID
	respData = append(respData, make([]byte, 2)...)
	order.PutUint16(respData[len(respData)-2:], 0x0000) // Connection serial number
	respData = append(respData, make([]byte, 2)...)
	order.PutUint16(respData[len(respData)-2:], 0x0000) // Originator vendor ID
	respData = append(respData, make([]byte, 4)...)
	order.PutUint32(respData[len(respData)-4:], 0x00000000) // Originator serial number
	respData = append(respData, 0x01)                       // Connection timeout multiplier

	sendData := cipclient.BuildSendRRDataPayload(respData)

	response := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandSendRRData,
		Length:        uint16(len(sendData)),
		SessionID:     encap.SessionID,
		Status:        cipclient.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          sendData,
	}

	s.trackConnection(oToTConnID, encap.SessionID, remoteAddr)
	s.trackConnection(tToOConnID, encap.SessionID, remoteAddr)

	fmt.Printf("[SERVER] ForwardOpen response: O->T=0x%08X T->O=0x%08X\n", oToTConnID, tToOConnID)

	return cipclient.EncodeENIP(response)
}

// handleForwardClose handles a ForwardClose request (I/O connection teardown)
func (s *Server) handleForwardClose(encap cipclient.ENIPEncapsulation, cipData []byte) []byte {
	fmt.Printf("[SERVER] Received ForwardClose request\n")

	if connID := parseForwardCloseConnectionID(cipData); connID != 0 {
		s.untrackConnection(connID)
	}

	// ForwardClose response structure:
	// - General status (1 byte) = 0x00 (success)
	// - Additional status size (1 byte) = 0x00

	// Build ForwardClose response
	var respData []byte
	respData = append(respData, 0x00) // General status (success)
	respData = append(respData, 0x00) // Additional status size

	sendData := cipclient.BuildSendRRDataPayload(respData)

	response := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandSendRRData,
		Length:        uint16(len(sendData)),
		SessionID:     encap.SessionID,
		Status:        cipclient.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          sendData,
	}

	fmt.Printf("[SERVER] ForwardClose response: success\n")

	return cipclient.EncodeENIP(response)
}

func (s *Server) handleUnconnectedSend(encap cipclient.ENIPEncapsulation, cipReq cipclient.CIPRequest) []byte {
	embeddedReqData, _, ok := cipclient.ParseUnconnectedSendRequestPayload(cipReq.Payload)
	if !ok {
		cipResp := cipclient.CIPResponse{Service: cipReq.Service, Status: 0x13, Path: cipReq.Path}
		cipRespData, _ := cipclient.EncodeCIPResponse(cipResp)
		return s.buildCIPResponse(encap, cipRespData)
	}

	embeddedReq, err := cipclient.DecodeCIPRequest(embeddedReqData)
	if err != nil {
		cipResp := cipclient.CIPResponse{Service: cipReq.Service, Status: 0x01, Path: cipReq.Path}
		cipRespData, _ := cipclient.EncodeCIPResponse(cipResp)
		return s.buildCIPResponse(encap, cipRespData)
	}

	embeddedResp, ok := s.handleIdentityRequest(embeddedReq)
	if !ok {
		embeddedResp = s.handleEmbeddedRequest(embeddedReq)
	}
	embeddedRespData, err := cipclient.EncodeCIPResponse(embeddedResp)
	if err != nil {
		cipResp := cipclient.CIPResponse{Service: cipReq.Service, Status: 0x01, Path: cipReq.Path}
		cipRespData, _ := cipclient.EncodeCIPResponse(cipResp)
		return s.buildCIPResponse(encap, cipRespData)
	}

	payload := cipclient.BuildUnconnectedSendResponsePayload(embeddedRespData)
	cipResp := cipclient.CIPResponse{
		Service: cipReq.Service,
		Status:  0x00,
		Path:    cipReq.Path,
		Payload: payload,
	}
	cipRespData, err := cipclient.EncodeCIPResponse(cipResp)
	if err != nil {
		return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidLength)
	}
	return s.buildCIPResponse(encap, cipRespData)
}

func (s *Server) handleMultipleService(encap cipclient.ENIPEncapsulation, cipReq cipclient.CIPRequest) []byte {
	if cipReq.Path.Class != cipclient.CIPClassMessageRouter || cipReq.Path.Instance != 0x0001 {
		cipResp := cipclient.CIPResponse{Service: cipReq.Service, Status: 0x05, Path: cipReq.Path}
		cipRespData, _ := cipclient.EncodeCIPResponse(cipResp)
		return s.buildCIPResponse(encap, cipRespData)
	}

	embeddedReqs, err := cipclient.ParseMultipleServiceRequestPayload(cipReq.Payload)
	if err != nil {
		cipResp := cipclient.CIPResponse{Service: cipReq.Service, Status: 0x13, Path: cipReq.Path}
		cipRespData, _ := cipclient.EncodeCIPResponse(cipResp)
		return s.buildCIPResponse(encap, cipRespData)
	}

	embeddedResps := make([]cipclient.CIPResponse, 0, len(embeddedReqs))
	for _, embeddedReq := range embeddedReqs {
		embeddedResps = append(embeddedResps, s.handleEmbeddedRequest(embeddedReq))
	}

	payload, err := cipclient.BuildMultipleServiceResponsePayload(embeddedResps)
	if err != nil {
		cipResp := cipclient.CIPResponse{Service: cipReq.Service, Status: 0x01, Path: cipReq.Path}
		cipRespData, _ := cipclient.EncodeCIPResponse(cipResp)
		return s.buildCIPResponse(encap, cipRespData)
	}

	cipResp := cipclient.CIPResponse{
		Service: cipReq.Service,
		Status:  0x00,
		Path:    cipReq.Path,
		Payload: payload,
	}
	cipRespData, err := cipclient.EncodeCIPResponse(cipResp)
	if err != nil {
		return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidLength)
	}
	return s.buildCIPResponse(encap, cipRespData)
}

func (s *Server) handleEmbeddedRequest(req cipclient.CIPRequest) cipclient.CIPResponse {
	if identityResp, ok := s.handleIdentityRequest(req); ok {
		return identityResp
	}
	if genericResp, ok := s.handleGenericRequest(req); ok {
		return genericResp
	}
	resp, err := s.personality.HandleCIPRequest(s.ctx, req)
	if err != nil {
		return cipclient.CIPResponse{Service: req.Service, Status: 0x01, Path: req.Path}
	}
	return resp
}

func (s *Server) buildCIPResponse(encap cipclient.ENIPEncapsulation, cipRespData []byte) []byte {
	sendData := cipclient.BuildSendRRDataPayload(cipRespData)
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

func (s *Server) handleIdentityRequest(req cipclient.CIPRequest) (cipclient.CIPResponse, bool) {
	if req.Path.Class != 0x0001 {
		return cipclient.CIPResponse{}, false
	}
	if req.Path.Instance != 0x0001 {
		return cipclient.CIPResponse{
			Service: req.Service,
			Status:  0x05, // Path destination unknown
			Path:    req.Path,
		}, true
	}

	switch req.Service {
	case cipclient.CIPServiceGetAttributeSingle:
		payload, ok := s.identityAttributePayload(req.Path.Attribute)
		if !ok {
			return cipclient.CIPResponse{
				Service: req.Service,
				Status:  0x14, // Attribute not supported
				Path:    req.Path,
			}, true
		}
		return cipclient.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
			Payload: payload,
		}, true
	case cipclient.CIPServiceGetAttributeAll:
		payload := s.identityAllPayload()
		return cipclient.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
			Payload: payload,
		}, true
	default:
		return cipclient.CIPResponse{
			Service: req.Service,
			Status:  0x08, // Service not supported
			Path:    req.Path,
		}, true
	}
}

func (s *Server) identityAttributePayload(attribute uint16) ([]byte, bool) {
	vendorID, deviceType, productCode, revMajor, revMinor, status, serial, productName := s.identityValues()
	order := cipclient.CurrentProtocolProfile().CIPByteOrder

	switch attribute {
	case 1:
		payload := make([]byte, 2)
		order.PutUint16(payload, vendorID)
		return payload, true
	case 2:
		payload := make([]byte, 2)
		order.PutUint16(payload, deviceType)
		return payload, true
	case 3:
		payload := make([]byte, 2)
		order.PutUint16(payload, productCode)
		return payload, true
	case 4:
		return []byte{revMajor, revMinor}, true
	case 5:
		payload := make([]byte, 2)
		order.PutUint16(payload, status)
		return payload, true
	case 6:
		payload := make([]byte, 4)
		order.PutUint32(payload, serial)
		return payload, true
	case 7:
		return encodeShortString(productName), true
	default:
		return nil, false
	}
}

func (s *Server) identityAllPayload() []byte {
	vendorID, deviceType, productCode, revMajor, revMinor, status, serial, productName := s.identityValues()
	order := cipclient.CurrentProtocolProfile().CIPByteOrder

	payload := make([]byte, 0, 16)
	buf2 := make([]byte, 2)
	buf4 := make([]byte, 4)

	order.PutUint16(buf2, vendorID)
	payload = append(payload, buf2...)
	order.PutUint16(buf2, deviceType)
	payload = append(payload, buf2...)
	order.PutUint16(buf2, productCode)
	payload = append(payload, buf2...)
	payload = append(payload, revMajor, revMinor)
	order.PutUint16(buf2, status)
	payload = append(payload, buf2...)
	order.PutUint32(buf4, serial)
	payload = append(payload, buf4...)
	payload = append(payload, encodeShortString(productName)...)

	return payload
}

func (s *Server) identityValues() (uint16, uint16, uint16, uint8, uint8, uint16, uint32, string) {
	cfg := s.config.Server
	vendorID := cfg.IdentityVendorID
	deviceType := cfg.IdentityDeviceType
	productCode := cfg.IdentityProductCode
	revMajor := cfg.IdentityRevMajor
	revMinor := cfg.IdentityRevMinor
	status := cfg.IdentityStatus
	serial := cfg.IdentitySerial
	productName := cfg.IdentityProductName
	if productName == "" {
		if cfg.Name != "" {
			productName = cfg.Name
		} else {
			productName = "CIPDIP"
		}
	}
	if revMajor == 0 && revMinor == 0 {
		revMajor = 1
	}
	return vendorID, deviceType, productCode, revMajor, revMinor, status, serial, productName
}

func encodeShortString(value string) []byte {
	data := []byte(value)
	if len(data) > 255 {
		data = data[:255]
	}
	payload := make([]byte, 1+len(data))
	payload[0] = byte(len(data))
	copy(payload[1:], data)
	return payload
}

type genericAttributeStore struct {
	mu     sync.RWMutex
	values map[string][]byte
}

func newGenericAttributeStore() *genericAttributeStore {
	return &genericAttributeStore{
		values: make(map[string][]byte),
	}
}

func (s *genericAttributeStore) get(class, instance, attribute uint16) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := genericKey(class, instance, attribute)
	value, ok := s.values[key]
	if !ok {
		return nil, false
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out, true
}

func (s *genericAttributeStore) set(class, instance, attribute uint16, value []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := genericKey(class, instance, attribute)
	out := make([]byte, len(value))
	copy(out, value)
	s.values[key] = out
}

func (s *genericAttributeStore) listAttributes(class, instance uint16) map[uint16][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[uint16][]byte)
	for key, value := range s.values {
		parsedClass, parsedInstance, parsedAttr, ok := parseGenericKey(key)
		if !ok {
			continue
		}
		if parsedClass == class && parsedInstance == instance {
			copyVal := make([]byte, len(value))
			copy(copyVal, value)
			out[parsedAttr] = copyVal
		}
	}
	return out
}

func (s *genericAttributeStore) clearInstance(class, instance uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key := range s.values {
		parsedClass, parsedInstance, _, ok := parseGenericKey(key)
		if !ok {
			continue
		}
		if parsedClass == class && parsedInstance == instance {
			delete(s.values, key)
		}
	}
}

func genericKey(class, instance, attribute uint16) string {
	return fmt.Sprintf("%04X:%04X:%04X", class, instance, attribute)
}

func parseGenericKey(key string) (uint16, uint16, uint16, bool) {
	var class, instance, attribute uint16
	_, err := fmt.Sscanf(key, "%04X:%04X:%04X", &class, &instance, &attribute)
	return class, instance, attribute, err == nil
}

func (s *Server) handleGenericRequest(req cipclient.CIPRequest) (cipclient.CIPResponse, bool) {
	if s.personality != nil && s.personality.GetName() == "adapter" && req.Path.Class == cipclient.CIPClassAssembly {
		return cipclient.CIPResponse{}, false
	}
	if !s.isGenericClass(req.Path.Class) {
		return cipclient.CIPResponse{}, false
	}

	switch req.Service {
	case cipclient.CIPServiceExecutePCCC,
		cipclient.CIPServiceReadTag,
		cipclient.CIPServiceWriteTag,
		cipclient.CIPServiceReadModifyWrite,
		cipclient.CIPServiceUploadTransfer,
		cipclient.CIPServiceDownloadTransfer,
		cipclient.CIPServiceClearFile:
		if isEnergyBaseClass(req.Path.Class) && (req.Service == cipclient.CIPServiceExecutePCCC || req.Service == cipclient.CIPServiceReadTag) {
			return cipclient.CIPResponse{
				Service: req.Service,
				Status:  0x00,
				Path:    req.Path,
			}, true
		}
		if isFileObjectClass(req.Path.Class) || isSymbolicClass(req.Path.Class) || isModbusClass(req.Path.Class) || isMotionAxisClass(req.Path.Class) || isSafetyClass(req.Path.Class) {
			return cipclient.CIPResponse{
				Service: req.Service,
				Status:  0x00,
				Path:    req.Path,
			}, true
		}
		return cipclient.CIPResponse{
			Service: req.Service,
			Status:  0x08,
			Path:    req.Path,
		}, true

	case cipclient.CIPServiceGetAttributeSingle:
		payload, ok := s.genericStore.get(req.Path.Class, req.Path.Instance, req.Path.Attribute)
		if !ok {
			payload = []byte{0x00}
		}
		return cipclient.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
			Payload: payload,
		}, true

	case cipclient.CIPServiceSetAttributeSingle:
		s.genericStore.set(req.Path.Class, req.Path.Instance, req.Path.Attribute, req.Payload)
		return cipclient.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
		}, true

	case cipclient.CIPServiceGetAttributeAll:
		attrs := s.genericStore.listAttributes(req.Path.Class, req.Path.Instance)
		payload := flattenAttributes(attrs)
		return cipclient.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
			Payload: payload,
		}, true
	case cipclient.CIPServiceSetAttributeList:
		return cipclient.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
		}, true

	case cipclient.CIPServiceGetAttributeList:
		payload, ok := buildAttributeListResponse(req, s.genericStore)
		status := uint8(0x00)
		if !ok {
			status = 0x13
		}
		return cipclient.CIPResponse{
			Service: req.Service,
			Status:  status,
			Path:    req.Path,
			Payload: payload,
		}, true

	case cipclient.CIPServiceReset:
		s.genericStore.clearInstance(req.Path.Class, req.Path.Instance)
		return cipclient.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
		}, true
	case cipclient.CIPServiceStart,
		cipclient.CIPServiceStop,
		cipclient.CIPServiceCreate,
		cipclient.CIPServiceDelete,
		cipclient.CIPServiceRestore,
		cipclient.CIPServiceSave,
		cipclient.CIPServiceGetMember,
		cipclient.CIPServiceSetMember,
		cipclient.CIPServiceInsertMember,
		cipclient.CIPServiceRemoveMember,
		cipclient.CIPServiceReadTagFragmented,
		cipclient.CIPServiceForwardOpen:
		return cipclient.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
		}, true
	default:
		return cipclient.CIPResponse{
			Service: req.Service,
			Status:  0x08,
			Path:    req.Path,
		}, true
	}
}

func (s *Server) isGenericClass(class uint16) bool {
	if _, ok := s.profileClasses[class]; ok {
		return true
	}
	switch class {
	case 0x0066, 0x00F4, 0x00F5, 0x0100, 0x00F6, 0x3700, 0x0002, 0x0064, 0x00AC, 0x008E, 0x1A00, 0x0004, 0x0005, 0x0006:
		return true
	case cipclient.CIPClassFileObject,
		cipclient.CIPClassSymbolObject,
		cipclient.CIPClassTemplateObject,
		cipclient.CIPClassEventLog,
		cipclient.CIPClassTimeSync,
		cipclient.CIPClassModbus:
		return true
	default:
		return false
	}
}

func isEnergyBaseClass(class uint16) bool {
	return class == cipclient.CIPClassEnergyBase
}

func isFileObjectClass(class uint16) bool {
	return class == cipclient.CIPClassFileObject
}

func isSymbolicClass(class uint16) bool {
	return class == cipclient.CIPClassSymbolObject || class == cipclient.CIPClassTemplateObject
}

func isModbusClass(class uint16) bool {
	return class == cipclient.CIPClassModbus
}

func isMotionAxisClass(class uint16) bool {
	return class == cipclient.CIPClassMotionAxis
}

func isSafetyClass(class uint16) bool {
	return class == cipclient.CIPClassSafetySupervisor || class == cipclient.CIPClassSafetyValidator
}

func flattenAttributes(attrs map[uint16][]byte) []byte {
	if len(attrs) == 0 {
		return nil
	}
	keys := make([]uint16, 0, len(attrs))
	for key := range attrs {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	payload := make([]byte, 0)
	for _, key := range keys {
		payload = append(payload, attrs[key]...)
	}
	return payload
}

func buildAttributeListResponse(req cipclient.CIPRequest, store *genericAttributeStore) ([]byte, bool) {
	if len(req.Payload) < 2 {
		return nil, false
	}
	count := int(binary.LittleEndian.Uint16(req.Payload[:2]))
	offset := 2
	order := cipclient.CurrentProtocolProfile().CIPByteOrder
	payload := make([]byte, 0)
	for i := 0; i < count; i++ {
		if len(req.Payload) < offset+2 {
			return payload, false
		}
		attrID := order.Uint16(req.Payload[offset : offset+2])
		offset += 2

		value, ok := store.get(req.Path.Class, req.Path.Instance, attrID)
		payload = append(payload, 0x00, 0x00)
		order.PutUint16(payload[len(payload)-2:], attrID)

		status := byte(0x00)
		if !ok {
			status = 0x14
		}
		payload = append(payload, status, 0x00)
		if ok {
			payload = append(payload, value...)
		}
	}
	return payload, true
}

func buildProfileClassSet(profiles []string, overrides map[string][]uint16) map[uint16]struct{} {
	classList := cipclient.ResolveCIPProfileClasses(cipclient.NormalizeCIPProfiles(profiles), overrides)
	out := make(map[uint16]struct{}, len(classList))
	for _, classID := range classList {
		out[classID] = struct{}{}
	}
	return out
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

	connectionID, cipData, err := cipclient.ParseSendUnitDataRequest(encap.Data)
	if err != nil {
		s.logger.Error("Parse SendUnitData error: %v", err)
		return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidLength)
	}

	if !s.isConnectionActive(connectionID, encap.SessionID) {
		s.logger.Error("SendUnitData for inactive connection %d from %s", connectionID, remoteAddr)
		return s.buildErrorResponse(encap, cipclient.ENIPStatusInvalidSessionHandle)
	}
	s.touchConnection(connectionID)

	s.logger.Debug("SendUnitData: connection %d, data length %d", connectionID, len(cipData))
	fmt.Printf("[SERVER] Received I/O data: connection=0x%08X size=%d bytes\n", connectionID, len(cipData))

	sendData := cipclient.BuildSendUnitDataPayload(connectionID, cipData)

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

		// Parse ENIP packet
		if n < 24 {
			s.logger.Debug("UDP packet too short: %d bytes", n)
			continue
		}

		// Decode ENIP header
		encap, err := cipclient.DecodeENIP(buffer[:n])
		if err != nil {
			s.logger.Debug("UDP decode error from %s: %v", addr.String(), err)
			continue
		}

		// Handle SendUnitData on UDP (I/O data)
		if encap.Command == cipclient.ENIPCommandSendUnitData {
			resp := s.handleSendUnitData(encap, addr.String())
			if resp != nil {
				// Send response back to client
				if _, err := s.udpListener.WriteToUDP(resp, addr); err != nil {
					s.logger.Error("UDP write error to %s: %v", addr.String(), err)
				} else {
					s.logger.Debug("UDP I/O response sent to %s: %d bytes", addr.String(), len(resp))
				}
			}
		} else {
			s.logger.Debug("UDP I/O packet from %s: unsupported command 0x%04X", addr.String(), encap.Command)
		}
	}
}

func (s *Server) trackConnection(connID uint32, sessionID uint32, remoteAddr string) {
	if connID == 0 {
		return
	}
	state := &ConnectionState{
		ID:           connID,
		SessionID:    sessionID,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		RemoteAddr:   remoteAddr,
	}
	s.connectionsMu.Lock()
	s.connections[connID] = state
	s.connectionsMu.Unlock()
}

func (s *Server) untrackConnection(connID uint32) {
	s.connectionsMu.Lock()
	delete(s.connections, connID)
	s.connectionsMu.Unlock()
}

func (s *Server) touchConnection(connID uint32) {
	s.connectionsMu.Lock()
	if state, ok := s.connections[connID]; ok {
		state.LastActivity = time.Now()
	}
	s.connectionsMu.Unlock()
}

func (s *Server) dropConnectionsForSession(sessionID uint32) {
	s.connectionsMu.Lock()
	for connID, state := range s.connections {
		if state != nil && state.SessionID == sessionID {
			delete(s.connections, connID)
		}
	}
	s.connectionsMu.Unlock()
}

func (s *Server) isConnectionActive(connID uint32, sessionID uint32) bool {
	s.connectionsMu.RLock()
	state, ok := s.connections[connID]
	s.connectionsMu.RUnlock()
	if !ok || state == nil {
		return false
	}
	if state.SessionID != sessionID {
		return false
	}

	timeout := time.Duration(s.config.Server.ConnectionTimeoutMs) * time.Millisecond
	if timeout > 0 && time.Since(state.LastActivity) > timeout {
		s.untrackConnection(connID)
		return false
	}

	return true
}

func parseForwardCloseConnectionID(cipData []byte) uint32 {
	order := cipclient.CurrentProtocolProfile().CIPByteOrder
	for i := 0; i+5 <= len(cipData); i++ {
		if cipData[i] == 0x34 && i+5 <= len(cipData) {
			return order.Uint32(cipData[i+1 : i+5])
		}
	}
	return 0
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
