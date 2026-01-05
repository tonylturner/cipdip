package server

// EtherNet/IP CIP Server implementation

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"io"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/enip"
	"github.com/tturner/cipdip/internal/logging"
)

// Server represents an EtherNet/IP CIP server
type Server struct {
	config          *config.ServerConfig
	logger          *logging.Logger
	tcpListener     *net.TCPListener
	udpListener     *net.UDPConn
	metricsListener net.Listener
	sessions        map[uint32]*Session
	sessionsMu      sync.RWMutex
	connections     map[uint32]*ConnectionState
	connectionsMu   sync.RWMutex
	nextSessionID   uint32
	personality     Personality
	genericStore    *genericAttributeStore
	profileClasses  map[uint16]struct{}
	enipSupport     enipSupportConfig
	sessionPolicy   enipSessionPolicy
	cipPolicy       cipPolicyConfig
	faults          faultPolicy
	coalesceMu      sync.Mutex
	coalesceQueue   map[*net.TCPConn][]byte
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
}

// Session represents an active EtherNet/IP session
type Session struct {
	ID           uint32
	Conn         *net.TCPConn
	RemoteIP     string
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
	HandleCIPRequest(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, error)
	GetName() string
}

type enipSupportConfig struct {
	listIdentity    bool
	listServices    bool
	listInterfaces  bool
	registerSession bool
	sendRRData      bool
	sendUnitData    bool
}

type enipSessionPolicy struct {
	requireRegister  bool
	maxSessions      int
	maxSessionsPerIP int
	idleTimeout      time.Duration
}

type cipPolicyConfig struct {
	strictPaths        bool
	defaultStatus      uint8
	defaultExtStatus   uint16
	allowRules         []config.ServerCIPRule
	denyRules          []config.ServerCIPRule
	denyStatusOverride []config.ServerCIPStatusOverride
}

type faultPolicy struct {
	enabled bool

	latencyBase   time.Duration
	latencyJitter time.Duration
	spikeEveryN   int
	spikeDelay    time.Duration

	dropEveryN  int
	dropPct     float64
	closeEveryN int
	stallEveryN int

	chunkWrites     bool
	chunkMin        int
	chunkMax        int
	interChunkDelay time.Duration
	coalesce        bool

	mu            sync.Mutex
	responseCount int
	rng           *rand.Rand
}

type responseFaultAction struct {
	drop     bool
	delay    time.Duration
	close    bool
	chunked  bool
	coalesce bool
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
		enipSupport:    resolveENIPSupport(cfg),
		sessionPolicy:  resolveSessionPolicy(cfg),
		cipPolicy:      resolveCIPPolicy(cfg),
		faults:         resolveFaultPolicy(cfg),
		coalesceQueue:  make(map[*net.TCPConn][]byte),
		ctx:            ctx,
		cancel:         cancel,
	}

	return s, nil
}

// Start starts the server
func (s *Server) Start() error {
	if s.config.Metrics.Enable {
		if err := s.startMetricsListener(); err != nil {
			return err
		}
	}

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

// Stop stops the server
func (s *Server) Stop() error {
	// Cancel context to signal all goroutines to stop
	s.cancel()

	// Close TCP listener (this will cause acceptLoop to exit)
	if s.tcpListener != nil {
		s.tcpListener.Close()
	}

	if s.metricsListener != nil {
		s.metricsListener.Close()
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

	buffer := make([]byte, 0, 8192)
	readBuf := make([]byte, 4096)

	// Read packets until connection closes
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Set read deadline
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

// handleENIPCommand handles an ENIP command and returns a response packet
func (s *Server) handleENIPCommand(encap enip.ENIPEncapsulation, remoteAddr string) []byte {
	switch encap.Command {
	case enip.ENIPCommandRegisterSession:
		if !s.enipSupport.registerSession {
			return s.buildErrorResponse(encap, enip.ENIPStatusUnsupportedCommand)
		}
		return s.handleRegisterSession(encap, remoteAddr)

	case enip.ENIPCommandUnregisterSession:
		if !s.enipSupport.registerSession {
			return s.buildErrorResponse(encap, enip.ENIPStatusUnsupportedCommand)
		}
		return s.handleUnregisterSession(encap)

	case enip.ENIPCommandSendRRData:
		if !s.enipSupport.sendRRData {
			return s.buildErrorResponse(encap, enip.ENIPStatusUnsupportedCommand)
		}
		return s.handleSendRRData(encap, remoteAddr)

	case enip.ENIPCommandSendUnitData:
		if !s.enipSupport.sendUnitData {
			return s.buildErrorResponse(encap, enip.ENIPStatusUnsupportedCommand)
		}
		return s.handleSendUnitData(encap, remoteAddr)

	case enip.ENIPCommandListIdentity:
		if !s.enipSupport.listIdentity {
			return s.buildErrorResponse(encap, enip.ENIPStatusUnsupportedCommand)
		}
		return s.handleListIdentity(encap, remoteAddr)

	case enip.ENIPCommandListServices:
		if !s.enipSupport.listServices {
			return s.buildErrorResponse(encap, enip.ENIPStatusUnsupportedCommand)
		}
		return s.handleListServices(encap)

	case enip.ENIPCommandListInterfaces:
		if !s.enipSupport.listInterfaces {
			return s.buildErrorResponse(encap, enip.ENIPStatusUnsupportedCommand)
		}
		return s.handleListInterfaces(encap)

	default:
		s.logger.Error("Unsupported ENIP command 0x%04X from %s", encap.Command, remoteAddr)
		return s.buildErrorResponse(encap, enip.ENIPStatusUnsupportedCommand)
	}
}

// handleRegisterSession handles a RegisterSession request
func (s *Server) handleRegisterSession(encap enip.ENIPEncapsulation, remoteAddr string) []byte {
	// Validate request
	if len(encap.Data) < 4 {
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
	}

	if err := s.enforceSessionLimits(remoteAddr); err != nil {
		s.logger.Error("RegisterSession rejected from %s: %v", remoteAddr, err)
		return s.buildErrorResponse(encap, enip.ENIPStatusInsufficientMemory)
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
		RemoteIP:     remoteIP(remoteAddr),
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
	response := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandRegisterSession,
		Length:        4,
		SessionID:     sessionID,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          encap.Data, // Echo back protocol version and flags
	}

	return enip.EncodeENIP(response)
}

// handleUnregisterSession handles an UnregisterSession request
func (s *Server) handleUnregisterSession(encap enip.ENIPEncapsulation) []byte {
	s.sessionsMu.Lock()
	delete(s.sessions, encap.SessionID)
	s.sessionsMu.Unlock()

	s.logger.Info("Unregistered session %d", encap.SessionID)
	fmt.Printf("[SERVER] Unregistered session %d\n", encap.SessionID)

	// Build response
	response := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandUnregisterSession,
		Length:        0,
		SessionID:     encap.SessionID,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          nil,
	}

	return enip.EncodeENIP(response)
}

// handleSendRRData handles a SendRRData request (UCMM)
func (s *Server) handleSendRRData(encap enip.ENIPEncapsulation, remoteAddr string) []byte {
	session, ok := s.requireSession(encap.SessionID, remoteAddr)
	if !ok {
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidSessionHandle)
	}

	// Update session activity
	if session != nil {
		session.mu.Lock()
		session.LastActivity = time.Now()
		session.mu.Unlock()
	}

	cipData, err := s.parseSendRRData(encap.Data)
	if err != nil {
		s.logger.Error("Parse SendRRData error: %v", err)
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
	}

	// Check if this is a ForwardOpen request (service 0x54)
	if len(cipData) > 0 && protocol.CIPServiceCode(cipData[0]) == protocol.CIPServiceForwardOpen {
		// Handle ForwardOpen specially (it doesn't follow standard CIP request format)
		return s.handleForwardOpen(encap, cipData, remoteAddr)
	}

	// Check if this is a ForwardClose request (service 0x4E)
	if len(cipData) > 0 && protocol.CIPServiceCode(cipData[0]) == protocol.CIPServiceForwardClose {
		// Handle ForwardClose specially (it doesn't follow standard CIP request format)
		return s.handleForwardClose(encap, cipData)
	}

	// Decode CIP request
	cipReq, err := protocol.DecodeCIPRequest(cipData)
	if err != nil {
		s.logger.Error("Decode CIP request error: %v", err)
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
	}

	// Log incoming request
	fmt.Printf("[SERVER] Received CIP request: service=0x%02X class=0x%04X instance=0x%04X attribute=0x%02X\n",
		uint8(cipReq.Service), cipReq.Path.Class, cipReq.Path.Instance, cipReq.Path.Attribute)
	if s.config.Logging.IncludeHexDump {
		s.logger.LogHex("CIP Request", cipData)
	}

	if policyResp, ok := s.applyCIPPolicy(cipReq); ok {
		cipRespData, err := protocol.EncodeCIPResponse(policyResp)
		if err != nil {
			s.logger.Error("Encode CIP response error: %v", err)
			return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
		}
		return s.buildCIPResponse(encap, cipRespData)
	}

	if cipReq.Service == protocol.CIPServiceUnconnectedSend {
		return s.handleUnconnectedSend(encap, cipReq)
	}
	if cipReq.Service == protocol.CIPServiceMultipleService {
		return s.handleMultipleService(encap, cipReq)
	}

	if identityResp, ok := s.handleIdentityRequest(cipReq); ok {
		cipRespData, err := protocol.EncodeCIPResponse(identityResp)
		if err != nil {
			s.logger.Error("Encode CIP response error: %v", err)
			return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
		}
		return s.buildCIPResponse(encap, cipRespData)
	}

	if genericResp, ok := s.handleGenericRequest(cipReq); ok {
		cipRespData, err := protocol.EncodeCIPResponse(genericResp)
		if err != nil {
			s.logger.Error("Encode CIP response error: %v", err)
			return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
		}
		return s.buildCIPResponse(encap, cipRespData)
	}

	// Handle CIP request via personality
	cipResp, err := s.personality.HandleCIPRequest(s.ctx, cipReq)
	if err != nil {
		s.logger.Error("Handle CIP request error: %v", err)
		fmt.Printf("[SERVER] Request failed: %v\n", err)
		// Return CIP error response
		cipResp = protocol.CIPResponse{
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
	cipRespData, err := protocol.EncodeCIPResponse(cipResp)
	if err != nil {
		s.logger.Error("Encode CIP response error: %v", err)
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
	}

	return s.buildCIPResponse(encap, cipRespData)
}

// handleForwardOpen handles a ForwardOpen request (I/O connection establishment)
func (s *Server) handleForwardOpen(encap enip.ENIPEncapsulation, cipData []byte, remoteAddr string) []byte {
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

	sendData := enip.BuildSendRRDataPayload(respData)

	response := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandSendRRData,
		Length:        uint16(len(sendData)),
		SessionID:     encap.SessionID,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          sendData,
	}

	s.trackConnection(oToTConnID, encap.SessionID, remoteAddr)
	s.trackConnection(tToOConnID, encap.SessionID, remoteAddr)

	fmt.Printf("[SERVER] ForwardOpen response: O->T=0x%08X T->O=0x%08X\n", oToTConnID, tToOConnID)

	return enip.EncodeENIP(response)
}

// handleForwardClose handles a ForwardClose request (I/O connection teardown)
func (s *Server) handleForwardClose(encap enip.ENIPEncapsulation, cipData []byte) []byte {
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

	sendData := enip.BuildSendRRDataPayload(respData)

	response := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandSendRRData,
		Length:        uint16(len(sendData)),
		SessionID:     encap.SessionID,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          sendData,
	}

	fmt.Printf("[SERVER] ForwardClose response: success\n")

	return enip.EncodeENIP(response)
}

func (s *Server) handleUnconnectedSend(encap enip.ENIPEncapsulation, cipReq protocol.CIPRequest) []byte {
	embeddedReqData, _, ok := protocol.ParseUnconnectedSendRequestPayload(cipReq.Payload)
	if !ok {
		cipResp := protocol.CIPResponse{Service: cipReq.Service, Status: 0x13, Path: cipReq.Path}
		cipRespData, _ := protocol.EncodeCIPResponse(cipResp)
		return s.buildCIPResponse(encap, cipRespData)
	}

	embeddedReq, err := protocol.DecodeCIPRequest(embeddedReqData)
	if err != nil {
		cipResp := protocol.CIPResponse{Service: cipReq.Service, Status: 0x01, Path: cipReq.Path}
		cipRespData, _ := protocol.EncodeCIPResponse(cipResp)
		return s.buildCIPResponse(encap, cipRespData)
	}

	if policyResp, ok := s.applyCIPPolicy(embeddedReq); ok {
		embeddedRespData, err := protocol.EncodeCIPResponse(policyResp)
		if err != nil {
			cipResp := protocol.CIPResponse{Service: cipReq.Service, Status: 0x01, Path: cipReq.Path}
			cipRespData, _ := protocol.EncodeCIPResponse(cipResp)
			return s.buildCIPResponse(encap, cipRespData)
		}
		payload := cipclient.BuildUnconnectedSendResponsePayload(embeddedRespData)
		cipResp := protocol.CIPResponse{
			Service: cipReq.Service,
			Status:  0x00,
			Path:    cipReq.Path,
			Payload: payload,
		}
		cipRespData, err := protocol.EncodeCIPResponse(cipResp)
		if err != nil {
			return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
		}
		return s.buildCIPResponse(encap, cipRespData)
	}

	embeddedResp, ok := s.handleIdentityRequest(embeddedReq)
	if !ok {
		embeddedResp = s.handleEmbeddedRequest(embeddedReq)
	}
	embeddedRespData, err := protocol.EncodeCIPResponse(embeddedResp)
	if err != nil {
		cipResp := protocol.CIPResponse{Service: cipReq.Service, Status: 0x01, Path: cipReq.Path}
		cipRespData, _ := protocol.EncodeCIPResponse(cipResp)
		return s.buildCIPResponse(encap, cipRespData)
	}

	payload := cipclient.BuildUnconnectedSendResponsePayload(embeddedRespData)
	cipResp := protocol.CIPResponse{
		Service: cipReq.Service,
		Status:  0x00,
		Path:    cipReq.Path,
		Payload: payload,
	}
	cipRespData, err := protocol.EncodeCIPResponse(cipResp)
	if err != nil {
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
	}
	return s.buildCIPResponse(encap, cipRespData)
}

func (s *Server) handleMultipleService(encap enip.ENIPEncapsulation, cipReq protocol.CIPRequest) []byte {
	if cipReq.Path.Class != cipclient.CIPClassMessageRouter || cipReq.Path.Instance != 0x0001 {
		cipResp := protocol.CIPResponse{Service: cipReq.Service, Status: 0x05, Path: cipReq.Path}
		cipRespData, _ := protocol.EncodeCIPResponse(cipResp)
		return s.buildCIPResponse(encap, cipRespData)
	}

	embeddedReqs, err := cipclient.ParseMultipleServiceRequestPayload(cipReq.Payload)
	if err != nil {
		cipResp := protocol.CIPResponse{Service: cipReq.Service, Status: 0x13, Path: cipReq.Path}
		cipRespData, _ := protocol.EncodeCIPResponse(cipResp)
		return s.buildCIPResponse(encap, cipRespData)
	}

	embeddedResps := make([]protocol.CIPResponse, 0, len(embeddedReqs))
	for _, embeddedReq := range embeddedReqs {
		if policyResp, ok := s.applyCIPPolicy(embeddedReq); ok {
			embeddedResps = append(embeddedResps, policyResp)
			continue
		}
		embeddedResps = append(embeddedResps, s.handleEmbeddedRequest(embeddedReq))
	}

	payload, err := cipclient.BuildMultipleServiceResponsePayload(embeddedResps)
	if err != nil {
		cipResp := protocol.CIPResponse{Service: cipReq.Service, Status: 0x01, Path: cipReq.Path}
		cipRespData, _ := protocol.EncodeCIPResponse(cipResp)
		return s.buildCIPResponse(encap, cipRespData)
	}

	cipResp := protocol.CIPResponse{
		Service: cipReq.Service,
		Status:  0x00,
		Path:    cipReq.Path,
		Payload: payload,
	}
	cipRespData, err := protocol.EncodeCIPResponse(cipResp)
	if err != nil {
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
	}
	return s.buildCIPResponse(encap, cipRespData)
}

func (s *Server) handleEmbeddedRequest(req protocol.CIPRequest) protocol.CIPResponse {
	if identityResp, ok := s.handleIdentityRequest(req); ok {
		return identityResp
	}
	if genericResp, ok := s.handleGenericRequest(req); ok {
		return genericResp
	}
	resp, err := s.personality.HandleCIPRequest(s.ctx, req)
	if err != nil {
		return protocol.CIPResponse{Service: req.Service, Status: 0x01, Path: req.Path}
	}
	return resp
}

func (s *Server) buildCIPResponse(encap enip.ENIPEncapsulation, cipRespData []byte) []byte {
	sendData := enip.BuildSendRRDataPayload(cipRespData)
	response := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandSendRRData,
		Length:        uint16(len(sendData)),
		SessionID:     encap.SessionID,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          sendData,
	}
	return enip.EncodeENIP(response)
}

func (s *Server) handleIdentityRequest(req protocol.CIPRequest) (protocol.CIPResponse, bool) {
	if req.Path.Class != 0x0001 {
		return protocol.CIPResponse{}, false
	}
	if req.Path.Instance != 0x0001 {
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x05, // Path destination unknown
			Path:    req.Path,
		}, true
	}

	switch req.Service {
	case protocol.CIPServiceGetAttributeSingle:
		payload, ok := s.identityAttributePayload(req.Path.Attribute)
		if !ok {
			return protocol.CIPResponse{
				Service: req.Service,
				Status:  0x14, // Attribute not supported
				Path:    req.Path,
			}, true
		}
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
			Payload: payload,
		}, true
	case protocol.CIPServiceGetAttributeAll:
		payload := s.identityAllPayload()
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
			Payload: payload,
		}, true
	default:
		return protocol.CIPResponse{
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

func (s *Server) handleGenericRequest(req protocol.CIPRequest) (protocol.CIPResponse, bool) {
	if s.personality != nil && s.personality.GetName() == "adapter" && req.Path.Class == cipclient.CIPClassAssembly {
		return protocol.CIPResponse{}, false
	}
	if !s.isGenericClass(req.Path.Class) {
		return protocol.CIPResponse{}, false
	}

	switch req.Service {
	case protocol.CIPServiceExecutePCCC,
		protocol.CIPServiceReadTag,
		protocol.CIPServiceWriteTag,
		protocol.CIPServiceReadModifyWrite,
		protocol.CIPServiceUploadTransfer,
		protocol.CIPServiceDownloadTransfer,
		protocol.CIPServiceClearFile:
		if isEnergyBaseClass(req.Path.Class) && (req.Service == protocol.CIPServiceExecutePCCC || req.Service == protocol.CIPServiceReadTag) {
			return protocol.CIPResponse{
				Service: req.Service,
				Status:  0x00,
				Path:    req.Path,
			}, true
		}
		if isFileObjectClass(req.Path.Class) || isSymbolicClass(req.Path.Class) || isModbusClass(req.Path.Class) || isMotionAxisClass(req.Path.Class) || isSafetyClass(req.Path.Class) {
			return protocol.CIPResponse{
				Service: req.Service,
				Status:  0x00,
				Path:    req.Path,
			}, true
		}
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x08,
			Path:    req.Path,
		}, true

	case protocol.CIPServiceGetAttributeSingle:
		payload, ok := s.genericStore.get(req.Path.Class, req.Path.Instance, req.Path.Attribute)
		if !ok {
			payload = []byte{0x00}
		}
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
			Payload: payload,
		}, true

	case protocol.CIPServiceSetAttributeSingle:
		s.genericStore.set(req.Path.Class, req.Path.Instance, req.Path.Attribute, req.Payload)
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
		}, true

	case protocol.CIPServiceGetAttributeAll:
		attrs := s.genericStore.listAttributes(req.Path.Class, req.Path.Instance)
		payload := flattenAttributes(attrs)
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
			Payload: payload,
		}, true
	case protocol.CIPServiceSetAttributeList:
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
		}, true

	case protocol.CIPServiceGetAttributeList:
		payload, ok := buildAttributeListResponse(req, s.genericStore)
		status := uint8(0x00)
		if !ok {
			status = 0x13
		}
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  status,
			Path:    req.Path,
			Payload: payload,
		}, true

	case protocol.CIPServiceReset:
		s.genericStore.clearInstance(req.Path.Class, req.Path.Instance)
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
		}, true
	case protocol.CIPServiceStart,
		protocol.CIPServiceStop,
		protocol.CIPServiceCreate,
		protocol.CIPServiceDelete,
		protocol.CIPServiceRestore,
		protocol.CIPServiceSave,
		protocol.CIPServiceGetMember,
		protocol.CIPServiceSetMember,
		protocol.CIPServiceInsertMember,
		protocol.CIPServiceRemoveMember,
		protocol.CIPServiceReadTagFragmented,
		protocol.CIPServiceForwardOpen:
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
		}, true
	default:
		return protocol.CIPResponse{
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

func buildAttributeListResponse(req protocol.CIPRequest, store *genericAttributeStore) ([]byte, bool) {
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
func (s *Server) handleSendUnitData(encap enip.ENIPEncapsulation, remoteAddr string) []byte {
	if _, ok := s.requireSession(encap.SessionID, remoteAddr); !ok {
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidSessionHandle)
	}

	connectionID, cipData, err := s.parseSendUnitData(encap.Data)
	if err != nil {
		s.logger.Error("Parse SendUnitData error: %v", err)
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
	}

	if !s.isConnectionActive(connectionID, encap.SessionID) {
		s.logger.Error("SendUnitData for inactive connection %d from %s", connectionID, remoteAddr)
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidSessionHandle)
	}
	s.touchConnection(connectionID)

	s.logger.Debug("SendUnitData: connection %d, data length %d", connectionID, len(cipData))
	fmt.Printf("[SERVER] Received I/O data: connection=0x%08X size=%d bytes\n", connectionID, len(cipData))

	sendData := enip.BuildSendUnitDataPayload(connectionID, cipData)

	response := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandSendUnitData,
		Length:        uint16(len(sendData)),
		SessionID:     encap.SessionID,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          sendData,
	}

	return enip.EncodeENIP(response)
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
		encap, err := enip.DecodeENIP(buffer[:n])
		if err != nil {
			s.logger.Debug("UDP decode error from %s: %v", addr.String(), err)
			continue
		}

		// Handle SendUnitData on UDP (I/O data)
		if encap.Command == enip.ENIPCommandSendUnitData && s.enipSupport.sendUnitData {
			resp := s.handleSendUnitData(encap, addr.String())
			if resp != nil {
				// Send response back to client
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

func (s *Server) requireSession(sessionID uint32, remoteAddr string) (*Session, bool) {
	if !s.sessionPolicy.requireRegister && sessionID == 0 {
		return nil, true
	}

	s.sessionsMu.RLock()
	session, ok := s.sessions[sessionID]
	s.sessionsMu.RUnlock()

	if !ok || session == nil {
		s.logger.Error("SendRRData with invalid session %d from %s", sessionID, remoteAddr)
		return nil, false
	}
	if session.LastActivity.IsZero() {
		session.LastActivity = time.Now()
	}
	if s.sessionPolicy.idleTimeout > 0 && time.Since(session.LastActivity) > s.sessionPolicy.idleTimeout {
		s.sessionsMu.Lock()
		delete(s.sessions, sessionID)
		s.sessionsMu.Unlock()
		return nil, false
	}
	return session, true
}

func (s *Server) enforceSessionLimits(remoteAddr string) error {
	maxSessions := s.sessionPolicy.maxSessions
	maxSessionsPerIP := s.sessionPolicy.maxSessionsPerIP
	if maxSessions <= 0 && maxSessionsPerIP <= 0 {
		return nil
	}

	targetIP := remoteIP(remoteAddr)
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	if maxSessions > 0 && len(s.sessions) >= maxSessions {
		return fmt.Errorf("max sessions reached")
	}
	if maxSessionsPerIP > 0 && targetIP != "" {
		count := 0
		for _, session := range s.sessions {
			if session != nil && session.RemoteIP == targetIP {
				count++
			}
		}
		if count >= maxSessionsPerIP {
			return fmt.Errorf("max sessions per IP reached")
		}
	}
	return nil
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func resolveENIPSupport(cfg *config.ServerConfig) enipSupportConfig {
	return enipSupportConfig{
		listIdentity:    boolValue(cfg.ENIP.Support.ListIdentity, true),
		listServices:    boolValue(cfg.ENIP.Support.ListServices, true),
		listInterfaces:  boolValue(cfg.ENIP.Support.ListInterfaces, true),
		registerSession: boolValue(cfg.ENIP.Support.RegisterSession, true),
		sendRRData:      boolValue(cfg.ENIP.Support.SendRRData, true),
		sendUnitData:    boolValue(cfg.ENIP.Support.SendUnitData, true),
	}
}

func resolveSessionPolicy(cfg *config.ServerConfig) enipSessionPolicy {
	idleMs := cfg.ENIP.Session.IdleTimeoutMs
	maxSessions := cfg.ENIP.Session.MaxSessions
	maxSessionsPerIP := cfg.ENIP.Session.MaxSessionsPerIP
	if maxSessions == 0 {
		maxSessions = 256
	}
	if maxSessionsPerIP == 0 {
		maxSessionsPerIP = 64
	}
	if idleMs == 0 {
		idleMs = 60000
	}
	return enipSessionPolicy{
		requireRegister:  boolValue(cfg.ENIP.Session.RequireRegisterSession, true),
		maxSessions:      maxSessions,
		maxSessionsPerIP: maxSessionsPerIP,
		idleTimeout:      time.Duration(idleMs) * time.Millisecond,
	}
}

func boolValue(value *bool, def bool) bool {
	if value == nil {
		return def
	}
	return *value
}

func (s *Server) handleListIdentity(encap enip.ENIPEncapsulation, remoteAddr string) []byte {
	vendorID, deviceType, productCode, revMajor, revMinor, status, serial, productName := s.identityValues()
	order := cipclient.CurrentProtocolProfile().ENIPByteOrder

	data := make([]byte, 0, 34+len(productName))
	socket := make([]byte, 16)
	order.PutUint16(socket[0:2], 0x0002)
	order.PutUint16(socket[2:4], uint16(s.config.Server.TCPPort))
	copy(socket[4:8], net.ParseIP(s.config.Server.ListenIP).To4())
	data = append(data, socket...)

	buf2 := make([]byte, 2)
	buf4 := make([]byte, 4)
	order.PutUint16(buf2, vendorID)
	data = append(data, buf2...)
	order.PutUint16(buf2, deviceType)
	data = append(data, buf2...)
	order.PutUint16(buf2, productCode)
	data = append(data, buf2...)
	data = append(data, revMajor, revMinor)
	order.PutUint16(buf2, status)
	data = append(data, buf2...)
	order.PutUint32(buf4, serial)
	data = append(data, buf4...)
	data = append(data, byte(len(productName)))
	data = append(data, []byte(productName)...)
	data = append(data, 0x03)

	resp := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandListIdentity,
		Length:        uint16(len(data)),
		SessionID:     0,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          data,
	}
	return enip.EncodeENIP(resp)
}

func (s *Server) handleListServices(encap enip.ENIPEncapsulation) []byte {
	resp := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandListServices,
		Length:        0,
		SessionID:     0,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          nil,
	}
	return enip.EncodeENIP(resp)
}

func (s *Server) handleListInterfaces(encap enip.ENIPEncapsulation) []byte {
	resp := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandListInterfaces,
		Length:        0,
		SessionID:     0,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          nil,
	}
	return enip.EncodeENIP(resp)
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

func resolveFaultPolicy(cfg *config.ServerConfig) faultPolicy {
	seed := cfg.Server.RNGSeed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	chunkMin := cfg.Faults.TCP.ChunkMin
	chunkMax := cfg.Faults.TCP.ChunkMax
	if chunkMin == 0 {
		chunkMin = 1
	}
	if chunkMax == 0 {
		chunkMax = 4
	}
	if chunkMax < chunkMin {
		chunkMax = chunkMin
	}

	return faultPolicy{
		enabled:         cfg.Faults.Enable,
		latencyBase:     time.Duration(cfg.Faults.Latency.BaseDelayMs) * time.Millisecond,
		latencyJitter:   time.Duration(cfg.Faults.Latency.JitterMs) * time.Millisecond,
		spikeEveryN:     cfg.Faults.Latency.SpikeEveryN,
		spikeDelay:      time.Duration(cfg.Faults.Latency.SpikeDelayMs) * time.Millisecond,
		dropEveryN:      cfg.Faults.Reliability.DropResponseEveryN,
		dropPct:         cfg.Faults.Reliability.DropResponsePct,
		closeEveryN:     cfg.Faults.Reliability.CloseConnectionEveryN,
		stallEveryN:     cfg.Faults.Reliability.StallResponseEveryN,
		chunkWrites:     cfg.Faults.TCP.ChunkWrites,
		chunkMin:        chunkMin,
		chunkMax:        chunkMax,
		interChunkDelay: time.Duration(cfg.Faults.TCP.InterChunkDelayMs) * time.Millisecond,
		coalesce:        cfg.Faults.TCP.CoalesceResponses,
		rng:             rand.New(rand.NewSource(seed)),
	}
}

func (s *Server) nextResponseFaultAction() responseFaultAction {
	if !s.faults.enabled {
		return responseFaultAction{
			chunked:  s.faults.chunkWrites,
			coalesce: s.faults.coalesce,
		}
	}

	s.faults.mu.Lock()
	defer s.faults.mu.Unlock()

	s.faults.responseCount++
	count := s.faults.responseCount
	delay := s.faults.latencyBase

	if s.faults.latencyJitter > 0 {
		jitter := time.Duration(s.faults.rng.Int63n(int64(s.faults.latencyJitter) + 1))
		delay += jitter
	}
	if s.faults.spikeEveryN > 0 && count%s.faults.spikeEveryN == 0 {
		delay += s.faults.spikeDelay
	}
	if s.faults.stallEveryN > 0 && count%s.faults.stallEveryN == 0 {
		stall := s.faults.spikeDelay
		if stall == 0 {
			stall = time.Second
		}
		delay += stall
	}

	drop := false
	if s.faults.dropEveryN > 0 && count%s.faults.dropEveryN == 0 {
		drop = true
	}
	if s.faults.dropPct > 0 && s.faults.rng.Float64() < s.faults.dropPct {
		drop = true
	}
	closeConn := s.faults.closeEveryN > 0 && count%s.faults.closeEveryN == 0

	return responseFaultAction{
		drop:     drop,
		delay:    delay,
		close:    closeConn,
		chunked:  s.faults.chunkWrites,
		coalesce: s.faults.coalesce,
	}
}

func (s *Server) writeResponse(conn *net.TCPConn, remoteAddr string, resp []byte) error {
	action := s.nextResponseFaultAction()
	if action.delay > 0 {
		time.Sleep(action.delay)
	}

	if action.coalesce {
		s.coalesceMu.Lock()
		if pending, ok := s.coalesceQueue[conn]; ok && len(pending) > 0 {
			resp = append(pending, resp...)
			delete(s.coalesceQueue, conn)
		} else {
			s.coalesceQueue[conn] = append([]byte(nil), resp...)
			s.coalesceMu.Unlock()
			if action.close {
				conn.Close()
				return io.EOF
			}
			return nil
		}
		s.coalesceMu.Unlock()
	}

	if action.drop {
		if action.close {
			conn.Close()
			return io.EOF
		}
		return nil
	}

	if action.chunked {
		if err := s.writeChunks(conn, resp); err != nil {
			s.logger.Error("Write response error to %s: %v", remoteAddr, err)
			return err
		}
	} else {
		if _, err := conn.Write(resp); err != nil {
			s.logger.Error("Write response error to %s: %v", remoteAddr, err)
			return err
		}
	}

	if action.close {
		conn.Close()
		return io.EOF
	}
	return nil
}

func (s *Server) writeChunks(conn *net.TCPConn, resp []byte) error {
	if len(resp) == 0 {
		return nil
	}
	s.faults.mu.Lock()
	chunks := s.faults.chunkMin
	if s.faults.chunkMax > s.faults.chunkMin {
		chunks = s.faults.chunkMin + s.faults.rng.Intn(s.faults.chunkMax-s.faults.chunkMin+1)
	}
	delay := s.faults.interChunkDelay
	s.faults.mu.Unlock()

	if chunks <= 1 {
		_, err := conn.Write(resp)
		return err
	}
	size := (len(resp) + chunks - 1) / chunks
	offset := 0
	for offset < len(resp) {
		end := offset + size
		if end > len(resp) {
			end = len(resp)
		}
		if _, err := conn.Write(resp[offset:end]); err != nil {
			return err
		}
		offset = end
		if delay > 0 && offset < len(resp) {
			time.Sleep(delay)
		}
	}
	return nil
}

func resolveCIPPolicy(cfg *config.ServerConfig) cipPolicyConfig {
	defaultStatus := cfg.CIP.DefaultUnsupportedStatus
	if defaultStatus == 0 {
		defaultStatus = 0x08
	}
	return cipPolicyConfig{
		strictPaths:        boolValue(cfg.CIP.StrictPaths, true),
		defaultStatus:      defaultStatus,
		defaultExtStatus:   cfg.CIP.DefaultErrorExtStatus,
		allowRules:         cfg.CIP.Allow,
		denyRules:          cfg.CIP.Deny,
		denyStatusOverride: cfg.CIP.DenyStatusOverrides,
	}
}

func (s *Server) applyCIPPolicy(req protocol.CIPRequest) (protocol.CIPResponse, bool) {
	if s.cipPolicy.strictPaths && req.Path.Class == 0 && req.Path.Name == "" {
		return s.policyReject(req), true
	}

	for _, rule := range s.cipPolicy.denyRules {
		if ruleMatches(rule, req) {
			return s.policyReject(req), true
		}
	}

	if len(s.cipPolicy.allowRules) > 0 {
		for _, rule := range s.cipPolicy.allowRules {
			if ruleMatches(rule, req) {
				return protocol.CIPResponse{}, false
			}
		}
		return s.policyReject(req), true
	}

	return protocol.CIPResponse{}, false
}

func (s *Server) policyReject(req protocol.CIPRequest) protocol.CIPResponse {
	status := s.cipPolicy.defaultStatus
	for _, override := range s.cipPolicy.denyStatusOverride {
		if overrideMatches(override, req) {
			status = override.Status
			break
		}
	}
	resp := protocol.CIPResponse{
		Service: req.Service,
		Status:  status,
		Path:    req.Path,
	}
	if s.cipPolicy.defaultExtStatus != 0 {
		resp.ExtStatus = []byte{
			byte(s.cipPolicy.defaultExtStatus & 0xFF),
			byte(s.cipPolicy.defaultExtStatus >> 8),
		}
	}
	return resp
}

func ruleMatches(rule config.ServerCIPRule, req protocol.CIPRequest) bool {
	if rule.Service != 0 && rule.Service != uint8(req.Service) {
		return false
	}
	if rule.Class != 0 && rule.Class != req.Path.Class {
		return false
	}
	if rule.Instance != 0 && rule.Instance != req.Path.Instance {
		return false
	}
	if rule.Attribute != 0 && rule.Attribute != req.Path.Attribute {
		return false
	}
	return true
}

func overrideMatches(rule config.ServerCIPStatusOverride, req protocol.CIPRequest) bool {
	if rule.Service != 0 && rule.Service != uint8(req.Service) {
		return false
	}
	if rule.Class != 0 && rule.Class != req.Path.Class {
		return false
	}
	if rule.Instance != 0 && rule.Instance != req.Path.Instance {
		return false
	}
	if rule.Attribute != 0 && rule.Attribute != req.Path.Attribute {
		return false
	}
	return true
}

func parseENIPStream(buffer []byte, logger *logging.Logger) ([]enip.ENIPEncapsulation, []byte) {
	const headerSize = 24
	order := cipclient.CurrentProtocolProfile().ENIPByteOrder
	frames := make([]enip.ENIPEncapsulation, 0)
	offset := 0

	for len(buffer[offset:]) >= headerSize {
		command := order.Uint16(buffer[offset : offset+2])
		if !isValidENIPCommand(command) {
			offset++
			continue
		}
		length := int(order.Uint16(buffer[offset+2 : offset+4]))
		total := headerSize + length
		if len(buffer[offset:]) < total {
			break
		}

		frame := buffer[offset : offset+total]
		encap, err := enip.DecodeENIP(frame)
		if err != nil {
			logger.Debug("Decode ENIP error: %v", err)
			offset++
			continue
		}
		frames = append(frames, encap)
		offset += total
	}

	if offset == 0 {
		return frames, buffer
	}
	remaining := make([]byte, len(buffer)-offset)
	copy(remaining, buffer[offset:])
	return frames, remaining
}

func isValidENIPCommand(cmd uint16) bool {
	switch cmd {
	case enip.ENIPCommandRegisterSession,
		enip.ENIPCommandUnregisterSession,
		enip.ENIPCommandSendRRData,
		enip.ENIPCommandSendUnitData,
		enip.ENIPCommandListIdentity,
		enip.ENIPCommandListServices,
		enip.ENIPCommandListInterfaces:
		return true
	default:
		return false
	}
}

func (s *Server) parseSendRRData(data []byte) ([]byte, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("SendRRData data too short: %d bytes", len(data))
	}
	payload := data[6:]
	cpfStrict := boolValue(s.config.ENIP.CPF.Strict, true)
	allowMissing := boolValue(s.config.ENIP.CPF.AllowMissingItems, false)
	allowExtra := boolValue(s.config.ENIP.CPF.AllowExtraItems, false)
	allowReorder := boolValue(s.config.ENIP.CPF.AllowItemReorder, true)

	items, err := enip.ParseCPFItems(payload)
	if err != nil {
		if !cpfStrict && allowMissing {
			return payload, nil
		}
		return nil, err
	}
	if len(items) == 0 {
		if allowMissing {
			return payload, nil
		}
		return nil, fmt.Errorf("missing CPF items")
	}
	if !allowExtra && len(items) != 2 {
		return nil, fmt.Errorf("unexpected CPF item count: %d", len(items))
	}
	if !allowReorder {
		if len(items) < 2 || items[0].TypeID != enip.CPFItemNullAddress || items[1].TypeID != enip.CPFItemUnconnectedData {
			return nil, fmt.Errorf("CPF items out of order")
		}
	}
	for _, item := range items {
		if item.TypeID == enip.CPFItemUnconnectedData {
			return item.Data, nil
		}
	}
	if allowMissing {
		return payload, nil
	}
	return nil, fmt.Errorf("missing unconnected data item")
}

func (s *Server) parseSendUnitData(data []byte) (uint32, []byte, error) {
	if len(data) < 4 {
		return 0, nil, fmt.Errorf("SendUnitData data too short: %d bytes", len(data))
	}
	payload := data
	cpfStrict := boolValue(s.config.ENIP.CPF.Strict, true)
	allowMissing := boolValue(s.config.ENIP.CPF.AllowMissingItems, false)
	allowExtra := boolValue(s.config.ENIP.CPF.AllowExtraItems, false)
	allowReorder := boolValue(s.config.ENIP.CPF.AllowItemReorder, true)

	if len(data) >= 6 {
		payload = data[6:]
	}
	items, err := enip.ParseCPFItems(payload)
	if err != nil {
		if !cpfStrict && allowMissing {
			connID := cipclient.CurrentProtocolProfile().ENIPByteOrder.Uint32(data[:4])
			return connID, data[4:], nil
		}
		return 0, nil, err
	}
	if len(items) == 0 {
		if allowMissing {
			connID := cipclient.CurrentProtocolProfile().ENIPByteOrder.Uint32(data[:4])
			return connID, data[4:], nil
		}
		return 0, nil, fmt.Errorf("missing CPF items")
	}
	if !allowExtra && len(items) != 2 {
		return 0, nil, fmt.Errorf("unexpected CPF item count: %d", len(items))
	}
	if !allowReorder {
		if len(items) < 2 || items[0].TypeID != enip.CPFItemConnectedAddress || items[1].TypeID != enip.CPFItemConnectedData {
			return 0, nil, fmt.Errorf("CPF items out of order")
		}
	}

	var connID uint32
	var cipData []byte
	order := cipclient.CurrentProtocolProfile().ENIPByteOrder
	for _, item := range items {
		switch item.TypeID {
		case enip.CPFItemConnectedAddress:
			if len(item.Data) < 4 {
				return 0, nil, fmt.Errorf("connected address item too short")
			}
			connID = order.Uint32(item.Data[:4])
		case enip.CPFItemConnectedData:
			cipData = item.Data
		}
	}
	if connID == 0 || cipData == nil {
		if allowMissing {
			connID = order.Uint32(data[:4])
			return connID, data[4:], nil
		}
		return 0, nil, fmt.Errorf("missing connected items")
	}
	return connID, cipData, nil
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
func (s *Server) buildErrorResponse(encap enip.ENIPEncapsulation, status uint32) []byte {
	response := enip.ENIPEncapsulation{
		Command:       encap.Command,
		Length:        0,
		SessionID:     encap.SessionID,
		Status:        status,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          nil,
	}

	return enip.EncodeENIP(response)
}
