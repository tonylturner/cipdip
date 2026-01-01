package cipclient

// Client interface and implementation for CIP/EtherNet-IP communication

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/tturner/cipdip/internal/errors"
)

// ConnectionParams represents parameters for establishing a connected I/O connection
type ConnectionParams struct {
	Name                  string
	Transport             string // "tcp" or "udp" - transport for I/O data (default: "tcp")
	OToTRPIMs             int
	TToORPIMs             int
	OToTSizeBytes         int
	TToOSizeBytes         int
	Priority              string
	TransportClassTrigger int
	Class                 uint16
	Instance              uint16
	ConnectionPathHex     string // optional raw EPATH override
}

// IOConnection represents an active connected I/O connection
type IOConnection struct {
	ID               uint32 // connection ID or identifying handle
	Params           ConnectionParams
	ioTransport      Transport // transport for I/O data (UDP 2222 or TCP 44818)
	LastOToTDataSent []byte
	LastTToODataRecv []byte
	Sequence         uint16
}

// Client interface for CIP/EtherNet-IP communication
type Client interface {
	Connect(ctx context.Context, ip string, port int) error
	Disconnect(ctx context.Context) error

	// Generic CIP service invocation (unconnected messaging over SendRRData)
	InvokeService(ctx context.Context, req CIPRequest) (CIPResponse, error)

	// Convenience helpers for common services
	ReadAttribute(ctx context.Context, path CIPPath) (CIPResponse, error)
	WriteAttribute(ctx context.Context, path CIPPath, value []byte) (CIPResponse, error)

	// Connected messaging support
	ForwardOpen(ctx context.Context, params ConnectionParams) (*IOConnection, error)
	ForwardClose(ctx context.Context, conn *IOConnection) error

	// I/O data handling
	SendIOData(ctx context.Context, conn *IOConnection, data []byte) error
	ReceiveIOData(ctx context.Context, conn *IOConnection) ([]byte, error)
}

// ENIPClient implements the Client interface
type ENIPClient struct {
	transport     Transport
	targetIP      string // Store target IP for UDP I/O connections
	targetPort    int    // Store target port for reference
	sessionID     uint32
	senderContext [8]byte
	connected     bool
	ioConnections map[uint32]*IOConnection
	nextConnID    uint32
}

// NewClient creates a new CIP/EtherNet-IP client
func NewClient() Client {
	client := &ENIPClient{
		transport:     NewTCPTransport(),
		ioConnections: make(map[uint32]*IOConnection),
		nextConnID:    1,
	}

	// Generate random sender context
	rand.Read(client.senderContext[:])

	return client
}

// Connect establishes a connection to the CIP device
func (c *ENIPClient) Connect(ctx context.Context, ip string, port int) error {
	if c.connected {
		return fmt.Errorf("already connected")
	}

	// Validate IP address format (basic check)
	if ip == "" {
		return fmt.Errorf("IP address cannot be empty")
	}

	// Store target IP/port for UDP I/O connections
	c.targetIP = ip
	c.targetPort = port

	addr := fmt.Sprintf("%s:%d", ip, port)
	if err := c.transport.Connect(ctx, addr); err != nil {
		// Wrap with user-friendly error message
		return errors.WrapNetworkError(err, ip, port)
	}

	// Send RegisterSession
	regPacket := BuildRegisterSession(c.senderContext)

	// Validate packet before sending (strict unless legacy_compat)
	profile := CurrentProtocolProfile()
	validator := NewPacketValidator(profile.Name != "legacy_compat")
	encapReq, _ := DecodeENIP(regPacket)
	if err := validator.ValidateENIP(encapReq); err != nil {
		c.transport.Disconnect()
		return fmt.Errorf("invalid RegisterSession packet: %w", err)
	}

	if err := c.transport.Send(ctx, regPacket); err != nil {
		c.transport.Disconnect()
		return errors.WrapNetworkError(err, ip, port)
	}

	// Receive RegisterSession response
	timeout := 5 * time.Second
	respData, err := c.transport.Receive(ctx, timeout)
	if err != nil {
		c.transport.Disconnect()
		return errors.WrapNetworkError(err, ip, port)
	}

	encap, err := DecodeENIP(respData)
	if err != nil {
		c.transport.Disconnect()
		return errors.WrapCIPError(err, "RegisterSession")
	}

	// Validate response
	if err := validator.ValidateENIP(encap); err != nil {
		c.transport.Disconnect()
		return errors.WrapCIPError(err, "RegisterSession response validation")
	}

	if encap.Status != ENIPStatusSuccess {
		c.transport.Disconnect()
		return errors.WrapCIPError(fmt.Errorf("RegisterSession failed with status: 0x%08X", encap.Status), "RegisterSession")
	}

	// Store session ID
	c.sessionID = encap.SessionID
	c.connected = true

	fmt.Printf("[CLIENT] Connected and registered session 0x%08X\n", c.sessionID)

	return nil
}

// Disconnect closes the connection to the CIP device
func (c *ENIPClient) Disconnect(ctx context.Context) error {
	if !c.connected {
		return nil
	}

	// Close all I/O connections
	for _, conn := range c.ioConnections {
		_ = c.ForwardClose(ctx, conn)
		// Close UDP transport if it's separate from main transport
		if conn.ioTransport != nil && conn.ioTransport != c.transport {
			_ = conn.ioTransport.Disconnect()
		}
	}
	c.ioConnections = make(map[uint32]*IOConnection)

	// Send UnregisterSession
	if c.sessionID != 0 {
		unregPacket := BuildUnregisterSession(c.sessionID, c.senderContext)
		_ = c.transport.Send(ctx, unregPacket) // Ignore error on disconnect
	}

	c.transport.Disconnect()
	c.connected = false
	c.sessionID = 0

	return nil
}

// InvokeService invokes a generic CIP service via UCMM (SendRRData)
func (c *ENIPClient) InvokeService(ctx context.Context, req CIPRequest) (CIPResponse, error) {
	if !c.connected {
		return CIPResponse{}, fmt.Errorf("not connected")
	}

	// Validate CIP request
	profile := CurrentProtocolProfile()
	validator := NewPacketValidator(profile.Name != "legacy_compat")
	if err := validator.ValidateCIPRequest(req); err != nil {
		return CIPResponse{}, errors.WrapCIPError(err, fmt.Sprintf("%s request", req.Service))
	}

	// Encode CIP request
	cipData, err := EncodeCIPRequest(req)
	if err != nil {
		return CIPResponse{}, errors.WrapCIPError(err, fmt.Sprintf("encode %s", req.Service))
	}

	// Build SendRRData packet
	packet := BuildSendRRData(c.sessionID, c.senderContext, cipData)

	// Send request
	if err := c.transport.Send(ctx, packet); err != nil {
		return CIPResponse{}, fmt.Errorf("send request: %w", err)
	}

	// Receive response
	timeout := 5 * time.Second
	respData, err := c.transport.Receive(ctx, timeout)
	if err != nil {
		return CIPResponse{}, fmt.Errorf("receive response: %w", err)
	}

	// Decode ENIP response
	encap, err := DecodeENIP(respData)
	if err != nil {
		return CIPResponse{}, fmt.Errorf("decode ENIP response: %w", err)
	}

	if encap.Status != ENIPStatusSuccess {
		return CIPResponse{}, fmt.Errorf("ENIP error status: 0x%08X", encap.Status)
	}

	// Parse SendRRData response
	cipRespData, err := ParseSendRRDataResponse(encap.Data)
	if err != nil {
		return CIPResponse{}, fmt.Errorf("parse SendRRData response: %w", err)
	}

	// Decode CIP response
	resp, err := DecodeCIPResponse(cipRespData, req.Path)
	if err != nil {
		return CIPResponse{}, errors.WrapCIPError(err, fmt.Sprintf("%s response", req.Service))
	}

	resp.Service = req.Service

	// Validate response
	if err := validator.ValidateCIPResponse(resp, req.Service); err != nil {
		// Log validation error but don't fail - device may be non-compliant
		// In strict mode, this would fail
	}

	return resp, nil
}

// ReadAttribute reads a CIP attribute using Get_Attribute_Single
func (c *ENIPClient) ReadAttribute(ctx context.Context, path CIPPath) (CIPResponse, error) {
	req := CIPRequest{
		Service: CIPServiceGetAttributeSingle,
		Path:    path,
		Payload: nil,
	}

	return c.InvokeService(ctx, req)
}

// WriteAttribute writes a CIP attribute using Set_Attribute_Single
func (c *ENIPClient) WriteAttribute(ctx context.Context, path CIPPath, value []byte) (CIPResponse, error) {
	req := CIPRequest{
		Service: CIPServiceSetAttributeSingle,
		Path:    path,
		Payload: value,
	}

	return c.InvokeService(ctx, req)
}

// ForwardOpen establishes a connected I/O-style connection
func (c *ENIPClient) ForwardOpen(ctx context.Context, params ConnectionParams) (*IOConnection, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	// Build ForwardOpen CIP request
	forwardOpenData, err := BuildForwardOpenRequest(params)
	if err != nil {
		return nil, fmt.Errorf("build ForwardOpen request: %w", err)
	}

	// Send via SendRRData (UCMM)
	packet := BuildSendRRData(c.sessionID, c.senderContext, forwardOpenData)

	// Send request
	if err := c.transport.Send(ctx, packet); err != nil {
		return nil, fmt.Errorf("send ForwardOpen request: %w", err)
	}

	// Receive response
	timeout := 5 * time.Second
	respData, err := c.transport.Receive(ctx, timeout)
	if err != nil {
		return nil, fmt.Errorf("receive ForwardOpen response: %w", err)
	}

	// Decode ENIP response
	encap, err := DecodeENIP(respData)
	if err != nil {
		return nil, fmt.Errorf("decode ENIP response: %w", err)
	}

	if encap.Status != ENIPStatusSuccess {
		return nil, fmt.Errorf("ENIP error status: 0x%08X", encap.Status)
	}

	// Parse SendRRData response
	cipRespData, err := ParseSendRRDataResponse(encap.Data)
	if err != nil {
		return nil, fmt.Errorf("parse SendRRData response: %w", err)
	}

	// Parse ForwardOpen response
	connectionID, oToTConnID, tToOConnID, err := ParseForwardOpenResponse(cipRespData)
	if err != nil {
		return nil, fmt.Errorf("parse ForwardOpen response: %w", err)
	}

	// Determine transport for I/O data
	// ForwardOpen/ForwardClose always use TCP 44818, but I/O data can use UDP 2222
	transportType := params.Transport
	if transportType == "" {
		transportType = "tcp" // Default to TCP
	}

	var ioTransport Transport
	if transportType == "udp" {
		// Create UDP transport for I/O data on port 2222
		udpTransport := NewUDPTransport()
		udpAddr := fmt.Sprintf("%s:2222", c.targetIP)
		if err := udpTransport.Connect(ctx, udpAddr); err != nil {
			return nil, fmt.Errorf("connect UDP transport for I/O: %w", err)
		}
		ioTransport = udpTransport
	} else {
		// Use the main TCP transport for I/O data
		ioTransport = c.transport
	}

	// Create connection object
	conn := &IOConnection{
		ID:          connectionID,
		Params:      params,
		ioTransport: ioTransport,
	}
	c.ioConnections[connectionID] = conn

	// Store connection IDs for later use
	_ = oToTConnID
	_ = tToOConnID

	return conn, nil
}

// ForwardClose terminates a connected I/O-style connection
func (c *ENIPClient) ForwardClose(ctx context.Context, conn *IOConnection) error {
	if !c.connected {
		return fmt.Errorf("not connected")
	}

	if conn == nil {
		return fmt.Errorf("invalid connection")
	}

	// Build ForwardClose CIP request
	forwardCloseData, err := BuildForwardCloseRequest(conn.ID)
	if err != nil {
		return fmt.Errorf("build ForwardClose request: %w", err)
	}

	// Send via SendRRData (UCMM) - ForwardClose always uses TCP 44818
	packet := BuildSendRRData(c.sessionID, c.senderContext, forwardCloseData)

	// Send request
	if err := c.transport.Send(ctx, packet); err != nil {
		return fmt.Errorf("send ForwardClose request: %w", err)
	}

	// Receive response
	timeout := 5 * time.Second
	respData, err := c.transport.Receive(ctx, timeout)
	if err != nil {
		return fmt.Errorf("receive ForwardClose response: %w", err)
	}

	// Decode ENIP response
	encap, err := DecodeENIP(respData)
	if err != nil {
		return fmt.Errorf("decode ENIP response: %w", err)
	}

	if encap.Status != ENIPStatusSuccess {
		return fmt.Errorf("ENIP error status: 0x%08X", encap.Status)
	}

	// Parse SendRRData response
	cipRespData, err := ParseSendRRDataResponse(encap.Data)
	if err != nil {
		return fmt.Errorf("parse SendRRData response: %w", err)
	}

	// Parse ForwardClose response
	if err := ParseForwardCloseResponse(cipRespData); err != nil {
		return fmt.Errorf("parse ForwardClose response: %w", err)
	}

	// Clean up connection
	// Close UDP transport if it's separate from main transport
	if conn.ioTransport != nil && conn.ioTransport != c.transport {
		_ = conn.ioTransport.Disconnect()
	}
	delete(c.ioConnections, conn.ID)

	return nil
}

// SendIOData sends I/O data over a connected path
func (c *ENIPClient) SendIOData(ctx context.Context, conn *IOConnection, data []byte) error {
	if !c.connected {
		return fmt.Errorf("not connected")
	}

	if conn == nil {
		return fmt.Errorf("invalid connection")
	}

	// Validate data size
	if len(data) > conn.Params.OToTSizeBytes {
		return fmt.Errorf("data size %d exceeds O->T size %d", len(data), conn.Params.OToTSizeBytes)
	}

	// Pad data to required size
	paddedData := make([]byte, conn.Params.OToTSizeBytes)
	copy(paddedData, data)

	profile := CurrentProtocolProfile()
	payload := paddedData
	if profile.UseCPF && profile.IOSequenceMode != "omit" {
		order := currentCIPByteOrder()
		seq := conn.Sequence
		if profile.IOSequenceMode == "random" {
			seq = uint16(time.Now().UnixNano())
		} else {
			seq++
		}
		conn.Sequence = seq
		var seqBytes [2]byte
		order.PutUint16(seqBytes[:], seq)
		payload = append(seqBytes[:], paddedData...)
	}

	// Build SendUnitData packet with connection ID and I/O data
	packet := BuildSendUnitData(c.sessionID, c.senderContext, conn.ID, payload)

	// Send via connection's I/O transport (UDP 2222 or TCP 44818)
	if conn.ioTransport == nil {
		return fmt.Errorf("I/O transport not initialized")
	}
	if err := conn.ioTransport.Send(ctx, packet); err != nil {
		return fmt.Errorf("send I/O data: %w", err)
	}

	// Store sent data
	conn.LastOToTDataSent = paddedData

	return nil
}

// ReceiveIOData receives I/O data from a connected path
func (c *ENIPClient) ReceiveIOData(ctx context.Context, conn *IOConnection) ([]byte, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	if conn == nil {
		return nil, fmt.Errorf("invalid connection")
	}

	// Receive SendUnitData response
	timeout := time.Duration(conn.Params.TToORPIMs) * time.Millisecond
	if timeout < 100*time.Millisecond {
		timeout = 100 * time.Millisecond // Minimum timeout
	}
	if timeout > 5*time.Second {
		timeout = 5 * time.Second // Maximum timeout
	}

	// Receive via connection's I/O transport (UDP 2222 or TCP 44818)
	if conn.ioTransport == nil {
		return nil, fmt.Errorf("I/O transport not initialized")
	}
	respData, err := conn.ioTransport.Receive(ctx, timeout)
	if err != nil {
		return nil, fmt.Errorf("receive I/O data: %w", err)
	}

	// Decode ENIP response
	encap, err := DecodeENIP(respData)
	if err != nil {
		return nil, fmt.Errorf("decode ENIP response: %w", err)
	}

	if encap.Status != ENIPStatusSuccess {
		return nil, fmt.Errorf("ENIP error status: 0x%08X", encap.Status)
	}

	if encap.Command != ENIPCommandSendUnitData {
		return nil, fmt.Errorf("unexpected command: 0x%04X", encap.Command)
	}

	// Parse SendUnitData response
	cipData, err := ParseSendUnitDataResponse(encap.Data)
	if err != nil {
		return nil, fmt.Errorf("parse SendUnitData response: %w", err)
	}

	profile := CurrentProtocolProfile()
	ioData := cipData
	if profile.UseCPF && profile.IOSequenceMode != "omit" {
		if len(ioData) < 2 {
			return nil, fmt.Errorf("response too short for sequence count")
		}
		ioData = ioData[2:]
	}
	if len(ioData) > conn.Params.TToOSizeBytes {
		ioData = ioData[:conn.Params.TToOSizeBytes]
	}

	// Store received data
	conn.LastTToODataRecv = ioData

	return ioData, nil
}
