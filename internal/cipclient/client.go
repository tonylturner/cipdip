package cipclient

// Client interface and implementation for CIP/EtherNet-IP communication

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"
)

// ConnectionParams represents parameters for establishing a connected I/O connection
type ConnectionParams struct {
	Name                  string
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
	ID              uint32 // connection ID or identifying handle
	Params          ConnectionParams
	LastOToTDataSent []byte
	LastTToODataRecv []byte
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
	transport      Transport
	sessionID      uint32
	senderContext  [8]byte
	connected      bool
	ioConnections  map[uint32]*IOConnection
	nextConnID     uint32
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

	addr := fmt.Sprintf("%s:%d", ip, port)
	if err := c.transport.Connect(ctx, addr); err != nil {
		return fmt.Errorf("transport connect: %w", err)
	}

	// Send RegisterSession
	regPacket := BuildRegisterSession(c.senderContext)
	if err := c.transport.Send(ctx, regPacket); err != nil {
		c.transport.Disconnect()
		return fmt.Errorf("send RegisterSession: %w", err)
	}

	// Receive RegisterSession response
	timeout := 5 * time.Second
	respData, err := c.transport.Receive(ctx, timeout)
	if err != nil {
		c.transport.Disconnect()
		return fmt.Errorf("receive RegisterSession response: %w", err)
	}

	encap, err := DecodeENIP(respData)
	if err != nil {
		c.transport.Disconnect()
		return fmt.Errorf("decode RegisterSession response: %w", err)
	}

	if encap.Status != ENIPStatusSuccess {
		c.transport.Disconnect()
		return fmt.Errorf("RegisterSession failed with status: 0x%08X", encap.Status)
	}

	// Store session ID
	c.sessionID = encap.SessionID
	c.connected = true

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

	// Encode CIP request
	cipData, err := EncodeCIPRequest(req)
	if err != nil {
		return CIPResponse{}, fmt.Errorf("encode CIP request: %w", err)
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
		return CIPResponse{}, fmt.Errorf("decode CIP response: %w", err)
	}

	resp.Service = req.Service

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

	// TODO: Implement ForwardOpen service
	// This requires building a ForwardOpen CIP request with connection parameters
	// For now, return a placeholder connection

	conn := &IOConnection{
		ID:     c.nextConnID,
		Params: params,
	}
	c.nextConnID++
	c.ioConnections[conn.ID] = conn

	return conn, fmt.Errorf("ForwardOpen not yet fully implemented")
}

// ForwardClose terminates a connected I/O-style connection
func (c *ENIPClient) ForwardClose(ctx context.Context, conn *IOConnection) error {
	if !c.connected {
		return fmt.Errorf("not connected")
	}

	// TODO: Implement ForwardClose service
	// This requires building a ForwardClose CIP request

	delete(c.ioConnections, conn.ID)
	return fmt.Errorf("ForwardClose not yet fully implemented")
}

// SendIOData sends I/O data over a connected path
func (c *ENIPClient) SendIOData(ctx context.Context, conn *IOConnection, data []byte) error {
	if !c.connected {
		return fmt.Errorf("not connected")
	}

	if conn == nil {
		return fmt.Errorf("invalid connection")
	}

	// TODO: Implement SendIOData
	// This requires using SendUnitData with the connection ID
	// For UDP 2222, this would use UDP transport

	return fmt.Errorf("SendIOData not yet fully implemented")
}

// ReceiveIOData receives I/O data from a connected path
func (c *ENIPClient) ReceiveIOData(ctx context.Context, conn *IOConnection) ([]byte, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	if conn == nil {
		return nil, fmt.Errorf("invalid connection")
	}

	// TODO: Implement ReceiveIOData
	// This requires receiving SendUnitData responses
	// For UDP 2222, this would use UDP transport

	return nil, fmt.Errorf("ReceiveIOData not yet fully implemented")
}
