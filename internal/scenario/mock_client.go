package scenario

import (
	"context"
	"fmt"
	"sync"

	"github.com/tturner/cipdip/internal/cipclient"
)

// MockClient is a mock implementation of cipclient.Client for testing
type MockClient struct {
	connected      bool
	connectError   error
	disconnectError error
	readResponses  map[string]cipclient.CIPResponse
	readErrors     map[string]error
	writeResponses map[string]cipclient.CIPResponse
	writeErrors    map[string]error
	readCount      map[string]int
	writeCount     map[string]int
	mu             sync.RWMutex

	// I/O connection support
	forwardOpenError   error
	forwardCloseError  error
	sendIODataError    error
	receiveIODataError error
	receiveIOData      []byte
}

// NewMockClient creates a new mock client
func NewMockClient() *MockClient {
	return &MockClient{
		readResponses:  make(map[string]cipclient.CIPResponse),
		readErrors:     make(map[string]error),
		writeResponses: make(map[string]cipclient.CIPResponse),
		writeErrors:    make(map[string]error),
		readCount:      make(map[string]int),
		writeCount:     make(map[string]int),
		receiveIOData:  make([]byte, 8),
	}
}

// Connect simulates connection
func (m *MockClient) Connect(ctx context.Context, ip string, port int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.connectError != nil {
		return m.connectError
	}
	m.connected = true
	return nil
}

// Disconnect simulates disconnection
func (m *MockClient) Disconnect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.disconnectError != nil {
		return m.disconnectError
	}
	m.connected = false
	return nil
}

// InvokeService simulates service invocation
func (m *MockClient) InvokeService(ctx context.Context, req cipclient.CIPRequest) (cipclient.CIPResponse, error) {
	// Not used by scenarios directly, but implement for interface compliance
	return cipclient.CIPResponse{}, nil
}

// ReadAttribute simulates reading an attribute
func (m *MockClient) ReadAttribute(ctx context.Context, path cipclient.CIPPath) (cipclient.CIPResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := pathKey(path)
	m.readCount[key]++

	if err, ok := m.readErrors[key]; ok {
		return cipclient.CIPResponse{}, err
	}

	if resp, ok := m.readResponses[key]; ok {
		return resp, nil
	}

	// Default success response
	return cipclient.CIPResponse{
		Service: cipclient.CIPServiceGetAttributeSingle,
		Status:  0x00,
		Path:    path,
		Payload: make([]byte, 16),
	}, nil
}

// WriteAttribute simulates writing an attribute
func (m *MockClient) WriteAttribute(ctx context.Context, path cipclient.CIPPath, value []byte) (cipclient.CIPResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := pathKey(path)
	m.writeCount[key]++

	if err, ok := m.writeErrors[key]; ok {
		return cipclient.CIPResponse{}, err
	}

	if resp, ok := m.writeResponses[key]; ok {
		return resp, nil
	}

	// Default success response
	return cipclient.CIPResponse{
		Service: cipclient.CIPServiceSetAttributeSingle,
		Status:  0x00,
		Path:    path,
	}, nil
}

// ForwardOpen simulates opening a connection
func (m *MockClient) ForwardOpen(ctx context.Context, params cipclient.ConnectionParams) (*cipclient.IOConnection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.forwardOpenError != nil {
		return nil, m.forwardOpenError
	}

	return &cipclient.IOConnection{
		ID:     1,
		Params: params,
	}, nil
}

// ForwardClose simulates closing a connection
func (m *MockClient) ForwardClose(ctx context.Context, conn *cipclient.IOConnection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.forwardCloseError
}

// SendIOData simulates sending I/O data
func (m *MockClient) SendIOData(ctx context.Context, conn *cipclient.IOConnection, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sendIODataError
}

// ReceiveIOData simulates receiving I/O data
func (m *MockClient) ReceiveIOData(ctx context.Context, conn *cipclient.IOConnection) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.receiveIODataError != nil {
		return nil, m.receiveIODataError
	}
	return m.receiveIOData, nil
}

// SetReadResponse sets a response for a specific path
func (m *MockClient) SetReadResponse(path cipclient.CIPPath, resp cipclient.CIPResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := pathKey(path)
	m.readResponses[key] = resp
}

// SetReadError sets an error for a specific path
func (m *MockClient) SetReadError(path cipclient.CIPPath, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := pathKey(path)
	m.readErrors[key] = err
}

// SetWriteResponse sets a response for a specific path
func (m *MockClient) SetWriteResponse(path cipclient.CIPPath, resp cipclient.CIPResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := pathKey(path)
	m.writeResponses[key] = resp
}

// SetWriteError sets an error for a specific path
func (m *MockClient) SetWriteError(path cipclient.CIPPath, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := pathKey(path)
	m.writeErrors[key] = err
}

// GetReadCount returns the number of reads for a path
func (m *MockClient) GetReadCount(path cipclient.CIPPath) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := pathKey(path)
	return m.readCount[key]
}

// GetWriteCount returns the number of writes for a path
func (m *MockClient) GetWriteCount(path cipclient.CIPPath) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := pathKey(path)
	return m.writeCount[key]
}

// pathKey creates a unique key for a path
func pathKey(path cipclient.CIPPath) string {
	return fmt.Sprintf("%04X:%04X:%02X", path.Class, path.Instance, path.Attribute)
}

