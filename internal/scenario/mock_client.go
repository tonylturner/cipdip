package scenario

import (
	"context"
	"fmt"
	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
	"sync"

	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
)

// MockClient is a mock implementation of cipclient.Client for testing
type MockClient struct {
	connected       bool
	connectError    error
	disconnectError error
	readResponses   map[string]protocol.CIPResponse
	readErrors      map[string]error
	writeResponses  map[string]protocol.CIPResponse
	writeErrors     map[string]error
	readCount       map[string]int
	writeCount      map[string]int
	mu              sync.RWMutex

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
		readResponses:  make(map[string]protocol.CIPResponse),
		readErrors:     make(map[string]error),
		writeResponses: make(map[string]protocol.CIPResponse),
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

// IsConnected returns true if the mock client is connected
func (m *MockClient) IsConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connected
}

// InvokeService simulates service invocation
func (m *MockClient) InvokeService(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, error) {
	// Not used by scenarios directly, but implement for interface compliance
	return protocol.CIPResponse{}, nil
}

// ReadAttribute simulates reading an attribute
func (m *MockClient) ReadAttribute(ctx context.Context, path protocol.CIPPath) (protocol.CIPResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := pathKey(path)
	m.readCount[key]++

	if err, ok := m.readErrors[key]; ok {
		return protocol.CIPResponse{}, err
	}

	if resp, ok := m.readResponses[key]; ok {
		return resp, nil
	}

	// Default success response
	return protocol.CIPResponse{
		Service: spec.CIPServiceGetAttributeSingle,
		Status:  0x00,
		Path:    path,
		Payload: make([]byte, 16),
	}, nil
}

// WriteAttribute simulates writing an attribute
func (m *MockClient) WriteAttribute(ctx context.Context, path protocol.CIPPath, value []byte) (protocol.CIPResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := pathKey(path)
	m.writeCount[key]++

	if err, ok := m.writeErrors[key]; ok {
		return protocol.CIPResponse{}, err
	}

	if resp, ok := m.writeResponses[key]; ok {
		return resp, nil
	}

	// Default success response
	return protocol.CIPResponse{
		Service: spec.CIPServiceSetAttributeSingle,
		Status:  0x00,
		Path:    path,
	}, nil
}

// ReadTag simulates reading a tag via Read_Tag
func (m *MockClient) ReadTag(ctx context.Context, path protocol.CIPPath, elementCount uint16) (protocol.CIPResponse, error) {
	return protocol.CIPResponse{
		Service: spec.CIPServiceReadTag,
		Status:  0x00,
		Path:    path,
		Payload: make([]byte, 4),
	}, nil
}

// ReadTagByName simulates reading a tag by symbolic name.
func (m *MockClient) ReadTagByName(ctx context.Context, tag string, elementCount uint16) (protocol.CIPResponse, error) {
	return m.ReadTag(ctx, protocol.CIPPath{Name: tag}, elementCount)
}

// WriteTag simulates writing a tag via Write_Tag
func (m *MockClient) WriteTag(ctx context.Context, path protocol.CIPPath, typeCode uint16, elementCount uint16, data []byte) (protocol.CIPResponse, error) {
	return protocol.CIPResponse{
		Service: spec.CIPServiceWriteTag,
		Status:  0x00,
		Path:    path,
	}, nil
}

// WriteTagByName simulates writing a tag by symbolic name.
func (m *MockClient) WriteTagByName(ctx context.Context, tag string, typeCode uint16, elementCount uint16, data []byte) (protocol.CIPResponse, error) {
	return m.WriteTag(ctx, protocol.CIPPath{Name: tag}, typeCode, elementCount, data)
}

// ReadTagFragmented simulates a fragmented tag read.
func (m *MockClient) ReadTagFragmented(ctx context.Context, path protocol.CIPPath, elementCount uint16, byteOffset uint32) (protocol.CIPResponse, error) {
	return protocol.CIPResponse{
		Service: spec.CIPServiceReadTagFragmented,
		Status:  0x00,
		Path:    path,
		Payload: make([]byte, 4),
	}, nil
}

// ReadTagFragmentedByName simulates a fragmented tag read by symbolic name.
func (m *MockClient) ReadTagFragmentedByName(ctx context.Context, tag string, elementCount uint16, byteOffset uint32) (protocol.CIPResponse, error) {
	return m.ReadTagFragmented(ctx, protocol.CIPPath{Name: tag}, elementCount, byteOffset)
}

// WriteTagFragmented simulates a fragmented tag write.
func (m *MockClient) WriteTagFragmented(ctx context.Context, path protocol.CIPPath, typeCode uint16, elementCount uint16, byteOffset uint32, data []byte) (protocol.CIPResponse, error) {
	return protocol.CIPResponse{
		Service: spec.CIPServiceWriteTagFragmented,
		Status:  0x00,
		Path:    path,
	}, nil
}

// WriteTagFragmentedByName simulates a fragmented tag write by symbolic name.
func (m *MockClient) WriteTagFragmentedByName(ctx context.Context, tag string, typeCode uint16, elementCount uint16, byteOffset uint32, data []byte) (protocol.CIPResponse, error) {
	return m.WriteTagFragmented(ctx, protocol.CIPPath{Name: tag}, typeCode, elementCount, byteOffset, data)
}

// FileInitiateUpload simulates a File Object initiate upload.
func (m *MockClient) FileInitiateUpload(ctx context.Context, instance uint16, payload []byte) (protocol.CIPResponse, error) {
	return protocol.CIPResponse{Service: spec.CIPServiceInitiateUpload, Status: 0x00}, nil
}

// FileInitiateDownload simulates a File Object initiate download.
func (m *MockClient) FileInitiateDownload(ctx context.Context, instance uint16, payload []byte) (protocol.CIPResponse, error) {
	return protocol.CIPResponse{Service: spec.CIPServiceInitiateDownload, Status: 0x00}, nil
}

// FileInitiatePartialRead simulates a File Object initiate partial read.
func (m *MockClient) FileInitiatePartialRead(ctx context.Context, instance uint16, payload []byte) (protocol.CIPResponse, error) {
	return protocol.CIPResponse{Service: spec.CIPServiceInitiatePartialRead, Status: 0x00}, nil
}

// FileInitiatePartialWrite simulates a File Object initiate partial write.
func (m *MockClient) FileInitiatePartialWrite(ctx context.Context, instance uint16, payload []byte) (protocol.CIPResponse, error) {
	return protocol.CIPResponse{Service: spec.CIPServiceInitiatePartialWrite, Status: 0x00}, nil
}

// FileUploadTransfer simulates a File Object upload transfer.
func (m *MockClient) FileUploadTransfer(ctx context.Context, instance uint16, payload []byte) (protocol.CIPResponse, error) {
	return protocol.CIPResponse{Service: spec.CIPServiceUploadTransfer, Status: 0x00}, nil
}

// FileDownloadTransfer simulates a File Object download transfer.
func (m *MockClient) FileDownloadTransfer(ctx context.Context, instance uint16, payload []byte) (protocol.CIPResponse, error) {
	return protocol.CIPResponse{Service: spec.CIPServiceDownloadTransfer, Status: 0x00}, nil
}

// FileClear simulates a File Object clear file.
func (m *MockClient) FileClear(ctx context.Context, instance uint16, payload []byte) (protocol.CIPResponse, error) {
	return protocol.CIPResponse{Service: spec.CIPServiceClearFile, Status: 0x00}, nil
}

// InvokeUnconnectedSend simulates an Unconnected Send with embedded response.
func (m *MockClient) InvokeUnconnectedSend(ctx context.Context, embeddedReq protocol.CIPRequest, opts cipclient.UnconnectedSendOptions) (protocol.CIPResponse, protocol.CIPResponse, error) {
	outer := protocol.CIPResponse{
		Service: spec.CIPServiceUnconnectedSend,
		Status:  0x00,
		Path:    protocol.CIPPath{Class: 0x0006, Instance: 0x0001},
	}
	embedded := protocol.CIPResponse{
		Service: embeddedReq.Service,
		Status:  0x00,
		Path:    embeddedReq.Path,
	}
	return outer, embedded, nil
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
func (m *MockClient) SetReadResponse(path protocol.CIPPath, resp protocol.CIPResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := pathKey(path)
	m.readResponses[key] = resp
}

// SetReadError sets an error for a specific path
func (m *MockClient) SetReadError(path protocol.CIPPath, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := pathKey(path)
	m.readErrors[key] = err
}

// SetWriteResponse sets a response for a specific path
func (m *MockClient) SetWriteResponse(path protocol.CIPPath, resp protocol.CIPResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := pathKey(path)
	m.writeResponses[key] = resp
}

// SetWriteError sets an error for a specific path
func (m *MockClient) SetWriteError(path protocol.CIPPath, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := pathKey(path)
	m.writeErrors[key] = err
}

// GetReadCount returns the number of reads for a path
func (m *MockClient) GetReadCount(path protocol.CIPPath) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := pathKey(path)
	return m.readCount[key]
}

// GetWriteCount returns the number of writes for a path
func (m *MockClient) GetWriteCount(path protocol.CIPPath) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := pathKey(path)
	return m.writeCount[key]
}

// pathKey creates a unique key for a path
func pathKey(path protocol.CIPPath) string {
	return fmt.Sprintf("%04X:%04X:%04X", path.Class, path.Instance, path.Attribute)
}


