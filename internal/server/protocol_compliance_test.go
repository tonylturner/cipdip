package server

import (
	"testing"

	"github.com/tturner/cipdip/internal/cipclient"
)

var enipOrder = cipclient.CurrentProtocolProfile().ENIPByteOrder

// TestRegisterSessionODVACompliance validates RegisterSession response against ODVA spec
// ODVA EtherNet/IP Specification: RegisterSession response must:
// - Command: 0x0065 (RegisterSession)
// - Status: 0x00000000 (success) or error code
// - SessionID: Non-zero session identifier assigned by server
// - Length: 4 bytes (Protocol Version + Options Flags)
// - Data: Echo of request data (Protocol Version + Options Flags)
func TestRegisterSessionODVACompliance(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()
	server, _ := NewServer(cfg, logger)

	// RegisterSession request per ODVA spec
	registerData := []byte{0x01, 0x00, 0x00, 0x00} // Protocol version 1.0, no flags
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	encap := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandRegisterSession,
		Length:        uint16(len(registerData)),
		SessionID:     0,
		Status:        0,
		SenderContext: senderContext,
		Options:       0,
		Data:          registerData,
	}

	resp := server.handleRegisterSession(encap)
	respEncap, err := cipclient.DecodeENIP(resp)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	// Validate command code per ODVA spec
	if respEncap.Command != 0x0065 {
		t.Errorf("Command code: got 0x%04X, want 0x0065 (RegisterSession per ODVA spec)", respEncap.Command)
	}

	// Validate status per ODVA spec
	if respEncap.Status != 0x00000000 {
		t.Errorf("Status: got 0x%08X, want 0x00000000 (success per ODVA spec)", respEncap.Status)
	}

	// Validate session ID per ODVA spec (must be non-zero)
	if respEncap.SessionID == 0 {
		t.Error("Session ID must be non-zero per ODVA spec")
	}

	// Validate length per ODVA spec (must be 4 bytes: Protocol Version + Options Flags)
	if respEncap.Length != 4 {
		t.Errorf("Length: got %d, want 4 (Protocol Version + Options Flags per ODVA spec)", respEncap.Length)
	}

	// Validate data per ODVA spec (must echo request data)
	if len(respEncap.Data) != 4 {
		t.Fatalf("Data length: got %d, want 4", len(respEncap.Data))
	}

	for i := 0; i < 4; i++ {
		if respEncap.Data[i] != registerData[i] {
			t.Errorf("Data[%d]: got 0x%02X, want 0x%02X (must echo request per ODVA spec)", i, respEncap.Data[i], registerData[i])
		}
	}

	// Validate sender context is echoed per ODVA spec
	if respEncap.SenderContext != senderContext {
		t.Error("Sender context must be echoed per ODVA spec")
	}
}

// TestUnregisterSessionODVACompliance validates UnregisterSession response against ODVA spec
// ODVA EtherNet/IP Specification: UnregisterSession response must:
// - Command: 0x0066 (UnregisterSession)
// - Status: 0x00000000 (success) or error code
// - SessionID: Echo of request session ID
// - Length: 0 (no data)
func TestUnregisterSessionODVACompliance(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()
	server, _ := NewServer(cfg, logger)

	// First register a session
	registerData := []byte{0x01, 0x00, 0x00, 0x00}
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	registerEncap := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandRegisterSession,
		Length:        4,
		SessionID:     0,
		Status:        0,
		SenderContext: senderContext,
		Options:       0,
		Data:          registerData,
	}

	registerResp := server.handleRegisterSession(registerEncap)
	registerRespEncap, _ := cipclient.DecodeENIP(registerResp)
	sessionID := registerRespEncap.SessionID

	// Now test UnregisterSession
	unregisterEncap := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandUnregisterSession,
		Length:        0,
		SessionID:     sessionID,
		Status:        0,
		SenderContext: senderContext,
		Options:       0,
		Data:          nil,
	}

	resp := server.handleUnregisterSession(unregisterEncap)
	respEncap, err := cipclient.DecodeENIP(resp)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	// Validate command code per ODVA spec
	if respEncap.Command != 0x0066 {
		t.Errorf("Command code: got 0x%04X, want 0x0066 (UnregisterSession per ODVA spec)", respEncap.Command)
	}

	// Validate status per ODVA spec
	if respEncap.Status != 0x00000000 {
		t.Errorf("Status: got 0x%08X, want 0x00000000 (success per ODVA spec)", respEncap.Status)
	}

	// Validate session ID is echoed per ODVA spec
	if respEncap.SessionID != sessionID {
		t.Errorf("Session ID: got 0x%08X, want 0x%08X (must echo request per ODVA spec)", respEncap.SessionID, sessionID)
	}

	// Validate length per ODVA spec (must be 0)
	if respEncap.Length != 0 {
		t.Errorf("Length: got %d, want 0 (no data per ODVA spec)", respEncap.Length)
	}

	// Validate sender context is echoed per ODVA spec
	if respEncap.SenderContext != senderContext {
		t.Error("Sender context must be echoed per ODVA spec")
	}
}

// TestSendRRDataODVACompliance validates SendRRData response structure against ODVA spec
// ODVA EtherNet/IP Specification: SendRRData response must:
// - Command: 0x006F (SendRRData)
// - Status: 0x00000000 (success) or error code
// - SessionID: Echo of request session ID
// - Length: 6 + CIP data length (Interface Handle + Timeout + CIP data)
// - Data: Interface Handle (4 bytes) + Timeout (2 bytes) + CIP response data
func TestSendRRDataODVACompliance(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()
	server, _ := NewServer(cfg, logger)

	// Register a session first
	registerData := []byte{0x01, 0x00, 0x00, 0x00}
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	registerEncap := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandRegisterSession,
		Length:        4,
		SessionID:     0,
		Status:        0,
		SenderContext: senderContext,
		Options:       0,
		Data:          registerData,
	}

	registerResp := server.handleRegisterSession(registerEncap)
	registerRespEncap, _ := cipclient.DecodeENIP(registerResp)
	sessionID := registerRespEncap.SessionID

	// Build CIP request: Get_Attribute_Single for class 0x04, instance 0x65, attribute 0x03
	cipReq := cipclient.CIPRequest{
		Service: cipclient.CIPServiceGetAttributeSingle,
		Path: cipclient.CIPPath{
			Class:     0x04,
			Instance:  0x65,
			Attribute: 0x03,
		},
		Payload: nil,
	}

	cipData, _ := cipclient.EncodeCIPRequest(cipReq)

	// Build SendRRData request per ODVA spec
	sendRRData := cipclient.BuildSendRRDataPayload(cipData)

	sendRRDataEncap := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandSendRRData,
		Length:        uint16(len(sendRRData)),
		SessionID:     sessionID,
		Status:        0,
		SenderContext: senderContext,
		Options:       0,
		Data:          sendRRData,
	}

	resp := server.handleSendRRData(sendRRDataEncap, "127.0.0.1:12345")
	if resp == nil {
		t.Fatal("handleSendRRData returned nil")
	}

	respEncap, err := cipclient.DecodeENIP(resp)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	// Validate command code per ODVA spec
	if respEncap.Command != 0x006F {
		t.Errorf("Command code: got 0x%04X, want 0x006F (SendRRData per ODVA spec)", respEncap.Command)
	}

	// Validate status per ODVA spec
	if respEncap.Status != 0x00000000 {
		t.Errorf("Status: got 0x%08X, want 0x00000000 (success per ODVA spec)", respEncap.Status)
	}

	// Validate session ID is echoed per ODVA spec
	if respEncap.SessionID != sessionID {
		t.Errorf("Session ID: got 0x%08X, want 0x%08X (must echo request per ODVA spec)", respEncap.SessionID, sessionID)
	}

	// Validate length per ODVA spec (matches data length)
	if respEncap.Length != uint16(len(respEncap.Data)) {
		t.Errorf("Length: got %d, want %d (data length per ODVA spec)", respEncap.Length, len(respEncap.Data))
	}

	// Validate SendRRData response structure per ODVA spec
	if len(respEncap.Data) < 6 {
		t.Fatalf("Response data too short: got %d, want at least 6", len(respEncap.Data))
	}

	// Interface Handle (4 bytes) - should be 0 for UCMM per ODVA spec
	interfaceHandle := enipOrder.Uint32(respEncap.Data[0:4])
	if interfaceHandle != 0 {
		t.Errorf("Interface Handle: got 0x%08X, want 0x00000000 (UCMM per ODVA spec)", interfaceHandle)
	}

	// Timeout (2 bytes) - should be 0 per ODVA spec
	timeout := enipOrder.Uint16(respEncap.Data[4:6])
	if timeout != 0 {
		t.Errorf("Timeout: got 0x%04X, want 0x0000 (no timeout per ODVA spec)", timeout)
	}

	// Validate CIP response structure per ODVA spec
	// CIP response: Service code + status + optional reserved fields
	cipRespData, err := cipclient.ParseSendRRDataRequest(respEncap.Data)
	if err != nil {
		t.Fatalf("ParseSendRRDataRequest failed: %v", err)
	}
	if len(cipRespData) < 2 {
		t.Fatalf("CIP response too short: got %d, want at least 2", len(cipRespData))
	}

	// Service code should echo request (0x0E = Get_Attribute_Single)
	if cipRespData[0] != 0x0E {
		t.Errorf("CIP service code: got 0x%02X, want 0x0E (Get_Attribute_Single per ODVA spec)", cipRespData[0])
	}

	statusOffset := 1
	if cipclient.CurrentProtocolProfile().IncludeCIPRespReserved {
		statusOffset = 2
	}
	// Status should be 0x00 (success)
	if cipRespData[statusOffset] != 0x00 {
		t.Errorf("CIP status: got 0x%02X, want 0x00 (success per ODVA spec)", cipRespData[statusOffset])
	}
}

// TestCIPResponseODVACompliance validates CIP response structure against ODVA spec
// ODVA CIP Specification: Response structure must be:
// - Byte 0: Service code (echoed from request)
// - Byte 1: General status (0x00 = success)
// - Bytes 2+: Extended status (if status != 0x00) or Response data (if status == 0x00)
func TestCIPResponseODVACompliance(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()
	server, _ := NewServer(cfg, logger)

	// Register a session
	registerData := []byte{0x01, 0x00, 0x00, 0x00}
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	registerEncap := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandRegisterSession,
		Length:        4,
		SessionID:     0,
		Status:        0,
		SenderContext: senderContext,
		Options:       0,
		Data:          registerData,
	}

	registerResp := server.handleRegisterSession(registerEncap)
	registerRespEncap, _ := cipclient.DecodeENIP(registerResp)
	sessionID := registerRespEncap.SessionID

	// Build Get_Attribute_Single request
	cipReq := cipclient.CIPRequest{
		Service: cipclient.CIPServiceGetAttributeSingle,
		Path: cipclient.CIPPath{
			Class:     0x04,
			Instance:  0x65,
			Attribute: 0x03,
		},
		Payload: nil,
	}

	cipData, _ := cipclient.EncodeCIPRequest(cipReq)

	sendRRData := cipclient.BuildSendRRDataPayload(cipData)

	sendRRDataEncap := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandSendRRData,
		Length:        uint16(len(sendRRData)),
		SessionID:     sessionID,
		Status:        0,
		SenderContext: senderContext,
		Options:       0,
		Data:          sendRRData,
	}

	resp := server.handleSendRRData(sendRRDataEncap, "127.0.0.1:12345")
	respEncap, _ := cipclient.DecodeENIP(resp)

	// Extract CIP response
	cipRespData, err := cipclient.ParseSendRRDataRequest(respEncap.Data)
	if err != nil {
		t.Fatalf("ParseSendRRDataRequest failed: %v", err)
	}

	// Validate CIP response structure per ODVA spec
	if len(cipRespData) < 2 {
		t.Fatalf("CIP response too short: got %d, want at least 2 per ODVA spec", len(cipRespData))
	}

	// Byte 0: Service code (must echo request per ODVA spec)
	serviceCode := cipRespData[0]
	if serviceCode != 0x0E {
		t.Errorf("Service code: got 0x%02X, want 0x0E (Get_Attribute_Single per ODVA spec)", serviceCode)
	}

	// Byte 1: General status (must be 0x00 for success per ODVA spec)
	statusOffset := 1
	if cipclient.CurrentProtocolProfile().IncludeCIPRespReserved {
		statusOffset = 2
	}
	status := cipRespData[statusOffset]
	if status != 0x00 {
		t.Errorf("Status: got 0x%02X, want 0x00 (success per ODVA spec)", status)
	}

	// Bytes 2+: Response data (must be present for success per ODVA spec)
	minPayloadOffset := 2
	if cipclient.CurrentProtocolProfile().IncludeCIPRespReserved {
		minPayloadOffset = 4
	}
	if len(cipRespData) < minPayloadOffset+1 {
		t.Error("Response data must be present for successful Get_Attribute_Single per ODVA spec")
	}
}

// TestCIPErrorResponseODVACompliance validates CIP error response structure against ODVA spec
// ODVA CIP Specification: Error response structure must be:
// - Byte 0: Service code (echoed from request)
// - Byte 1: General status (non-zero error code)
// - Byte 2: Extended status size
// - Bytes 3+: Extended status bytes
func TestCIPErrorResponseODVACompliance(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()
	server, _ := NewServer(cfg, logger)

	// Register a session
	registerData := []byte{0x01, 0x00, 0x00, 0x00}
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	registerEncap := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandRegisterSession,
		Length:        4,
		SessionID:     0,
		Status:        0,
		SenderContext: senderContext,
		Options:       0,
		Data:          registerData,
	}

	registerResp := server.handleRegisterSession(registerEncap)
	registerRespEncap, _ := cipclient.DecodeENIP(registerResp)
	sessionID := registerRespEncap.SessionID

	// Build Get_Attribute_Single request for non-existent assembly
	cipReq := cipclient.CIPRequest{
		Service: cipclient.CIPServiceGetAttributeSingle,
		Path: cipclient.CIPPath{
			Class:     0x04,
			Instance:  0x99, // Non-existent instance
			Attribute: 0x03,
		},
		Payload: nil,
	}

	cipData, _ := cipclient.EncodeCIPRequest(cipReq)

	sendRRData := cipclient.BuildSendRRDataPayload(cipData)

	sendRRDataEncap := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandSendRRData,
		Length:        uint16(len(sendRRData)),
		SessionID:     sessionID,
		Status:        0,
		SenderContext: senderContext,
		Options:       0,
		Data:          sendRRData,
	}

	resp := server.handleSendRRData(sendRRDataEncap, "127.0.0.1:12345")
	respEncap, _ := cipclient.DecodeENIP(resp)

	// Extract CIP response
	cipRespData, err := cipclient.ParseSendRRDataRequest(respEncap.Data)
	if err != nil {
		t.Fatalf("ParseSendRRDataRequest failed: %v", err)
	}

	// Validate CIP error response structure per ODVA spec
	if len(cipRespData) < 2 {
		t.Fatalf("CIP error response too short: got %d, want at least 2 per ODVA spec", len(cipRespData))
	}

	// Byte 0: Service code (must echo request per ODVA spec)
	serviceCode := cipRespData[0]
	if serviceCode != 0x0E {
		t.Errorf("Service code: got 0x%02X, want 0x0E (Get_Attribute_Single per ODVA spec)", serviceCode)
	}

	// Byte 1: General status (must be non-zero for error per ODVA spec)
	statusOffset := 1
	if cipclient.CurrentProtocolProfile().IncludeCIPRespReserved {
		statusOffset = 2
	}
	status := cipRespData[statusOffset]
	if status == 0x00 {
		t.Error("Status must be non-zero for error response per ODVA spec")
	}

	// Status 0x01 = General error (per ODVA spec)
	if status != 0x01 {
		t.Errorf("Status: got 0x%02X, want 0x01 (general error per ODVA spec)", status)
	}
}

// TestENIPErrorResponseODVACompliance validates ENIP error response structure against ODVA spec
// ODVA EtherNet/IP Specification: Error response must:
// - Command: Echo of request command
// - Status: Non-zero error code
// - SessionID: Echo of request session ID (if session exists)
// - Length: 0 (no data for most errors)
func TestENIPErrorResponseODVACompliance(t *testing.T) {
	cfg := createTestServerConfig()
	logger := createTestLogger()
	server, _ := NewServer(cfg, logger)

	// Test invalid session ID
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	sendRRDataEncap := cipclient.ENIPEncapsulation{
		Command:       cipclient.ENIPCommandSendRRData,
		Length:        6,
		SessionID:     0x12345678, // Invalid session ID
		Status:        0,
		SenderContext: senderContext,
		Options:       0,
		Data:          []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}

	resp := server.handleSendRRData(sendRRDataEncap, "127.0.0.1:12345")
	if resp == nil {
		t.Fatal("handleSendRRData returned nil")
	}

	respEncap, err := cipclient.DecodeENIP(resp)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	// Validate error response per ODVA spec
	if respEncap.Command != cipclient.ENIPCommandSendRRData {
		t.Errorf("Command: got 0x%04X, want 0x%04X (must echo request per ODVA spec)", respEncap.Command, cipclient.ENIPCommandSendRRData)
	}

	// Status must be non-zero for error per ODVA spec
	if respEncap.Status == 0x00000000 {
		t.Error("Status must be non-zero for error response per ODVA spec")
	}

	// Status 0x00000064 = Invalid session handle (per ODVA EtherNet/IP spec, status code 100)
	if respEncap.Status != 0x00000064 {
		t.Errorf("Status: got 0x%08X, want 0x00000064 (invalid session handle per ODVA spec)", respEncap.Status)
	}

	// Session ID must be echoed per ODVA spec
	if respEncap.SessionID != 0x12345678 {
		t.Errorf("Session ID: got 0x%08X, want 0x12345678 (must echo request per ODVA spec)", respEncap.SessionID)
	}

	// Length should be 0 for error response per ODVA spec
	if respEncap.Length != 0 {
		t.Errorf("Length: got %d, want 0 (no data for error per ODVA spec)", respEncap.Length)
	}
}
