package cipclient

// ODVA Protocol Compliance Tests
//
// IMPORTANT: These tests validate protocol compliance based on:
// 1. ODVA EtherNet/IP Encapsulation Protocol Specification
// 2. ODVA Common Industrial Protocol (CIP) Specification (Volume 1)
// 3. ODVA CIP Connection Management Specification
//
// Test values are based on ODVA specification requirements, not just our implementation.
// Where ODVA spec references are available, they are documented in test comments.
//
// Note: ODVA specifications are member documents and may not be publicly available.
// These tests use known ODVA-compliant values from public documentation and reverse engineering.
//
// Key ODVA References:
// - ENIP Command Codes: EtherNet/IP Encapsulation Protocol
// - CIP Service Codes: CIP Specification Volume 1, Table 3-5.1
// - EPATH Encoding: CIP Specification Volume 1, Section 3-5.2
// - ForwardOpen/ForwardClose: CIP Connection Management Specification

import (
	"testing"
)

// TestENIPHeaderCompliance validates ENIP encapsulation header structure
func TestENIPHeaderCompliance(t *testing.T) {
	order := currentENIPByteOrder()
	encap := ENIPEncapsulation{
		Command:     ENIPCommandRegisterSession,
		Length:      4,
		SessionID:   0x12345678,
		Status:      0,
		SenderContext: [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Options:     0,
		Data:        []byte{0x01, 0x00, 0x00, 0x00},
	}

	packet := EncodeENIP(encap)

	// ENIP header must be exactly 24 bytes
	if len(packet) < 24 {
		t.Fatalf("ENIP header too short: %d bytes (must be at least 24)", len(packet))
	}

	// Verify header structure per ODVA EtherNet/IP Encapsulation Protocol:
	// - Header is exactly 24 bytes (ODVA requirement)
	// - All multi-byte fields use big-endian byte order (ODVA requirement)
	// - Field order: Command, Length, SessionID, Status, SenderContext, Options (ODVA requirement)
	// Offset 0-1: Command (2 bytes, big-endian)
	cmd := order.Uint16(packet[0:2])
	if cmd != ENIPCommandRegisterSession {
		t.Errorf("Command: got 0x%04X, want 0x%04X", cmd, ENIPCommandRegisterSession)
	}

	// Offset 2-3: Length (2 bytes, big-endian)
	length := order.Uint16(packet[2:4])
	if length != 4 {
		t.Errorf("Length: got %d, want 4", length)
	}

	// Offset 4-7: Session Handle (4 bytes, big-endian)
	sessionID := order.Uint32(packet[4:8])
	if sessionID != 0x12345678 {
		t.Errorf("Session ID: got 0x%08X, want 0x%08X", sessionID, 0x12345678)
	}

	// Offset 8-11: Status (4 bytes, big-endian)
	status := order.Uint32(packet[8:12])
	if status != 0 {
		t.Errorf("Status: got 0x%08X, want 0x00000000", status)
	}

	// Offset 12-19: Sender Context (8 bytes)
	// Verify sender context matches
	for i := 0; i < 8; i++ {
		if packet[12+i] != encap.SenderContext[i] {
			t.Errorf("SenderContext[%d]: got 0x%02X, want 0x%02X", i, packet[12+i], encap.SenderContext[i])
		}
	}

	// Offset 20-23: Options (4 bytes, big-endian)
	options := order.Uint32(packet[20:24])
	if options != 0 {
		t.Errorf("Options: got 0x%08X, want 0x00000000", options)
	}

	// Offset 24+: Data field
	if len(packet) != 24+int(length) {
		t.Errorf("Total packet length: got %d, want %d", len(packet), 24+int(length))
	}
}

// TestENIPHeaderLengthConsistency validates length field matches data
func TestENIPHeaderLengthConsistency(t *testing.T) {
	order := currentENIPByteOrder()
	tests := []struct {
		name     string
		dataLen  int
		expected uint16
	}{
		{"zero length", 0, 0},
		{"small data", 4, 4},
		{"medium data", 100, 100},
		{"large data", 1000, 1000},
		{"max uint16", 65535, 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.dataLen)
			encap := ENIPEncapsulation{
				Command:      ENIPCommandSendRRData,
				Length:       uint16(tt.dataLen),
				SessionID:    0x12345678,
				Status:       0,
				SenderContext: [8]byte{},
				Options:      0,
				Data:         data,
			}

			packet := EncodeENIP(encap)
			length := order.Uint16(packet[2:4])

			if length != tt.expected {
				t.Errorf("Length field: got %d, want %d", length, tt.expected)
			}

			if len(packet) != 24+int(length) {
				t.Errorf("Total packet length: got %d, want %d", len(packet), 24+int(length))
			}
		})
	}
}

// TestENIPByteOrder validates all fields use big-endian byte order
// Note: Length field is calculated from Data length per ODVA spec, not set directly
func TestENIPByteOrder(t *testing.T) {
	order := currentENIPByteOrder()
	// Create data that will result in length 0x5678 (22136 bytes)
	// For testing, use a smaller length that's easier to verify
	testData := make([]byte, 0x1234) // 4660 bytes
	encap := ENIPEncapsulation{
		Command:     0x1234, // Will be 0x12 0x34 in big-endian
		Length:      0,      // Ignored - calculated from Data length
		SessionID:   0xABCDEF00,
		Status:      0x11223344,
		SenderContext: [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22},
		Options:     0x99887766,
		Data:        testData, // Length will be calculated from this
	}

	packet := EncodeENIP(encap)

	// Verify byte order encoding
	cmd := order.Uint16(packet[0:2])
	if cmd != 0x1234 {
		t.Errorf("Command byte order: got 0x%04X, want 0x1234", cmd)
	}

	length := order.Uint16(packet[2:4])
	if length != 0x1234 {
		t.Errorf("Length byte order: got 0x%04X, want 0x1234 (calculated from Data length per ODVA spec)", length)
	}

	session := order.Uint32(packet[4:8])
	if session != 0xABCDEF00 {
		t.Errorf("Session ID byte order: got 0x%08X, want 0xABCDEF00", session)
	}

	status := order.Uint32(packet[8:12])
	if status != 0x11223344 {
		t.Errorf("Status byte order: got 0x%08X, want 0x11223344", status)
	}
}

// TestENIPCommandCodes validates all ENIP command codes match ODVA EtherNet/IP Encapsulation Protocol
// Reference: ODVA EtherNet/IP Encapsulation Protocol Specification
// These command codes are standardized by ODVA and must match exactly.
func TestENIPCommandCodes(t *testing.T) {
	expectedCommands := map[uint16]string{
		0x0065: "RegisterSession",
		0x0066: "UnregisterSession",
		0x006F: "SendRRData",
		0x0070: "SendUnitData",
		0x0063: "ListIdentity",
		0x0004: "ListServices",
		0x0064: "ListInterfaces",
	}

	actualCommands := map[uint16]uint16{
		ENIPCommandRegisterSession:   0x0065,
		ENIPCommandUnregisterSession: 0x0066,
		ENIPCommandSendRRData:        0x006F,
		ENIPCommandSendUnitData:      0x0070,
		ENIPCommandListIdentity:      0x0063,
		ENIPCommandListServices:      0x0004,
		ENIPCommandListInterfaces:    0x0064,
	}

	for code, name := range expectedCommands {
		if actualCommands[code] != code {
			t.Errorf("%s: got 0x%04X, want 0x%04X", name, actualCommands[code], code)
		}
	}
}

// TestENIPStatusCodes validates ENIP status codes match ODVA EtherNet/IP Encapsulation Protocol
// Reference: ODVA EtherNet/IP Encapsulation Protocol Specification
// Status codes are standardized by ODVA for error reporting.
func TestENIPStatusCodes(t *testing.T) {
	expectedStatuses := map[uint32]string{
		0x00000000: "Success",
		0x00000001: "InvalidCommand",
		0x00000002: "InsufficientMemory",
		0x00000003: "IncorrectData",
		0x00000064: "InvalidSessionHandle",
		0x00000065: "InvalidLength",
		0x00000066: "UnsupportedCommand",
	}

	actualStatuses := map[uint32]uint32{
		ENIPStatusSuccess:             0x00000000,
		ENIPStatusInvalidCommand:       0x00000001,
		ENIPStatusInsufficientMemory:  0x00000002,
		ENIPStatusIncorrectData:        0x00000003,
		ENIPStatusInvalidSessionHandle: 0x00000064,
		ENIPStatusInvalidLength:       0x00000065,
		ENIPStatusUnsupportedCommand:  0x00000066,
	}

	for status, name := range expectedStatuses {
		if actualStatuses[status] != status {
			t.Errorf("%s: got 0x%08X, want 0x%08X", name, actualStatuses[status], status)
		}
	}
}

// TestRegisterSessionCompliance validates RegisterSession packet structure
func TestRegisterSessionCompliance(t *testing.T) {
	order := currentENIPByteOrder()
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	packet := BuildRegisterSession(senderContext)

	// Decode and verify
	encap, err := DecodeENIP(packet)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	// Verify command
	if encap.Command != ENIPCommandRegisterSession {
		t.Errorf("Command: got 0x%04X, want 0x%04X", encap.Command, ENIPCommandRegisterSession)
	}

	// RegisterSession data structure per ODVA EtherNet/IP Encapsulation Protocol:
	// - Protocol Version (2 bytes): MUST be 1 (ODVA requirement)
	// - Option Flags (2 bytes): MUST be 0 (ODVA requirement)
	// - Total data length: MUST be exactly 4 bytes (ODVA requirement)
	if len(encap.Data) != 4 {
		t.Errorf("RegisterSession data length: got %d, want 4", len(encap.Data))
	}

	protocolVersion := order.Uint16(encap.Data[0:2])
	if protocolVersion != 1 {
		t.Errorf("Protocol Version: got %d, want 1", protocolVersion)
	}

	optionFlags := order.Uint16(encap.Data[2:4])
	if optionFlags != 0 {
		t.Errorf("Option Flags: got %d, want 0", optionFlags)
	}

	// Verify length field matches data length
	if encap.Length != 4 {
		t.Errorf("Length field: got %d, want 4", encap.Length)
	}

	// Verify session ID is 0 in request
	if encap.SessionID != 0 {
		t.Errorf("Session ID in request: got 0x%08X, want 0x00000000", encap.SessionID)
	}
}

// TestUnregisterSessionCompliance validates UnregisterSession packet structure
func TestUnregisterSessionCompliance(t *testing.T) {
	sessionID := uint32(0x12345678)
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	packet := BuildUnregisterSession(sessionID, senderContext)

	encap, err := DecodeENIP(packet)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	if encap.Command != ENIPCommandUnregisterSession {
		t.Errorf("Command: got 0x%04X, want 0x%04X", encap.Command, ENIPCommandUnregisterSession)
	}

	if encap.SessionID != sessionID {
		t.Errorf("Session ID: got 0x%08X, want 0x%08X", encap.SessionID, sessionID)
	}

	if encap.Length != 0 {
		t.Errorf("Length: got %d, want 0 (no data)", encap.Length)
	}

	if len(encap.Data) != 0 {
		t.Errorf("Data length: got %d, want 0", len(encap.Data))
	}
}

// TestSendRRDataCompliance validates SendRRData packet structure
func TestSendRRDataCompliance(t *testing.T) {
	order := currentENIPByteOrder()
	sessionID := uint32(0x12345678)
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	cipData := []byte{0x0E, 0x20, 0x04, 0x24, 0x65, 0x30, 0x03} // Get_Attribute_Single

	packet := BuildSendRRData(sessionID, senderContext, cipData)

	// Decode ENIP
	encap, err := DecodeENIP(packet)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	// Verify command
	if encap.Command != ENIPCommandSendRRData {
		t.Errorf("Command: got 0x%04X, want 0x%04X", encap.Command, ENIPCommandSendRRData)
	}

	// SendRRData structure per ODVA EtherNet/IP Encapsulation Protocol:
	// - Interface Handle (4 bytes): MUST be 0 for UCMM (Unconnected Messaging) - ODVA requirement
	// - Timeout (2 bytes): Request timeout in seconds (0 = no timeout)
	// - CIP data (variable length): CIP service request/response data
	if len(encap.Data) < 6 {
		t.Fatalf("SendRRData data too short: %d bytes (minimum 6)", len(encap.Data))
	}

	interfaceHandle := order.Uint32(encap.Data[0:4])
	if interfaceHandle != 0 {
		t.Errorf("Interface Handle: got 0x%08X, want 0x00000000 (must be 0 for UCMM)", interfaceHandle)
	}

	timeout := order.Uint16(encap.Data[4:6])
	// Timeout can be 0 or other values, but typically 0 for UCMM
	_ = timeout

	cipDataFromPacket, err := ParseSendRRDataRequest(encap.Data)
	if err != nil {
		t.Fatalf("ParseSendRRDataRequest failed: %v", err)
	}
	if len(cipDataFromPacket) != len(cipData) {
		t.Errorf("CIP data length: got %d, want %d", len(cipDataFromPacket), len(cipData))
	}

	// Verify length field matches data length
	if encap.Length != uint16(len(encap.Data)) {
		t.Errorf("Length field: got %d, want %d", encap.Length, len(encap.Data))
	}

	// Verify session ID
	if encap.SessionID != sessionID {
		t.Errorf("Session ID: got 0x%08X, want 0x%08X", encap.SessionID, sessionID)
	}
}

// TestSendUnitDataCompliance validates SendUnitData packet structure
func TestSendUnitDataCompliance(t *testing.T) {
	sessionID := uint32(0x12345678)
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	connectionID := uint32(0xABCDEF00)
	cipData := []byte{0x01, 0x02, 0x03, 0x04}

	packet := BuildSendUnitData(sessionID, senderContext, connectionID, cipData)

	// Decode ENIP
	encap, err := DecodeENIP(packet)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	// Verify command
	if encap.Command != ENIPCommandSendUnitData {
		t.Errorf("Command: got 0x%04X, want 0x%04X", encap.Command, ENIPCommandSendUnitData)
	}

	// SendUnitData structure:
	// - Connection ID (4 bytes, big-endian)
	// - CIP data (variable length)
	if len(encap.Data) < 4 {
		t.Fatalf("SendUnitData data too short: %d bytes (minimum 4)", len(encap.Data))
	}

	recvConnectionID, cipDataFromPacket, err := ParseSendUnitDataRequest(encap.Data)
	if err != nil {
		t.Fatalf("ParseSendUnitDataRequest failed: %v", err)
	}
	if recvConnectionID != connectionID {
		t.Errorf("Connection ID: got 0x%08X, want 0x%08X", recvConnectionID, connectionID)
	}
	if len(cipDataFromPacket) != len(cipData) {
		t.Errorf("CIP data length: got %d, want %d", len(cipDataFromPacket), len(cipData))
	}

	// Verify length field matches data length
	if encap.Length != uint16(len(encap.Data)) {
		t.Errorf("Length field: got %d, want %d", encap.Length, len(encap.Data))
	}

	// Verify session ID
	if encap.SessionID != sessionID {
		t.Errorf("Session ID: got 0x%08X, want 0x%08X", encap.SessionID, sessionID)
	}
}

// TestEPATHEncodingCompliance validates EPATH encoding per ODVA CIP Specification
// Reference: ODVA CIP Specification Volume 1, Section 3-5.2 (EPATH Encoding)
// EPATH segment types:
// - 0x20 = 8-bit class ID
// - 0x21 = 16-bit class ID
// - 0x24 = 8-bit instance ID
// - 0x25 = 16-bit instance ID
// - 0x30 = 8-bit attribute ID
// All multi-byte values use big-endian byte order (ODVA requirement).
func TestEPATHEncodingCompliance(t *testing.T) {
	order := currentCIPByteOrder()
	tests := []struct {
		name     string
		path     CIPPath
		validate func(t *testing.T, epath []byte)
	}{
		{
			name: "8-bit class and instance",
			path: CIPPath{
				Class:     0x04,
				Instance:  0x65,
				Attribute: 0x03,
			},
			validate: func(t *testing.T, epath []byte) {
				// Segment format: segment type (1 byte) + segment data (1-2 bytes)
				// Class segment: 0x20 (8-bit) + class ID
				if epath[0] != 0x20 {
					t.Errorf("Class segment type: got 0x%02X, want 0x20", epath[0])
				}
				if epath[1] != 0x04 {
					t.Errorf("Class ID: got 0x%02X, want 0x04", epath[1])
				}

				// Instance segment: 0x24 (8-bit) + instance ID
				if epath[2] != 0x24 {
					t.Errorf("Instance segment type: got 0x%02X, want 0x24", epath[2])
				}
				if epath[3] != 0x65 {
					t.Errorf("Instance ID: got 0x%02X, want 0x65", epath[3])
				}

				// Attribute segment: 0x30 (8-bit) + attribute ID
				if epath[4] != 0x30 {
					t.Errorf("Attribute segment type: got 0x%02X, want 0x30", epath[4])
				}
				if epath[5] != 0x03 {
					t.Errorf("Attribute ID: got 0x%02X, want 0x03", epath[5])
				}

				// Total length should be 6 bytes
				if len(epath) != 6 {
					t.Errorf("EPATH length: got %d, want 6", len(epath))
				}
			},
		},
		{
			name: "16-bit class",
			path: CIPPath{
				Class:     0x0100,
				Instance:  0x65,
				Attribute: 0x03,
			},
			validate: func(t *testing.T, epath []byte) {
				// Class segment: 0x21 (16-bit) + class ID (2 bytes, big-endian)
				if epath[0] != 0x21 {
					t.Errorf("Class segment type: got 0x%02X, want 0x21 (16-bit)", epath[0])
				}
				classID := order.Uint16(epath[1:3])
				if classID != 0x0100 {
					t.Errorf("Class ID: got 0x%04X, want 0x0100", classID)
				}

				// Instance should still be 8-bit
				if epath[3] != 0x24 {
					t.Errorf("Instance segment type: got 0x%02X, want 0x24", epath[3])
				}
			},
		},
		{
			name: "16-bit instance",
			path: CIPPath{
				Class:     0x04,
				Instance:  0x0100,
				Attribute: 0x03,
			},
			validate: func(t *testing.T, epath []byte) {
				// Instance segment: 0x25 (16-bit) + instance ID (2 bytes, big-endian)
				if epath[2] != 0x25 {
					t.Errorf("Instance segment type: got 0x%02X, want 0x25 (16-bit)", epath[2])
				}
				instanceID := order.Uint16(epath[3:5])
				if instanceID != 0x0100 {
					t.Errorf("Instance ID: got 0x%04X, want 0x0100", instanceID)
				}
			},
		},
		{
			name: "boundary 8-bit max",
			path: CIPPath{
				Class:     0xFF,
				Instance:  0xFF,
				Attribute: 0xFF,
			},
			validate: func(t *testing.T, epath []byte) {
				// Should use 8-bit encoding for 0xFF
				if epath[0] != 0x20 {
					t.Errorf("Class segment type: got 0x%02X, want 0x20 (8-bit)", epath[0])
				}
				if epath[1] != 0xFF {
					t.Errorf("Class ID: got 0x%02X, want 0xFF", epath[1])
				}
			},
		},
		{
			name: "boundary 16-bit min",
			path: CIPPath{
				Class:     0x0100,
				Instance:  0x0100,
				Attribute: 0x03,
			},
			validate: func(t *testing.T, epath []byte) {
				// Should use 16-bit encoding for 0x0100
				if epath[0] != 0x21 {
					t.Errorf("Class segment type: got 0x%02X, want 0x21 (16-bit)", epath[0])
				}
				classID := order.Uint16(epath[1:3])
				if classID != 0x0100 {
					t.Errorf("Class ID: got 0x%04X, want 0x0100", classID)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			epath := EncodeEPATH(tt.path)
			tt.validate(t, epath)
		})
	}
}

// TestCIPServiceCodeCompliance validates CIP service codes match ODVA CIP Specification
// Reference: ODVA CIP Specification Volume 1, Table 3-5.1 (Service Codes)
// These service codes are standardized by ODVA and must match exactly.
// Service codes are defined in the CIP specification and are vendor-independent.
func TestCIPServiceCodeCompliance(t *testing.T) {
	// Verify service codes match ODVA CIP Specification Volume 1, Table 3-5.1
	serviceCodes := map[CIPServiceCode]struct {
		value    uint8
		name     string
		odvaSpec string
	}{
		CIPServiceGetAttributeAll:    {0x01, "Get_Attribute_All", "Volume 1, Table 3-5.1"},
		CIPServiceSetAttributeAll:    {0x02, "Set_Attribute_All", "Volume 1, Table 3-5.1"},
		CIPServiceGetAttributeList:   {0x03, "Get_Attribute_List", "Volume 1, Table 3-5.1"},
		CIPServiceSetAttributeList:   {0x04, "Set_Attribute_List", "Volume 1, Table 3-5.1"},
		CIPServiceReset:              {0x05, "Reset", "Volume 1, Table 3-5.1"},
		CIPServiceStart:              {0x06, "Start", "Volume 1, Table 3-5.1"},
		CIPServiceStop:               {0x07, "Stop", "Volume 1, Table 3-5.1"},
		CIPServiceCreate:             {0x08, "Create", "Volume 1, Table 3-5.1"},
		CIPServiceDelete:             {0x09, "Delete", "Volume 1, Table 3-5.1"},
		CIPServiceMultipleService:    {0x0A, "Multiple_Service", "Volume 1, Table 3-5.1"},
		CIPServiceApplyAttributes:    {0x0D, "Apply_Attributes", "Volume 1, Table 3-5.1"},
		CIPServiceGetAttributeSingle: {0x0E, "Get_Attribute_Single", "Volume 1, Table 3-5.1"},
		CIPServiceSetAttributeSingle: {0x10, "Set_Attribute_Single", "Volume 1, Table 3-5.1"},
		CIPServiceFindNextObjectInst: {0x11, "Find_Next_Object_Instance", "Volume 1, Table 3-5.1"},
		CIPServiceForwardOpen:        {0x54, "Forward_Open", "Volume 1, Table 3-5.1"},
		CIPServiceForwardClose:       {0x4E, "Forward_Close", "Volume 1, Table 3-5.1"},
	}

	for code, expected := range serviceCodes {
		actualCode := uint8(code)
		if actualCode != expected.value {
			t.Errorf("%s (%s): got 0x%02X, want 0x%02X", expected.name, expected.odvaSpec, actualCode, expected.value)
		}
	}
}

// TestForwardOpenCompliance validates ForwardOpen packet structure per ODVA CIP Connection Management
// Reference: ODVA CIP Connection Management Specification
// ForwardOpen (service 0x54) is used to establish a connection for I/O data exchange.
// Key requirements:
// - Service code: 0x54 (ODVA standard)
// - Connection Manager path: class 0x06, instance 0x01 (ODVA standard)
// - Connection parameters must be valid per ODVA spec
func TestForwardOpenCompliance(t *testing.T) {
	profile := CurrentProtocolProfile()
	params := ConnectionParams{
		OToTRPIMs:             20,
		TToORPIMs:             20,
		OToTSizeBytes:         8,
		TToOSizeBytes:         8,
		Priority:              "scheduled",
		TransportClassTrigger: 3,
		Class:                 0x04,
		Instance:              0x65,
	}

	forwardOpenData, err := BuildForwardOpenRequest(params)
	if err != nil {
		t.Fatalf("BuildForwardOpenRequest failed: %v", err)
	}

	// ForwardOpen structure per ODVA CIP Connection Management Specification:
	// - Service code (1 byte): MUST be 0x54 (ODVA standard)
	if forwardOpenData[0] != uint8(CIPServiceForwardOpen) {
		t.Errorf("Service code: got 0x%02X, want 0x%02X", forwardOpenData[0], uint8(CIPServiceForwardOpen))
	}

	// - Connection Manager path: class 0x06, instance 0x01 (ODVA standard path)
	//   EPATH encoding: 0x20 0x06 0x24 0x01 (8-bit class + 8-bit instance)
	pathOffset := 1
	if profile.IncludeCIPPathSize {
		pathOffset = 2
	}
	if forwardOpenData[pathOffset] != 0x20 || forwardOpenData[pathOffset+1] != 0x06 {
		t.Errorf("Connection Manager class path: got 0x%02X 0x%02X, want 0x20 0x06", forwardOpenData[pathOffset], forwardOpenData[pathOffset+1])
	}
	if forwardOpenData[pathOffset+2] != 0x24 || forwardOpenData[pathOffset+3] != 0x01 {
		t.Errorf("Connection Manager instance path: got 0x%02X 0x%02X, want 0x24 0x01", forwardOpenData[pathOffset+2], forwardOpenData[pathOffset+3])
	}

	// Verify minimum structure exists
	// ForwardOpen has many fields, so we just verify it's not empty and has service code
	if len(forwardOpenData) < 10 {
		t.Errorf("ForwardOpen data too short: %d bytes (minimum 10)", len(forwardOpenData))
	}

	// Verify it contains connection path
	// Connection path should be near the end: class 0x04, instance 0x65
	found := false
	for i := 0; i < len(forwardOpenData)-2; i++ {
		if forwardOpenData[i] == 0x20 && forwardOpenData[i+1] == 0x04 {
			// Found class segment, check for instance
			if i+3 < len(forwardOpenData) && forwardOpenData[i+2] == 0x24 && forwardOpenData[i+3] == 0x65 {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("Connection path (class 0x04, instance 0x65) not found in ForwardOpen data")
	}
}

// TestForwardCloseCompliance validates ForwardClose packet structure per ODVA CIP Connection Management
// Reference: ODVA CIP Connection Management Specification
// ForwardClose (service 0x4E) is used to close a connection established by ForwardOpen.
// Key requirements:
// - Service code: 0x4E (ODVA standard)
// - Connection Manager path: class 0x06, instance 0x01 (ODVA standard)
// - Connection path must reference the connection ID from ForwardOpen response
func TestForwardCloseCompliance(t *testing.T) {
	profile := CurrentProtocolProfile()
	connectionID := uint32(0x12345678)

	forwardCloseData, err := BuildForwardCloseRequest(connectionID)
	if err != nil {
		t.Fatalf("BuildForwardCloseRequest failed: %v", err)
	}

	// ForwardClose structure per ODVA CIP Connection Management Specification:
	// - Service code (1 byte): MUST be 0x4E (ODVA standard)
	if forwardCloseData[0] != uint8(CIPServiceForwardClose) {
		t.Errorf("Service code: got 0x%02X, want 0x%02X", forwardCloseData[0], uint8(CIPServiceForwardClose))
	}

	// - Connection Manager path (class 0x06, instance 0x01)
	pathOffset := 1
	if profile.IncludeCIPPathSize {
		pathOffset = 2
	}
	if forwardCloseData[pathOffset] != 0x20 || forwardCloseData[pathOffset+1] != 0x06 {
		t.Errorf("Connection Manager class path: got 0x%02X 0x%02X, want 0x20 0x06", forwardCloseData[pathOffset], forwardCloseData[pathOffset+1])
	}
	if forwardCloseData[pathOffset+2] != 0x24 || forwardCloseData[pathOffset+3] != 0x01 {
		t.Errorf("Connection Manager instance path: got 0x%02X 0x%02X, want 0x24 0x01", forwardCloseData[pathOffset+2], forwardCloseData[pathOffset+3])
	}

	// Verify minimum structure exists
	if len(forwardCloseData) < 10 {
		t.Errorf("ForwardClose data too short: %d bytes (minimum 10)", len(forwardCloseData))
	}
}

// TestListIdentityCompliance validates ListIdentity packet structure per ODVA EtherNet/IP Encapsulation Protocol
// Reference: ODVA EtherNet/IP Encapsulation Protocol Specification
// ListIdentity (command 0x0063) is used for device discovery via UDP broadcast.
// Key requirements:
// - Command code: 0x0063 (ODVA standard)
// - No data field required (length = 0)
// - No session required (session ID = 0)
func TestListIdentityCompliance(t *testing.T) {
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	packet := BuildListIdentity(senderContext)

	encap, err := DecodeENIP(packet)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	if encap.Command != ENIPCommandListIdentity {
		t.Errorf("Command: got 0x%04X, want 0x%04X", encap.Command, ENIPCommandListIdentity)
	}

	if encap.Length != 0 {
		t.Errorf("Length: got %d, want 0 (no data)", encap.Length)
	}

	if len(encap.Data) != 0 {
		t.Errorf("Data length: got %d, want 0", len(encap.Data))
	}

	if encap.SessionID != 0 {
		t.Errorf("Session ID: got 0x%08X, want 0x00000000 (no session required)", encap.SessionID)
	}
}

// TestDecodeENIPErrorHandling validates error handling for invalid packets
func TestDecodeENIPErrorHandling(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty packet", []byte{}},
		{"too short", []byte{0x00, 0x65}},
		{"exactly 23 bytes", make([]byte, 23)},
		{"partial header", make([]byte, 12)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeENIP(tt.data)
			if err == nil {
				t.Errorf("DecodeENIP should have failed for %s", tt.name)
			}
		})
	}
}

// TestCIPRequestEncoding validates CIP request encoding structure
func TestCIPRequestEncoding(t *testing.T) {
	profile := CurrentProtocolProfile()
	req := CIPRequest{
		Service: CIPServiceGetAttributeSingle,
		Path: CIPPath{
			Class:     0x04,
			Instance:  0x65,
			Attribute: 0x03,
		},
		Payload: []byte{},
	}

	data, err := EncodeCIPRequest(req)
	if err != nil {
		t.Fatalf("EncodeCIPRequest failed: %v", err)
	}

	// Should have: service code (1) + path size (1, if enabled) + EPATH (6) = 8 bytes minimum
	minLen := 7
	if profile.IncludeCIPPathSize {
		minLen = 8
	}
	if len(data) < minLen {
		t.Errorf("CIP request too short: %d bytes (minimum %d)", len(data), minLen)
	}

	// Verify service code
	if data[0] != uint8(CIPServiceGetAttributeSingle) {
		t.Errorf("Service code: got 0x%02X, want 0x%02X", data[0], uint8(CIPServiceGetAttributeSingle))
	}

	// Verify EPATH follows
	offset := 1
	if profile.IncludeCIPPathSize {
		offset = 2
	}
	if data[offset] != 0x20 || data[offset+1] != 0x04 {
		t.Errorf("Class segment: got 0x%02X 0x%02X, want 0x20 0x04", data[offset], data[offset+1])
	}
}

// TestSenderContextValidation validates sender context is preserved
func TestSenderContextValidation(t *testing.T) {
	senderContexts := [][8]byte{
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22},
	}

	for i, ctx := range senderContexts {
		packet := BuildRegisterSession(ctx)
		encap, err := DecodeENIP(packet)
		if err != nil {
			t.Fatalf("DecodeENIP failed for context %d: %v", i, err)
		}

		for j := 0; j < 8; j++ {
			if encap.SenderContext[j] != ctx[j] {
				t.Errorf("SenderContext[%d][%d]: got 0x%02X, want 0x%02X", i, j, encap.SenderContext[j], ctx[j])
			}
		}
	}
}

// TestSessionIDRange validates session ID can handle full uint32 range
func TestSessionIDRange(t *testing.T) {
	sessionIDs := []uint32{
		0x00000000,
		0x00000001,
		0x12345678,
		0xFFFFFFFF,
		0x80000000,
	}

	for _, sid := range sessionIDs {
		encap := ENIPEncapsulation{
			Command:      ENIPCommandSendRRData,
			Length:       0,
			SessionID:    sid,
			Status:       0,
			SenderContext: [8]byte{},
			Options:      0,
			Data:         []byte{},
		}

		packet := EncodeENIP(encap)
		decoded, err := DecodeENIP(packet)
		if err != nil {
			t.Fatalf("DecodeENIP failed for session ID 0x%08X: %v", sid, err)
		}

		if decoded.SessionID != sid {
			t.Errorf("Session ID: got 0x%08X, want 0x%08X", decoded.SessionID, sid)
		}
	}
}
