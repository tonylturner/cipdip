package client

// ODVA Specification Compliance Audit Tests
//
// These tests audit our implementation against actual ODVA specification requirements,
// not just what our code produces. They validate that we're correctly implementing
// the protocol as specified by ODVA.
//
// Key ODVA Specification References:
// - EtherNet/IP Encapsulation Protocol (ENIP)
// - CIP Specification Volume 1
// - CIP Connection Management Specification
//
// Test methodology:
// 1. Define expected structure based on ODVA spec requirements
// 2. Generate packet using our implementation
// 3. Validate byte-by-byte against spec requirements
// 4. Test edge cases and constraints from spec

import (
	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
	"github.com/tonylturner/cipdip/internal/enip"
	"testing"
)

var enipOrder = currentENIPByteOrder()
var cipOrder = currentCIPByteOrder()

// TestENIPHeaderStructureODVA validates ENIP header matches ODVA spec exactly
// ODVA Spec: EtherNet/IP Encapsulation Protocol
// Header MUST be exactly 24 bytes with specific field layout:
// - Bytes 0-1: Command (2 bytes, big-endian)
// - Bytes 2-3: Length (2 bytes, big-endian) - length of data field only
// - Bytes 4-7: Session Handle (4 bytes, big-endian)
// - Bytes 8-11: Status (4 bytes, big-endian)
// - Bytes 12-19: Sender Context (8 bytes, opaque)
// - Bytes 20-23: Options (4 bytes, big-endian, typically 0)
func TestENIPHeaderStructureODVA(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	encap := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandRegisterSession,
		Length:        4,
		SessionID:     0x12345678,
		Status:        0,
		SenderContext: [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Options:       0,
		Data:          []byte{0x01, 0x00, 0x00, 0x00},
	}

	packet := enip.EncodeENIP(encap)

	// ODVA requirement: Header MUST be exactly 24 bytes
	if len(packet) < 24 {
		t.Fatalf("ODVA violation: Header must be exactly 24 bytes, got %d", len(packet))
	}

	// ODVA requirement: Length field is data length only (not including header)
	lengthField := enipOrder.Uint16(packet[2:4])
	if lengthField != 4 {
		t.Errorf("ODVA violation: Length field must be data length (4), got %d", lengthField)
	}

	// ODVA requirement: Total packet = 24 (header) + length (data)
	if len(packet) != 24+int(lengthField) {
		t.Errorf("ODVA violation: Total packet length must be 24 + data length, got %d, want %d",
			len(packet), 24+int(lengthField))
	}

	// ODVA requirement: Command must be correctly encoded
	if enipOrder.Uint16(packet[0:2]) != 0x0065 {
		t.Errorf("ODVA violation: Command must be 0x0065, got 0x%04X", enipOrder.Uint16(packet[0:2]))
	}

	// ODVA requirement: Session Handle in bytes 4-7
	sessionID := enipOrder.Uint32(packet[4:8])
	if sessionID != 0x12345678 {
		t.Errorf("ODVA violation: Session Handle must be in bytes 4-7, got 0x%08X, want 0x12345678", sessionID)
	}

	// ODVA requirement: Status in bytes 8-11 (must be 0 in request)
	status := enipOrder.Uint32(packet[8:12])
	if status != 0 {
		t.Errorf("ODVA violation: Status must be 0 in request, got 0x%08X", status)
	}

	// ODVA requirement: Sender Context in bytes 12-19 (8 bytes)
	for i := 0; i < 8; i++ {
		if packet[12+i] != encap.SenderContext[i] {
			t.Errorf("ODVA violation: Sender Context byte %d: got 0x%02X, want 0x%02X", i, packet[12+i], encap.SenderContext[i])
		}
	}

	// ODVA requirement: Options in bytes 20-23 (typically 0)
	options := enipOrder.Uint32(packet[20:24])
	if options != 0 {
		t.Errorf("ODVA violation: Options should be 0, got 0x%08X", options)
	}
}

// TestRegisterSessionODVA validates RegisterSession matches ODVA spec exactly
// ODVA Spec: EtherNet/IP Encapsulation Protocol
// RegisterSession data structure:
// - Bytes 0-1: Protocol Version (2 bytes, big-endian, MUST be 1)
// - Bytes 2-3: Option Flags (2 bytes, big-endian, MUST be 0)
// Total: Exactly 4 bytes
func TestRegisterSessionODVA(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	packet := enip.BuildRegisterSession(senderContext)

	encap, err := enip.DecodeENIP(packet)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	// ODVA requirement: Command MUST be 0x0065
	if encap.Command != 0x0065 {
		t.Errorf("ODVA violation: RegisterSession command must be 0x0065, got 0x%04X", encap.Command)
	}

	// ODVA requirement: Length MUST be 4 (protocol version + option flags)
	if encap.Length != 4 {
		t.Errorf("ODVA violation: RegisterSession length must be 4, got %d", encap.Length)
	}

	// ODVA requirement: Data MUST be exactly 4 bytes
	if len(encap.Data) != 4 {
		t.Errorf("ODVA violation: RegisterSession data must be 4 bytes, got %d", len(encap.Data))
	}

	// ODVA requirement: Protocol Version MUST be 1
	protocolVersion := enipOrder.Uint16(encap.Data[0:2])
	if protocolVersion != 1 {
		t.Errorf("ODVA violation: Protocol version must be 1, got %d", protocolVersion)
	}

	// ODVA requirement: Option Flags MUST be 0
	optionFlags := enipOrder.Uint16(encap.Data[2:4])
	if optionFlags != 0 {
		t.Errorf("ODVA violation: Option flags must be 0, got %d", optionFlags)
	}

	// ODVA requirement: Session ID MUST be 0 in request
	if encap.SessionID != 0 {
		t.Errorf("ODVA violation: Session ID must be 0 in RegisterSession request, got 0x%08X", encap.SessionID)
	}
}

// TestSendRRDataStructureODVA validates SendRRData structure per ODVA spec
// ODVA Spec: EtherNet/IP Encapsulation Protocol
// SendRRData data structure (for UCMM):
// - Bytes 0-3: Interface Handle (4 bytes, big-endian, MUST be 0 for UCMM)
// - Bytes 4-5: Timeout (2 bytes, big-endian, in seconds, 0 = no timeout)
// - Bytes 6+: CIP data (variable length)
func TestSendRRDataStructureODVA(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	sessionID := uint32(0x12345678)
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	cipData := []byte{0x0E, 0x20, 0x04, 0x24, 0x65, 0x30, 0x03}

	packet := enip.BuildSendRRData(sessionID, senderContext, cipData)
	encap, err := enip.DecodeENIP(packet)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	// ODVA requirement: Command MUST be 0x006F
	if encap.Command != 0x006F {
		t.Errorf("ODVA violation: SendRRData command must be 0x006F, got 0x%04X", encap.Command)
	}

	// ODVA requirement: Minimum data length is 6 bytes (Interface Handle + Timeout)
	if len(encap.Data) < 6 {
		t.Fatalf("ODVA violation: SendRRData data must be at least 6 bytes, got %d", len(encap.Data))
	}

	// ODVA requirement: Interface Handle MUST be 0 for UCMM
	interfaceHandle := enipOrder.Uint32(encap.Data[0:4])
	if interfaceHandle != 0 {
		t.Errorf("ODVA violation: Interface Handle must be 0 for UCMM, got 0x%08X", interfaceHandle)
	}

	// ODVA requirement: Timeout field present (2 bytes)
	timeout := enipOrder.Uint16(encap.Data[4:6])
	_ = timeout // Can be any value, but must be present

	// ODVA requirement: Length field matches data length
	if encap.Length != uint16(len(encap.Data)) {
		t.Errorf("ODVA violation: Length must match data length, got %d, want %d", encap.Length, len(encap.Data))
	}

	// ODVA requirement: CIP data present
	cipDataFromPacket, err := enip.ParseSendRRDataRequest(encap.Data)
	if err != nil {
		t.Fatalf("ParseSendRRDataRequest failed: %v", err)
	}
	if len(cipDataFromPacket) != len(cipData) {
		t.Errorf("ODVA violation: CIP data length mismatch, got %d, want %d", len(cipDataFromPacket), len(cipData))
	}
}

// TestSendUnitDataStructureODVA validates SendUnitData structure per ODVA spec
// ODVA Spec: EtherNet/IP Encapsulation Protocol
// SendUnitData data structure (for connected messaging):
// - Bytes 0-3: Connection ID (4 bytes, big-endian)
// - Bytes 4+: CIP data (variable length)
func TestSendUnitDataStructureODVA(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	sessionID := uint32(0x12345678)
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	connectionID := uint32(0xABCDEF00)
	cipData := []byte{0x01, 0x02, 0x03, 0x04}

	packet := enip.BuildSendUnitData(sessionID, senderContext, connectionID, cipData)
	encap, err := enip.DecodeENIP(packet)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	// ODVA requirement: Command MUST be 0x0070
	if encap.Command != 0x0070 {
		t.Errorf("ODVA violation: SendUnitData command must be 0x0070, got 0x%04X", encap.Command)
	}

	// ODVA requirement: Minimum data length is 4 bytes (Connection ID)
	if len(encap.Data) < 4 {
		t.Fatalf("ODVA violation: SendUnitData data must be at least 4 bytes, got %d", len(encap.Data))
	}

	// ODVA requirement: Connection ID present
	recvConnectionID, _, err := enip.ParseSendUnitDataRequest(encap.Data)
	if err != nil {
		t.Fatalf("ParseSendUnitDataRequest failed: %v", err)
	}
	if recvConnectionID != connectionID {
		t.Errorf("ODVA violation: Connection ID must be in bytes 0-3, got 0x%08X, want 0x%08X", recvConnectionID, connectionID)
	}

	// ODVA requirement: Length field matches data length
	if encap.Length != uint16(len(encap.Data)) {
		t.Errorf("ODVA violation: Length must match data length, got %d, want %d", encap.Length, len(encap.Data))
	}
}

// TestEPATHEncodingODVA validates EPATH encoding per ODVA CIP spec
// ODVA Spec: CIP Specification Volume 1, Section 3-5.2
// EPATH segment format:
// - Segment type byte: bits 0-3 = format (0=8-bit, 1=16-bit), bits 4-7 = segment type
// - Segment data: 1 byte (8-bit) or 2 bytes (16-bit, big-endian)
//
// Segment type codes:
// - 0x20 = Class ID (8-bit)
// - 0x21 = Class ID (16-bit)
// - 0x24 = Instance ID (8-bit)
// - 0x25 = Instance ID (16-bit)
// - 0x30 = Attribute ID (8-bit)
// - 0x31 = Attribute ID (16-bit)
func TestEPATHEncodingODVA(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	tests := []struct {
		name          string
		path          protocol.CIPPath
		expectedEPATH []byte
		description   string
	}{
		{
			name: "8-bit class and instance (ODVA standard)",
			path: protocol.CIPPath{
				Class:     0x04,
				Instance:  0x65,
				Attribute: 0x03,
			},
			expectedEPATH: []byte{
				0x20, 0x04, // Class ID (8-bit): type 0x20, value 0x04
				0x24, 0x65, // Instance ID (8-bit): type 0x24, value 0x65
				0x30, 0x03, // Attribute ID (8-bit): type 0x30, value 0x03
			},
			description: "ODVA spec: 8-bit segments use type 0x20/0x24/0x30",
		},
		{
			name: "16-bit class (ODVA requirement for class > 0xFF)",
			path: protocol.CIPPath{
				Class:     0x0100,
				Instance:  0x65,
				Attribute: 0x03,
			},
			expectedEPATH: []byte{
				0x21, 0x00, 0x01, // Class ID (16-bit): type 0x21, value 0x0100 (little-endian)
				0x24, 0x65, // Instance ID (8-bit)
				0x30, 0x03, // Attribute ID (8-bit)
			},
			description: "ODVA spec: 16-bit segments use type 0x21/0x25/0x31, little-endian",
		},
		{
			name: "16-bit instance (ODVA requirement for instance > 0xFF)",
			path: protocol.CIPPath{
				Class:     0x04,
				Instance:  0x0100,
				Attribute: 0x03,
			},
			expectedEPATH: []byte{
				0x20, 0x04, // Class ID (8-bit)
				0x25, 0x00, 0x01, // Instance ID (16-bit): type 0x25, value 0x0100 (little-endian)
				0x30, 0x03, // Attribute ID (8-bit)
			},
			description: "ODVA spec: Instance > 0xFF must use 16-bit encoding (little-endian)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			epath := protocol.EncodeEPATH(tt.path)

			// ODVA requirement: EPATH must match expected structure
			if len(epath) != len(tt.expectedEPATH) {
				t.Errorf("ODVA violation: EPATH length mismatch, got %d, want %d", len(epath), len(tt.expectedEPATH))
				t.Errorf("  Got:      %v", epath)
				t.Errorf("  Expected: %v", tt.expectedEPATH)
				return
			}

			// ODVA requirement: Byte-by-byte match
			for i := 0; i < len(epath); i++ {
				if epath[i] != tt.expectedEPATH[i] {
					t.Errorf("ODVA violation: EPATH byte %d: got 0x%02X, want 0x%02X", i, epath[i], tt.expectedEPATH[i])
					t.Errorf("  %s", tt.description)
				}
			}

			// ODVA requirement: 16-bit values must follow CIP byte order
			if tt.path.Class > 0xFF {
				// Check 16-bit class encoding
				classValue := cipOrder.Uint16(epath[1:3])
				if classValue != tt.path.Class {
					t.Errorf("ODVA violation: 16-bit class must use CIP byte order, got 0x%04X, want 0x%04X", classValue, tt.path.Class)
				}
			}
			if tt.path.Instance > 0xFF {
				// Find instance segment (after class segment)
				instanceOffset := 2
				if tt.path.Class > 0xFF {
					instanceOffset = 3
				}
				instanceValue := cipOrder.Uint16(epath[instanceOffset+1 : instanceOffset+3])
				if instanceValue != tt.path.Instance {
					t.Errorf("ODVA violation: 16-bit instance must be big-endian, got 0x%04X, want 0x%04X", instanceValue, tt.path.Instance)
				}
			}
		})
	}
}

// TestForwardOpenStructureODVA audits ForwardOpen against ODVA CIP Connection Management spec
// ODVA Spec: CIP Connection Management Specification
// ForwardOpen structure (service 0x54):
//   - Byte 0: Service code (MUST be 0x54)
//   - Bytes 1-4: Connection Manager path (class 0x06, instance 0x01)
//     EPATH: 0x20 0x06 0x24 0x01 (ODVA standard path)
//   - Payload structure (after Connection Manager path):
//     - Byte 0: Priority/Time_Tick (bits 0-3=priority, bits 4-7=time tick)
//     - Byte 1: Timeout_Ticks
//     - Bytes 2-5: O->T Network Connection ID (4 bytes)
//     - Bytes 6-9: T->O Network Connection ID (4 bytes)
//     - Bytes 10-11: Connection Serial Number (2 bytes)
//     - Bytes 12-13: Originator Vendor ID (2 bytes)
//     - Bytes 14-17: Originator Serial Number (4 bytes)
//     - Byte 18: Connection Timeout Multiplier
//     - Bytes 19-21: Reserved (3 bytes)
//     - Bytes 22-25: O->T RPI (4 bytes, microseconds)
//     - Bytes 26-29: O->T Network Connection Parameters (4 bytes)
//     - Bytes 30-33: T->O RPI (4 bytes, microseconds)
//     - Bytes 34-37: T->O Network Connection Parameters (4 bytes)
//     - Byte 38: Transport Type/Trigger
//     - Byte 39: Connection Path Size (in 16-bit words)
//     - Bytes 40+: Connection Path (padded to 16-bit boundary)
func TestForwardOpenStructureODVA(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
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

	// ODVA requirement: Service code MUST be 0x54
	if forwardOpenData[0] != 0x54 {
		t.Errorf("ODVA violation: ForwardOpen service code must be 0x54, got 0x%02X", forwardOpenData[0])
	}

	// ODVA requirement: Connection Manager path MUST be class 0x06, instance 0x01
	// EPATH encoding: 0x20 0x06 0x24 0x01
	if len(forwardOpenData) < 5 {
		t.Fatalf("ODVA violation: ForwardOpen too short for Connection Manager path")
	}
	pathOffset := 1
	if profile.IncludeCIPPathSize {
		pathOffset = 2
	}
	if forwardOpenData[pathOffset] != 0x20 || forwardOpenData[pathOffset+1] != 0x06 {
		t.Errorf("ODVA violation: Connection Manager class path must be 0x20 0x06, got 0x%02X 0x%02X",
			forwardOpenData[pathOffset], forwardOpenData[pathOffset+1])
	}
	if forwardOpenData[pathOffset+2] != 0x24 || forwardOpenData[pathOffset+3] != 0x01 {
		t.Errorf("ODVA violation: Connection Manager instance path must be 0x24 0x01, got 0x%02X 0x%02X",
			forwardOpenData[pathOffset+2], forwardOpenData[pathOffset+3])
	}

	// Payload starts after Connection Manager path
	payloadStart := pathOffset + 4

	// ODVA requirement: Priority and tick time at payload byte 0
	// Bits 0-3: Priority (0=low, 1=scheduled, 2=high, 3=urgent)
	// Bits 4-7: Time tick (2^n ms base)
	priorityByte := forwardOpenData[payloadStart]
	priority := priorityByte & 0x0F
	if priority != 0x01 { // scheduled
		t.Errorf("ODVA violation: Priority for 'scheduled' must be 0x01, got 0x%02X", priority)
	}
	// Time tick of 0x0A (10) means 2^10 = 1024ms base - this is valid per ODVA
	// The actual timeout = timeout_ticks * 2^time_tick

	// ODVA requirement: Timeout ticks at payload byte 1
	if len(forwardOpenData) < payloadStart+2 {
		t.Fatalf("ODVA violation: ForwardOpen too short for timeout ticks")
	}
	timeoutTicks := forwardOpenData[payloadStart+1]
	if timeoutTicks == 0 {
		t.Errorf("ODVA violation: Timeout ticks should be non-zero")
	}

	// ODVA requirement: O->T Connection ID at payload bytes 2-5
	if len(forwardOpenData) < payloadStart+6 {
		t.Fatalf("ODVA violation: ForwardOpen too short for O->T connection ID")
	}
	oToTConnID := cipOrder.Uint32(forwardOpenData[payloadStart+2 : payloadStart+6])
	if oToTConnID == 0 {
		t.Errorf("ODVA violation: O->T connection ID should be non-zero")
	}

	// ODVA requirement: T->O Connection ID at payload bytes 6-9
	if len(forwardOpenData) < payloadStart+10 {
		t.Fatalf("ODVA violation: ForwardOpen too short for T->O connection ID")
	}
	tToOConnID := cipOrder.Uint32(forwardOpenData[payloadStart+6 : payloadStart+10])
	if tToOConnID == 0 {
		t.Errorf("ODVA violation: T->O connection ID should be non-zero")
	}

	// ODVA requirement: O->T RPI at payload bytes 22-25 (microseconds)
	if len(forwardOpenData) < payloadStart+26 {
		t.Fatalf("ODVA violation: ForwardOpen too short for O->T RPI")
	}
	rpiOToT := cipOrder.Uint32(forwardOpenData[payloadStart+22 : payloadStart+26])
	expectedRPI := uint32(20 * 1000) // 20ms = 20000 microseconds
	if rpiOToT != expectedRPI {
		t.Errorf("ODVA violation: O->T RPI must be in microseconds, got %d, want %d", rpiOToT, expectedRPI)
	}

	// ODVA requirement: O->T Connection Parameters at payload bytes 26-29
	if len(forwardOpenData) < payloadStart+30 {
		t.Fatalf("ODVA violation: ForwardOpen too short for O->T connection parameters")
	}
	oToTParams := cipOrder.Uint32(forwardOpenData[payloadStart+26 : payloadStart+30])
	// Bit 0 must be 1 for IO connection
	if oToTParams&0x01 != 0x01 {
		t.Errorf("ODVA violation: O->T connection parameters bit 0 must be 1 for IO connection, got 0x%08X", oToTParams)
	}

	// ODVA requirement: T->O RPI at payload bytes 30-33 (microseconds)
	if len(forwardOpenData) < payloadStart+34 {
		t.Fatalf("ODVA violation: ForwardOpen too short for T->O RPI")
	}
	rpiTToO := cipOrder.Uint32(forwardOpenData[payloadStart+30 : payloadStart+34])
	if rpiTToO != expectedRPI {
		t.Errorf("ODVA violation: T->O RPI must be in microseconds, got %d, want %d", rpiTToO, expectedRPI)
	}

	// ODVA requirement: Transport Type/Trigger at payload byte 38
	if len(forwardOpenData) < payloadStart+39 {
		t.Fatalf("ODVA violation: ForwardOpen too short for transport type/trigger")
	}
	transportTrigger := forwardOpenData[payloadStart+38]
	if transportTrigger != 0x03 { // Cyclic
		t.Errorf("ODVA violation: Transport class/trigger should be 0x03 (cyclic), got 0x%02X", transportTrigger)
	}

	// ODVA requirement: Connection path size at payload byte 39
	if len(forwardOpenData) < payloadStart+40 {
		t.Fatalf("ODVA violation: ForwardOpen too short for connection path size")
	}
	pathSizeByte := forwardOpenData[payloadStart+39]

	// Connection path for class 0x04, instance 0x65:
	// EncodeEPATH includes attribute segment even when 0:
	// EPATH: 0x20 0x04 0x24 0x65 0x30 0x00 = 6 bytes = 3 words
	expectedPathSize := uint8(3) // 6 bytes = 3 words (includes attribute=0)
	if pathSizeByte != expectedPathSize {
		t.Errorf("ODVA violation: Connection path size should be %d words, got %d", expectedPathSize, pathSizeByte)
	}

	// Verify connection path content at payload bytes 40+
	pathStart := payloadStart + 40
	if len(forwardOpenData) < pathStart+6 {
		t.Fatalf("ODVA violation: ForwardOpen too short for connection path data")
	}
	if forwardOpenData[pathStart] != 0x20 || forwardOpenData[pathStart+1] != 0x04 {
		t.Errorf("ODVA violation: Connection path class must be 0x20 0x04, got 0x%02X 0x%02X",
			forwardOpenData[pathStart], forwardOpenData[pathStart+1])
	}
	if forwardOpenData[pathStart+2] != 0x24 || forwardOpenData[pathStart+3] != 0x65 {
		t.Errorf("ODVA violation: Connection path instance must be 0x24 0x65, got 0x%02X 0x%02X",
			forwardOpenData[pathStart+2], forwardOpenData[pathStart+3])
	}
	// Attribute segment (0x30 0x00) is included by protocol.EncodeEPATH
	if forwardOpenData[pathStart+4] != 0x30 || forwardOpenData[pathStart+5] != 0x00 {
		t.Errorf("ODVA violation: Connection path attribute must be 0x30 0x00, got 0x%02X 0x%02X",
			forwardOpenData[pathStart+4], forwardOpenData[pathStart+5])
	}
}

// TestForwardCloseStructureODVA audits ForwardClose against ODVA CIP Connection Management spec
// ODVA Spec: CIP Connection Management Specification
// ForwardClose structure (service 0x4E):
//   - Byte 0: Service code (MUST be 0x4E)
//   - Bytes 1-4: Connection Manager path (class 0x06, instance 0x01)
//     EPATH: 0x20 0x06 0x24 0x01
//   - Payload structure (after Connection Manager path):
//     - Byte 0: Priority/Time_Tick
//     - Byte 1: Timeout_Ticks
//     - Bytes 2-3: Connection Serial Number (2 bytes)
//     - Bytes 4-5: Originator Vendor ID (2 bytes)
//     - Bytes 6-9: Originator Serial Number (4 bytes)
//     - Byte 10: Connection Path Size (in 16-bit words)
//     - Bytes 11+: Connection Path (class/instance EPATH)
func TestForwardCloseStructureODVA(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	profile := CurrentProtocolProfile()
	connectionID := uint32(0x12345678)

	forwardCloseData, err := BuildForwardCloseRequest(connectionID)
	if err != nil {
		t.Fatalf("BuildForwardCloseRequest failed: %v", err)
	}

	// ODVA requirement: Service code MUST be 0x4E
	if forwardCloseData[0] != 0x4E {
		t.Errorf("ODVA violation: ForwardClose service code must be 0x4E, got 0x%02X", forwardCloseData[0])
	}

	// ODVA requirement: Connection Manager path MUST be class 0x06, instance 0x01
	if len(forwardCloseData) < 5 {
		t.Fatalf("ODVA violation: ForwardClose too short for Connection Manager path")
	}
	pathOffset := 1
	if profile.IncludeCIPPathSize {
		pathOffset = 2
	}
	if forwardCloseData[pathOffset] != 0x20 || forwardCloseData[pathOffset+1] != 0x06 {
		t.Errorf("ODVA violation: Connection Manager class path must be 0x20 0x06, got 0x%02X 0x%02X",
			forwardCloseData[pathOffset], forwardCloseData[pathOffset+1])
	}
	if forwardCloseData[pathOffset+2] != 0x24 || forwardCloseData[pathOffset+3] != 0x01 {
		t.Errorf("ODVA violation: Connection Manager instance path must be 0x24 0x01, got 0x%02X 0x%02X",
			forwardCloseData[pathOffset+2], forwardCloseData[pathOffset+3])
	}

	// Payload starts after Connection Manager path
	payloadStart := pathOffset + 4

	// ODVA requirement: Priority/Time_Tick at payload byte 0
	if len(forwardCloseData) < payloadStart+1 {
		t.Fatalf("ODVA violation: ForwardClose too short for priority/tick byte")
	}
	priorityByte := forwardCloseData[payloadStart]
	priority := priorityByte & 0x0F
	if priority != 0x01 { // scheduled
		t.Errorf("ODVA violation: Priority should be 0x01 (scheduled), got 0x%02X", priority)
	}

	// ODVA requirement: Timeout ticks at payload byte 1
	if len(forwardCloseData) < payloadStart+2 {
		t.Fatalf("ODVA violation: ForwardClose too short for timeout ticks")
	}

	// ODVA requirement: Connection Serial at payload bytes 2-3
	if len(forwardCloseData) < payloadStart+4 {
		t.Fatalf("ODVA violation: ForwardClose too short for connection serial")
	}
	connectionSerial := cipOrder.Uint16(forwardCloseData[payloadStart+2 : payloadStart+4])
	expectedSerial := uint16(connectionID & 0xFFFF)
	if connectionSerial != expectedSerial {
		t.Errorf("ODVA violation: Connection serial should be 0x%04X, got 0x%04X", expectedSerial, connectionSerial)
	}

	// ODVA requirement: Originator Vendor ID at payload bytes 4-5
	if len(forwardCloseData) < payloadStart+6 {
		t.Fatalf("ODVA violation: ForwardClose too short for originator vendor ID")
	}
	originatorVendor := cipOrder.Uint16(forwardCloseData[payloadStart+4 : payloadStart+6])
	if originatorVendor != 0x0001 {
		t.Errorf("ODVA violation: Originator vendor ID should be 0x0001, got 0x%04X", originatorVendor)
	}

	// ODVA requirement: Originator Serial at payload bytes 6-9
	if len(forwardCloseData) < payloadStart+10 {
		t.Fatalf("ODVA violation: ForwardClose too short for originator serial")
	}
	originatorSerial := cipOrder.Uint32(forwardCloseData[payloadStart+6 : payloadStart+10])
	if originatorSerial != connectionID {
		t.Errorf("ODVA violation: Originator serial should be 0x%08X, got 0x%08X", connectionID, originatorSerial)
	}

	// ODVA requirement: Connection path size at payload byte 10
	if len(forwardCloseData) < payloadStart+11 {
		t.Fatalf("ODVA violation: ForwardClose too short for connection path size")
	}
	pathSizeByte := forwardCloseData[payloadStart+10]

	// Connection path includes attribute segment even when 0:
	// EPATH: 0x20 0x04 0x24 0x65 0x30 0x00 = 6 bytes = 3 words
	expectedPathSize := uint8(3) // 6 bytes = 3 words (includes attribute=0)
	if pathSizeByte != expectedPathSize {
		t.Errorf("ODVA violation: Connection path size should be %d words, got %d", expectedPathSize, pathSizeByte)
	}

	// ODVA requirement: Connection path at payload bytes 11+
	connPathStart := payloadStart + 11
	if len(forwardCloseData) < connPathStart+6 {
		t.Fatalf("ODVA violation: ForwardClose too short for connection path")
	}
	// Verify EPATH encoding
	if forwardCloseData[connPathStart] != 0x20 || forwardCloseData[connPathStart+1] != 0x04 {
		t.Errorf("ODVA violation: Connection path class must be 0x20 0x04, got 0x%02X 0x%02X",
			forwardCloseData[connPathStart], forwardCloseData[connPathStart+1])
	}
	if forwardCloseData[connPathStart+2] != 0x24 || forwardCloseData[connPathStart+3] != 0x65 {
		t.Errorf("ODVA violation: Connection path instance must be 0x24 0x65, got 0x%02X 0x%02X",
			forwardCloseData[connPathStart+2], forwardCloseData[connPathStart+3])
	}
	// Attribute segment (0x30 0x00) is included by protocol.EncodeEPATH
	if forwardCloseData[connPathStart+4] != 0x30 || forwardCloseData[connPathStart+5] != 0x00 {
		t.Errorf("ODVA violation: Connection path attribute must be 0x30 0x00, got 0x%02X 0x%02X",
			forwardCloseData[connPathStart+4], forwardCloseData[connPathStart+5])
	}
}

// TestCIPResponseStructureODVA audits CIP response structure per ODVA spec
// ODVA Spec: CIP Specification Volume 1
// CIP response structure:
// - Byte 0: Service code (echoed from request)
// - Byte 1: General status (0x00 = success)
// - Bytes 2+: Extended status (if status != 0x00) + Additional status size byte
// - Bytes N+: Response data (if status == 0x00)
func TestCIPResponseStructureODVA(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	profile := CurrentProtocolProfile()
	// Test success response
	successResp := protocol.CIPResponse{
		Service: spec.CIPServiceGetAttributeSingle,
		Status:  0x00, // Success
		Payload: []byte{0x01, 0x02, 0x03, 0x04},
	}

	data, err := protocol.EncodeCIPResponse(successResp)
	if err != nil {
		t.Fatalf("protocol.EncodeCIPResponse failed: %v", err)
	}

	// ODVA requirement: Service code must be first byte
	if data[0] != uint8(spec.CIPServiceGetAttributeSingle) {
		t.Errorf("ODVA violation: Service code must be first byte, got 0x%02X, want 0x%02X",
			data[0], uint8(spec.CIPServiceGetAttributeSingle))
	}

	offset := 1
	if profile.IncludeCIPRespReserved {
		if len(data) < 4 {
			t.Fatalf("ODVA violation: Response too short for reserved fields")
		}
		if data[2] != 0x00 {
			t.Errorf("ODVA violation: Status must be byte 2, got 0x%02X, want 0x00", data[2])
		}
		offset = 4
	} else {
		// ODVA requirement: Status must be second byte
		if data[1] != 0x00 {
			t.Errorf("ODVA violation: Status must be second byte, got 0x%02X, want 0x00", data[1])
		}
		offset = 2
	}

	// ODVA requirement: Payload follows status for success (status = 0x00)
	if len(data) < offset+len(successResp.Payload) {
		t.Errorf("ODVA violation: Response too short for payload")
	}
	payload := data[offset:]
	if len(payload) != len(successResp.Payload) {
		t.Errorf("ODVA violation: Payload length mismatch, got %d, want %d", len(payload), len(successResp.Payload))
	}
}

// TestListIdentityODVA validates ListIdentity per ODVA spec
// ODVA Spec: EtherNet/IP Encapsulation Protocol
// ListIdentity (command 0x0063):
// - Command: 0x0063
// - Length: 0 (no data field)
// - Session ID: 0 (no session required for discovery)
func TestListIdentityODVA(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	packet := enip.BuildListIdentity(senderContext)

	encap, err := enip.DecodeENIP(packet)
	if err != nil {
		t.Fatalf("DecodeENIP failed: %v", err)
	}

	// ODVA requirement: Command MUST be 0x0063
	if encap.Command != 0x0063 {
		t.Errorf("ODVA violation: ListIdentity command must be 0x0063, got 0x%04X", encap.Command)
	}

	// ODVA requirement: Length MUST be 0 (no data)
	if encap.Length != 0 {
		t.Errorf("ODVA violation: ListIdentity length must be 0, got %d", encap.Length)
	}

	// ODVA requirement: Session ID MUST be 0 (no session required)
	if encap.SessionID != 0 {
		t.Errorf("ODVA violation: ListIdentity session ID must be 0, got 0x%08X", encap.SessionID)
	}

	// ODVA requirement: No data field
	if len(encap.Data) != 0 {
		t.Errorf("ODVA violation: ListIdentity must have no data, got %d bytes", len(encap.Data))
	}
}

// TestForwardOpenConnectionParametersODVA audits connection parameter encoding
// ODVA Spec: CIP Connection Management Specification
// Connection parameters encode:
// - Bit 0: Connection type (0=explicit, 1=IO)
// - Bit 1: Priority (from priority byte)
// - Bits 2-3: Connection size encoding (0=8 bytes, 1=16 bytes, 2=32 bytes, 3=variable)
func TestForwardOpenConnectionParametersODVA(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	profile := CurrentProtocolProfile()
	tests := []struct {
		name         string
		sizeBytes    int
		expectedBits uint32
	}{
		{"8 bytes", 8, 0x00},        // Bits 2-3 = 00
		{"16 bytes", 16, 0x04},      // Bits 2-3 = 01 (shifted left 2)
		{"32 bytes", 32, 0x08},      // Bits 2-3 = 10 (shifted left 2)
		{"variable size", 64, 0x0C}, // Bits 2-3 = 11 (shifted left 2)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := ConnectionParams{
				OToTRPIMs:             20,
				TToORPIMs:             20,
				OToTSizeBytes:         tt.sizeBytes,
				TToOSizeBytes:         tt.sizeBytes,
				Priority:              "scheduled",
				TransportClassTrigger: 3,
				Class:                 0x04,
				Instance:              0x65,
			}

			forwardOpenData, err := BuildForwardOpenRequest(params)
			if err != nil {
				t.Fatalf("BuildForwardOpenRequest failed: %v", err)
			}

			// Calculate payload start after Connection Manager path
			pathOffset := 1
			if profile.IncludeCIPPathSize {
				pathOffset = 2
			}
			payloadStart := pathOffset + 4

			// O->T connection parameters at payload bytes 26-29
			paramOffset := payloadStart + 26
			if len(forwardOpenData) < paramOffset+4 {
				t.Fatalf("ODVA violation: ForwardOpen too short for O->T connection parameters")
			}
			oToTParams := cipOrder.Uint32(forwardOpenData[paramOffset : paramOffset+4])

			// ODVA requirement: Bit 0 must be 1 for IO connection
			if oToTParams&0x01 != 0x01 {
				t.Errorf("ODVA violation: Bit 0 must be 1 for IO connection, got 0x%08X", oToTParams)
			}

			// ODVA requirement: Bits 2-3 encode connection size
			sizeBits := (oToTParams >> 2) & 0x03
			expectedSizeBits := tt.expectedBits >> 2
			if sizeBits != expectedSizeBits {
				t.Errorf("ODVA violation: Connection size encoding for %d bytes: got bits 0x%02X, want 0x%02X",
					tt.sizeBytes, sizeBits, expectedSizeBits)
			}
		})
	}
}

// TestForwardOpenRPIMicrosecondsODVA validates RPI encoding in microseconds
// ODVA Spec: CIP Connection Management Specification
// RPI (Requested Packet Interval) MUST be encoded in microseconds (not milliseconds)
func TestForwardOpenRPIMicrosecondsODVA(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	profile := CurrentProtocolProfile()
	params := ConnectionParams{
		OToTRPIMs:             20, // 20 milliseconds
		TToORPIMs:             20, // 20 milliseconds
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

	// Calculate payload start after Connection Manager path
	pathOffset := 1
	if profile.IncludeCIPPathSize {
		pathOffset = 2
	}
	payloadStart := pathOffset + 4

	// ODVA requirement: O->T RPI at payload bytes 22-25 (microseconds)
	oToTRPIOffset := payloadStart + 22
	if len(forwardOpenData) < oToTRPIOffset+4 {
		t.Fatalf("ODVA violation: ForwardOpen too short for O->T RPI")
	}
	rpiOToT := cipOrder.Uint32(forwardOpenData[oToTRPIOffset : oToTRPIOffset+4])
	expectedMicroseconds := uint32(20 * 1000) // 20ms = 20000 microseconds
	if rpiOToT != expectedMicroseconds {
		t.Errorf("ODVA violation: O->T RPI must be in microseconds, got %d, want %d (20ms = 20000µs)",
			rpiOToT, expectedMicroseconds)
	}

	// ODVA requirement: T->O RPI at payload bytes 30-33 (microseconds)
	tToORPIOffset := payloadStart + 30
	if len(forwardOpenData) < tToORPIOffset+4 {
		t.Fatalf("ODVA violation: ForwardOpen too short for T->O RPI")
	}
	rpiTToO := cipOrder.Uint32(forwardOpenData[tToORPIOffset : tToORPIOffset+4])
	if rpiTToO != expectedMicroseconds {
		t.Errorf("ODVA violation: T->O RPI must be in microseconds, got %d, want %d (20ms = 20000µs)",
			rpiTToO, expectedMicroseconds)
	}
}

// TestForwardOpenResponseStructureODVA audits ForwardOpen response parsing
// ODVA Spec: CIP Connection Management Specification
// ForwardOpen response structure:
// - Byte 0: General status (0x00 = success)
// - Byte 1: Additional status size (if status != 0x00)
// - Bytes 2-N: Additional status (if present)
// - Bytes N+0 to N+3: O->T connection ID (4 bytes, big-endian)
// - Bytes N+4 to N+7: T->O connection ID (4 bytes, big-endian)
// - Bytes N+8 to N+9: Connection serial number (2 bytes, big-endian)
// - Bytes N+10 to N+11: Originator vendor ID (2 bytes, big-endian)
// - Bytes N+12 to N+15: Originator serial number (4 bytes, big-endian)
// - Byte N+16: Connection timeout multiplier (1 byte)
func TestForwardOpenResponseStructureODVA(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	// Build a valid ForwardOpen response (success case)
	responseData := []byte{
		0x00,                   // General status: success
		0x00,                   // Additional status size: 0 (no extended status)
		0x78, 0x56, 0x34, 0x12, // O->T connection ID (little-endian)
		0xF0, 0xDE, 0xBC, 0x9A, // T->O connection ID (little-endian)
		0x00, 0x01, // Connection serial number
		0x00, 0x01, // Originator vendor ID
		0x00, 0x00, 0x00, 0x01, // Originator serial number
		0x01, // Connection timeout multiplier
	}

	connectionID, oToTConnID, tToOConnID, err := ParseForwardOpenResponse(responseData)
	if err != nil {
		t.Fatalf("ParseForwardOpenResponse failed: %v", err)
	}

	// ODVA requirement: O->T connection ID must be extracted correctly
	expectedOToT := uint32(0x12345678)
	if oToTConnID != expectedOToT {
		t.Errorf("ODVA violation: O->T connection ID must be 0x%08X, got 0x%08X", expectedOToT, oToTConnID)
	}

	// ODVA requirement: T->O connection ID must be extracted correctly
	expectedTToO := uint32(0x9ABCDEF0)
	if tToOConnID != expectedTToO {
		t.Errorf("ODVA violation: T->O connection ID must be 0x%08X, got 0x%08X", expectedTToO, tToOConnID)
	}

	// ODVA requirement: Primary connection ID should be O->T connection ID
	if connectionID != oToTConnID {
		t.Errorf("ODVA violation: Primary connection ID should be O->T connection ID, got 0x%08X, want 0x%08X",
			connectionID, oToTConnID)
	}
}

// TestCIPServiceCodeValuesODVA validates all service codes match ODVA spec exactly
// ODVA Spec: CIP Specification Volume 1, Table 3-5.1
// These values are standardized and MUST match exactly
func TestCIPServiceCodeValuesODVA(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	// ODVA standard service codes from CIP Specification Volume 1, Table 3-5.1
	odvaServiceCodes := map[string]uint8{
		"Get_Attribute_All":         0x01,
		"Set_Attribute_All":         0x02,
		"Get_Attribute_List":        0x03,
		"Set_Attribute_List":        0x04,
		"Reset":                     0x05,
		"Start":                     0x06,
		"Stop":                      0x07,
		"Create":                    0x08,
		"Delete":                    0x09,
		"Multiple_Service":          0x0A,
		"Apply_Attributes":          0x0D,
		"Get_Attribute_Single":      0x0E,
		"Set_Attribute_Single":      0x10,
		"Find_Next_Object_Instance": 0x11,
		"Forward_Open":              0x54,
		"Forward_Close":             0x4E,
	}

	ourServiceCodes := map[protocol.CIPServiceCode]string{
		spec.CIPServiceGetAttributeAll:    "Get_Attribute_All",
		spec.CIPServiceSetAttributeAll:    "Set_Attribute_All",
		spec.CIPServiceGetAttributeList:   "Get_Attribute_List",
		spec.CIPServiceSetAttributeList:   "Set_Attribute_List",
		spec.CIPServiceReset:              "Reset",
		spec.CIPServiceStart:              "Start",
		spec.CIPServiceStop:               "Stop",
		spec.CIPServiceCreate:             "Create",
		spec.CIPServiceDelete:             "Delete",
		spec.CIPServiceMultipleService:    "Multiple_Service",
		spec.CIPServiceApplyAttributes:    "Apply_Attributes",
		spec.CIPServiceGetAttributeSingle: "Get_Attribute_Single",
		spec.CIPServiceSetAttributeSingle: "Set_Attribute_Single",
		spec.CIPServiceFindNextObjectInst: "Find_Next_Object_Instance",
		spec.CIPServiceForwardOpen:        "Forward_Open",
		spec.CIPServiceForwardClose:       "Forward_Close",
	}

	for code, name := range ourServiceCodes {
		expectedValue, exists := odvaServiceCodes[name]
		if !exists {
			t.Errorf("ODVA violation: Service '%s' not found in ODVA spec", name)
			continue
		}

		actualValue := uint8(code)
		if actualValue != expectedValue {
			t.Errorf("ODVA violation: Service '%s' code must be 0x%02X per ODVA spec, got 0x%02X",
				name, expectedValue, actualValue)
		}
	}
}

// TestENIPCommandCodeValuesODVA validates all command codes match ODVA spec exactly
// ODVA Spec: EtherNet/IP Encapsulation Protocol
// These values are standardized and MUST match exactly
func TestENIPCommandCodeValuesODVA(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	// ODVA standard command codes from EtherNet/IP Encapsulation Protocol
	odvaCommandCodes := map[string]uint16{
		"RegisterSession":   0x0065,
		"UnregisterSession": 0x0066,
		"SendRRData":        0x006F,
		"SendUnitData":      0x0070,
		"ListIdentity":      0x0063,
		"ListServices":      0x0004,
		"ListInterfaces":    0x0064,
	}

	ourCommandCodes := map[uint16]string{
		enip.ENIPCommandRegisterSession:   "RegisterSession",
		enip.ENIPCommandUnregisterSession: "UnregisterSession",
		enip.ENIPCommandSendRRData:        "SendRRData",
		enip.ENIPCommandSendUnitData:      "SendUnitData",
		enip.ENIPCommandListIdentity:      "ListIdentity",
		enip.ENIPCommandListServices:      "ListServices",
		enip.ENIPCommandListInterfaces:    "ListInterfaces",
	}

	for code, name := range ourCommandCodes {
		expectedValue, exists := odvaCommandCodes[name]
		if !exists {
			t.Errorf("ODVA violation: Command '%s' not found in ODVA spec", name)
			continue
		}

		if code != expectedValue {
			t.Errorf("ODVA violation: Command '%s' code must be 0x%04X per ODVA spec, got 0x%04X",
				name, expectedValue, code)
		}
	}
}

// TestEPATHSegmentTypeODVA validates EPATH segment type encoding per ODVA spec
// ODVA Spec: CIP Specification Volume 1, Section 3-5.2
// Segment type byte format:
// - Bits 0-3: Format (0=8-bit, 1=16-bit)
// - Bits 4-7: Segment type (0x2=class, 0x2=instance, 0x3=attribute)
func TestEPATHSegmentTypeODVA(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)
	tests := []struct {
		name          string
		path          protocol.CIPPath
		expectedTypes []uint8
		description   string
	}{
		{
			name: "8-bit segments",
			path: protocol.CIPPath{
				Class:     0x04,
				Instance:  0x65,
				Attribute: 0x03,
			},
			expectedTypes: []uint8{0x20, 0x24, 0x30}, // 8-bit class, instance, attribute
			description:   "ODVA: 8-bit segments use type 0x20/0x24/0x30 (format bit 0=0)",
		},
		{
			name: "16-bit class segment",
			path: protocol.CIPPath{
				Class:     0x0100,
				Instance:  0x65,
				Attribute: 0x03,
			},
			expectedTypes: []uint8{0x21, 0x24, 0x30}, // 16-bit class, 8-bit instance, 8-bit attribute
			description:   "ODVA: 16-bit class uses type 0x21 (format bit 0=1, type bits 4-7=0x2)",
		},
		{
			name: "16-bit instance segment",
			path: protocol.CIPPath{
				Class:     0x04,
				Instance:  0x0100,
				Attribute: 0x03,
			},
			expectedTypes: []uint8{0x20, 0x25, 0x30}, // 8-bit class, 16-bit instance, 8-bit attribute
			description:   "ODVA: 16-bit instance uses type 0x25 (format bit 0=1, type bits 4-7=0x2)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			epath := protocol.EncodeEPATH(tt.path)

			// Verify segment type bytes match ODVA spec
			if len(epath) < len(tt.expectedTypes)*2 {
				t.Fatalf("ODVA violation: EPATH too short, got %d bytes, need at least %d",
					len(epath), len(tt.expectedTypes)*2)
			}

			offset := 0
			for i, expectedType := range tt.expectedTypes {
				if epath[offset] != expectedType {
					t.Errorf("ODVA violation: Segment %d type: got 0x%02X, want 0x%02X (%s)",
						i, epath[offset], expectedType, tt.description)
				}
				// Move to next segment (type byte + data byte(s))
				if expectedType&0x01 == 0 {
					offset += 2 // 8-bit: type + 1 data byte
				} else {
					offset += 3 // 16-bit: type + 2 data bytes
				}
			}
		})
	}
}

