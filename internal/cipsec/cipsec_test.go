package cipsec

import (
	"encoding/binary"
	"testing"
)

// --- TLS Detection Tests ---

func TestDetectTLS_ClientHello(t *testing.T) {
	// TLS 1.2 ClientHello record
	data := make([]byte, 100)
	data[0] = byte(TLSHandshake) // Content type: Handshake
	data[1] = 0x03               // TLS major version
	data[2] = 0x03               // TLS 1.2 minor version
	binary.BigEndian.PutUint16(data[3:5], 95) // Length
	data[5] = 0x01 // ClientHello handshake type

	ind := DetectTLS(data)
	if ind == nil {
		t.Fatal("expected TLS detection")
	}
	if ind.Type != SecurityTLS {
		t.Errorf("type = %v, want SecurityTLS", ind.Type)
	}
	if ind.Confidence < 0.9 {
		t.Errorf("confidence = %f, want >= 0.9", ind.Confidence)
	}
	if ind.Details["handshake_type"] != "ClientHello" {
		t.Errorf("handshake_type = %q, want ClientHello", ind.Details["handshake_type"])
	}
}

func TestDetectTLS_ServerHello(t *testing.T) {
	data := make([]byte, 100)
	data[0] = byte(TLSHandshake)
	data[1] = 0x03
	data[2] = 0x03
	binary.BigEndian.PutUint16(data[3:5], 95)
	data[5] = 0x02 // ServerHello

	ind := DetectTLS(data)
	if ind == nil {
		t.Fatal("expected TLS detection")
	}
	if ind.Details["handshake_type"] != "ServerHello" {
		t.Errorf("handshake_type = %q, want ServerHello", ind.Details["handshake_type"])
	}
}

func TestDetectTLS_ApplicationData(t *testing.T) {
	data := make([]byte, 100)
	data[0] = byte(TLSApplicationData) // 0x17
	data[1] = 0x03
	data[2] = 0x03
	binary.BigEndian.PutUint16(data[3:5], 95)

	ind := DetectTLS(data)
	if ind == nil {
		t.Fatal("expected TLS detection")
	}
	if ind.Type != SecurityTLS {
		t.Errorf("type = %v, want SecurityTLS", ind.Type)
	}
}

func TestDetectTLS_TooShort(t *testing.T) {
	data := []byte{0x16, 0x03, 0x03} // Only 3 bytes
	if ind := DetectTLS(data); ind != nil {
		t.Errorf("expected nil for short data, got %v", ind)
	}
}

func TestDetectTLS_InvalidContentType(t *testing.T) {
	data := make([]byte, 10)
	data[0] = 0x00 // Invalid content type
	data[1] = 0x03
	data[2] = 0x03
	binary.BigEndian.PutUint16(data[3:5], 5)

	if ind := DetectTLS(data); ind != nil {
		t.Errorf("expected nil for invalid content type, got %v", ind)
	}
}

func TestDetectTLS_UnknownVersion(t *testing.T) {
	data := make([]byte, 10)
	data[0] = byte(TLSHandshake)
	data[1] = 0x04 // Unknown major version
	data[2] = 0x00
	binary.BigEndian.PutUint16(data[3:5], 5)

	if ind := DetectTLS(data); ind != nil {
		t.Errorf("expected nil for unknown version, got %v", ind)
	}
}

func TestDetectTLS_ENIPNotConfused(t *testing.T) {
	// ENIP RegisterSession: command=0x0065, length=0x0004
	data := make([]byte, 28)
	binary.LittleEndian.PutUint16(data[0:2], 0x0065)
	binary.LittleEndian.PutUint16(data[2:4], 4)

	if ind := DetectTLS(data); ind != nil {
		t.Errorf("ENIP frame detected as TLS: %v", ind)
	}
}

// --- DTLS Detection Tests ---

func TestDetectDTLS_ClientHello(t *testing.T) {
	data := make([]byte, 50)
	data[0] = byte(TLSHandshake) // Content type
	data[1] = 0xFE               // DTLS 1.2 version
	data[2] = 0xFD
	// Epoch(2) + Sequence(6) at bytes 3-10
	binary.BigEndian.PutUint16(data[11:13], 37) // Length
	data[13] = 0x01 // ClientHello

	ind := DetectDTLS(data)
	if ind == nil {
		t.Fatal("expected DTLS detection")
	}
	if ind.Type != SecurityDTLS {
		t.Errorf("type = %v, want SecurityDTLS", ind.Type)
	}
	if ind.Confidence < 0.9 {
		t.Errorf("confidence = %f, want >= 0.9", ind.Confidence)
	}
}

func TestDetectDTLS_TooShort(t *testing.T) {
	data := make([]byte, 10) // Less than 13 bytes
	if ind := DetectDTLS(data); ind != nil {
		t.Errorf("expected nil for short data, got %v", ind)
	}
}

// --- CIP Security Object Detection Tests ---

func TestDetectCIPSecurityObject(t *testing.T) {
	tests := []struct {
		classID uint16
		wantNil bool
		wantType SecurityType
	}{
		{CIPSecurityObjectClass, false, SecurityCIPSecurityObject},
		{CertificateManagementClass, false, SecurityCertificateManagement},
		{CIPSecurityInformationClass, false, SecurityCIPSecurityObject},
		{0x01, true, 0}, // Identity class, not security
		{0x00, true, 0},
	}

	for _, tt := range tests {
		ind := DetectCIPSecurityObject(tt.classID)
		if tt.wantNil {
			if ind != nil {
				t.Errorf("class 0x%04X: expected nil, got %v", tt.classID, ind)
			}
		} else {
			if ind == nil {
				t.Fatalf("class 0x%04X: expected indicator", tt.classID)
			}
			if ind.Type != tt.wantType {
				t.Errorf("class 0x%04X: type = %v, want %v", tt.classID, ind.Type, tt.wantType)
			}
			if ind.Confidence != 1.0 {
				t.Errorf("class 0x%04X: confidence = %f, want 1.0", tt.classID, ind.Confidence)
			}
		}
	}
}

// --- IsTLSOnENIPPort Tests ---

func TestIsTLSOnENIPPort(t *testing.T) {
	// TLS Handshake on port 44818
	tls := []byte{0x16, 0x03, 0x03, 0x00, 0x05}
	if !IsTLSOnENIPPort(tls) {
		t.Error("expected TLS detection")
	}

	// ENIP RegisterSession
	enip := make([]byte, 28)
	binary.LittleEndian.PutUint16(enip[0:2], 0x0065)
	if IsTLSOnENIPPort(enip) {
		t.Error("ENIP misdetected as TLS")
	}

	// Too short
	if IsTLSOnENIPPort([]byte{0x16}) {
		t.Error("short data should not be TLS")
	}
}

// --- Safety Class Detection Tests ---

func TestIsSafetyClass(t *testing.T) {
	for classID := uint16(0x39); classID <= 0x3F; classID++ {
		if !IsSafetyClass(classID) {
			t.Errorf("class 0x%02X should be safety", classID)
		}
	}
	if IsSafetyClass(0x01) {
		t.Error("Identity class should not be safety")
	}
	if IsSafetyClass(0x40) {
		t.Error("class 0x40 should not be safety")
	}
}

func TestDetectSafetyClass(t *testing.T) {
	ind := DetectSafetyClass(0x39)
	if ind == nil {
		t.Fatal("expected safety indicator for 0x39")
	}
	if ind.ClassID != 0x39 {
		t.Errorf("classID = 0x%04X, want 0x0039", ind.ClassID)
	}
	if ind.ClassName != "Safety_Supervisor" {
		t.Errorf("className = %q, want Safety_Supervisor", ind.ClassName)
	}
	if ind.Confidence != 1.0 {
		t.Errorf("confidence = %f, want 1.0", ind.Confidence)
	}

	if ind := DetectSafetyClass(0x01); ind != nil {
		t.Errorf("expected nil for non-safety class, got %v", ind)
	}
}

// --- Safety Payload Detection Tests ---

func TestDetectSafetyPayload_ShortFormat(t *testing.T) {
	// 10 bytes data + 3 bytes safety overhead = 13 bytes
	payload := make([]byte, 13)
	ind := DetectSafetyPayload(payload, 10)
	if ind == nil {
		t.Fatal("expected safety payload detection (short format)")
	}
	if ind.Details["format"] != "short" {
		t.Errorf("format = %q, want short", ind.Details["format"])
	}
}

func TestDetectSafetyPayload_ExtendedFormat(t *testing.T) {
	// 10 bytes data + 7 bytes safety overhead = 17 bytes
	payload := make([]byte, 17)
	ind := DetectSafetyPayload(payload, 10)
	if ind == nil {
		t.Fatal("expected safety payload detection (extended format)")
	}
	if ind.Details["format"] != "extended" {
		t.Errorf("format = %q, want extended", ind.Details["format"])
	}
}

func TestDetectSafetyPayload_NoExpectedSize(t *testing.T) {
	// Mode byte = 0x01 (run) at position len-3
	payload := make([]byte, 13)
	payload[10] = 0x01 // mode byte at len-3
	ind := DetectSafetyPayload(payload, 0)
	if ind == nil {
		t.Fatal("expected heuristic safety payload detection")
	}
	if ind.Confidence > 0.5 {
		t.Errorf("heuristic confidence should be low, got %f", ind.Confidence)
	}
}

func TestDetectSafetyPayload_Empty(t *testing.T) {
	if ind := DetectSafetyPayload(nil, 0); ind != nil {
		t.Errorf("expected nil for empty payload, got %v", ind)
	}
}

// --- Safety ForwardOpen Detection Tests ---

func TestDetectSafetyForwardOpen_ClassPath(t *testing.T) {
	// Connection path: class 0x39 (Safety Supervisor)
	path := []byte{0x20, 0x39, 0x24, 0x01}
	ind := DetectSafetyForwardOpen(path)
	if ind == nil {
		t.Fatal("expected safety detection in ForwardOpen")
	}
	if ind.ClassID != 0x39 {
		t.Errorf("classID = 0x%04X, want 0x0039", ind.ClassID)
	}
}

func TestDetectSafetyForwardOpen_SafetyNetworkSegment(t *testing.T) {
	// Safety network number segment (0x43)
	path := []byte{0x20, 0x01, 0x43, 0x00}
	ind := DetectSafetyForwardOpen(path)
	if ind == nil {
		t.Fatal("expected safety network number detection")
	}
	if ind.Details["segment"] != "safety_network_number" {
		t.Errorf("segment = %q, want safety_network_number", ind.Details["segment"])
	}
}

func TestDetectSafetyForwardOpen_NonSafety(t *testing.T) {
	// Regular path: class 0x04 (Assembly)
	path := []byte{0x20, 0x04, 0x24, 0x64}
	if ind := DetectSafetyForwardOpen(path); ind != nil {
		t.Errorf("expected nil for non-safety path, got %v", ind)
	}
}

func TestDetectSafetyForwardOpen_Empty(t *testing.T) {
	if ind := DetectSafetyForwardOpen(nil); ind != nil {
		t.Errorf("expected nil for empty path, got %v", ind)
	}
}

// --- Batch Analysis Tests ---

func TestAnalyzeSafetyClasses(t *testing.T) {
	classes := []uint16{0x01, 0x39, 0x3A, 0x04, 0x3F, 0x39} // 0x39 duplicated
	indicators := AnalyzeSafetyClasses(classes)
	if len(indicators) != 3 { // 0x39, 0x3A, 0x3F (deduplicated)
		t.Errorf("indicators = %d, want 3", len(indicators))
	}
}

func TestAnalyzeSafetyClasses_Empty(t *testing.T) {
	indicators := AnalyzeSafetyClasses(nil)
	if len(indicators) != 0 {
		t.Errorf("indicators = %d, want 0", len(indicators))
	}
}

// --- DetectionResult Tests ---

func TestDetectionResult(t *testing.T) {
	r := &DetectionResult{}
	if r.HasSecurity() {
		t.Error("empty result should not have security")
	}
	if r.HasSafety() {
		t.Error("empty result should not have safety")
	}

	r.Security = append(r.Security, SecurityIndicator{Type: SecurityTLS})
	if !r.HasSecurity() {
		t.Error("result with TLS should have security")
	}

	r.Safety = append(r.Safety, SafetyIndicator{ClassID: 0x39})
	if !r.HasSafety() {
		t.Error("result with safety class should have safety")
	}
}

// --- Type String Tests ---

func TestSecurityTypeString(t *testing.T) {
	if SecurityTLS.String() != "TLS" {
		t.Errorf("SecurityTLS.String() = %q", SecurityTLS.String())
	}
	if SecurityDTLS.String() != "DTLS" {
		t.Errorf("SecurityDTLS.String() = %q", SecurityDTLS.String())
	}
	if SecurityType(99).String() != "unknown" {
		t.Errorf("unknown security type string = %q", SecurityType(99).String())
	}
}

func TestTLSRecordTypeString(t *testing.T) {
	if TLSHandshake.String() != "Handshake" {
		t.Errorf("TLSHandshake.String() = %q", TLSHandshake.String())
	}
	if TLSRecordType(99).String() != "unknown" {
		t.Errorf("unknown TLS type string = %q", TLSRecordType(99).String())
	}
}

func TestSafetyConnectionTypeString(t *testing.T) {
	if SafetyTypeSinglecast.String() != "singlecast" {
		t.Errorf("SafetyTypeSinglecast.String() = %q", SafetyTypeSinglecast.String())
	}
	if SafetyTypeUnknown.String() != "unknown" {
		t.Errorf("SafetyTypeUnknown.String() = %q", SafetyTypeUnknown.String())
	}
}
