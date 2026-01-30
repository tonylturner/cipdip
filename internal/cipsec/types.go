package cipsec

// CIP Security and Safety detection types.
//
// CIP Security (ODVA Vol 8) adds TLS/DTLS to EtherNet/IP connections.
// CIP Safety (SIL2/SIL3) uses dedicated object classes 0x39-0x3F.
//
// This package provides heuristic detection of both in captured traffic
// without requiring full protocol decoding.

// SecurityIndicator describes a detected CIP Security signal.
type SecurityIndicator struct {
	Type        SecurityType
	Description string
	Confidence  float64 // 0.0–1.0
	Details     map[string]string
}

// SecurityType classifies a security detection.
type SecurityType int

const (
	// SecurityTLS indicates TLS (port 44818 encrypted session).
	SecurityTLS SecurityType = iota
	// SecurityDTLS indicates DTLS (UDP encrypted I/O).
	SecurityDTLS
	// SecurityCIPSecurityObject indicates CIP Security Object access (class 0x5D).
	SecurityCIPSecurityObject
	// SecurityCertificateManagement indicates Certificate Management Object access (class 0x5E).
	SecurityCertificateManagement
)

// String returns a human-readable name for the security type.
func (s SecurityType) String() string {
	switch s {
	case SecurityTLS:
		return "TLS"
	case SecurityDTLS:
		return "DTLS"
	case SecurityCIPSecurityObject:
		return "CIP_Security_Object"
	case SecurityCertificateManagement:
		return "Certificate_Management"
	default:
		return "unknown"
	}
}

// SafetyIndicator describes a detected CIP Safety signal.
type SafetyIndicator struct {
	ClassID     uint16
	ClassName   string
	Description string
	Confidence  float64
	Details     map[string]string
}

// SafetyClass maps CIP Safety object class IDs to names.
var SafetyClass = map[uint16]string{
	0x39: "Safety_Supervisor",
	0x3A: "Safety_Validator",
	0x3B: "Safety_Discrete_Output_Point",
	0x3C: "Safety_Discrete_Output_Group",
	0x3D: "Safety_Discrete_Input_Point",
	0x3E: "Safety_Discrete_Input_Group",
	0x3F: "Safety_Dual_Channel_Output",
}

// IsSafetyClass returns true if the class ID is a CIP Safety class.
func IsSafetyClass(classID uint16) bool {
	_, ok := SafetyClass[classID]
	return ok
}

// CIP Security object classes (ODVA Volume 8).
const (
	CIPSecurityObjectClass          uint16 = 0x5D
	CertificateManagementClass      uint16 = 0x5E
	CIPSecurityInformationClass     uint16 = 0x5F
	EtherNetIPSecurityClass         uint16 = 0x60 // not yet standardized widely
)

// TLSRecordType identifies a TLS record content type.
type TLSRecordType uint8

const (
	TLSChangeCipherSpec TLSRecordType = 20
	TLSAlert            TLSRecordType = 21
	TLSHandshake        TLSRecordType = 22
	TLSApplicationData  TLSRecordType = 23
)

// String returns a human-readable name for the TLS record type.
func (t TLSRecordType) String() string {
	switch t {
	case TLSChangeCipherSpec:
		return "ChangeCipherSpec"
	case TLSAlert:
		return "Alert"
	case TLSHandshake:
		return "Handshake"
	case TLSApplicationData:
		return "ApplicationData"
	default:
		return "unknown"
	}
}

// DetectionResult holds the combined results of CIP Security/Safety analysis.
type DetectionResult struct {
	Security []SecurityIndicator
	Safety   []SafetyIndicator
	Summary  string
}

// HasSecurity returns true if any CIP Security indicators were detected.
func (r *DetectionResult) HasSecurity() bool {
	return len(r.Security) > 0
}

// HasSafety returns true if any CIP Safety indicators were detected.
func (r *DetectionResult) HasSafety() bool {
	return len(r.Safety) > 0
}
