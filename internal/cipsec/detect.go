package cipsec

// TLS/DTLS detection for CIP Security.
//
// CIP Security (ODVA Volume 8) wraps EtherNet/IP in TLS (TCP) or DTLS (UDP).
// When CIP Security is active, port 44818 carries TLS records instead of
// plaintext ENIP frames. This file detects that condition by inspecting
// the first bytes of TCP payloads for TLS record layer signatures.

import (
	"encoding/binary"
	"fmt"
)

// TLS record header: ContentType(1) + ProtocolVersion(2) + Length(2) = 5 bytes.
const tlsRecordHeaderSize = 5

// Known TLS/DTLS protocol versions.
var knownTLSVersions = map[uint16]string{
	0x0301: "TLS 1.0",
	0x0302: "TLS 1.1",
	0x0303: "TLS 1.2",
	0x0304: "TLS 1.3",
}

var knownDTLSVersions = map[uint16]string{
	0xFEFF: "DTLS 1.0",
	0xFEFD: "DTLS 1.2",
}

// DetectTLS checks if TCP payload data appears to be a TLS record.
// Returns a SecurityIndicator if TLS is detected, nil otherwise.
func DetectTLS(data []byte) *SecurityIndicator {
	if len(data) < tlsRecordHeaderSize {
		return nil
	}

	contentType := TLSRecordType(data[0])
	version := binary.BigEndian.Uint16(data[1:3])
	length := binary.BigEndian.Uint16(data[3:5])

	// Validate content type (must be 20-23).
	if contentType < TLSChangeCipherSpec || contentType > TLSApplicationData {
		return nil
	}

	// Validate version.
	versionName, ok := knownTLSVersions[version]
	if !ok {
		return nil
	}

	// Validate length (TLS max record is 16384 + 2048 for overhead).
	if length == 0 || length > 18432 {
		return nil
	}

	confidence := 0.7
	details := map[string]string{
		"content_type": contentType.String(),
		"version":      versionName,
		"length":       fmt.Sprintf("%d", length),
	}

	// Higher confidence for ClientHello (handshake + sufficient length).
	if contentType == TLSHandshake && len(data) > tlsRecordHeaderSize {
		handshakeType := data[tlsRecordHeaderSize]
		switch handshakeType {
		case 0x01:
			confidence = 0.95
			details["handshake_type"] = "ClientHello"
		case 0x02:
			confidence = 0.95
			details["handshake_type"] = "ServerHello"
		}
	}

	// Full record present raises confidence.
	if int(length)+tlsRecordHeaderSize <= len(data) {
		confidence = min(confidence+0.05, 1.0)
	}

	return &SecurityIndicator{
		Type:        SecurityTLS,
		Description: fmt.Sprintf("TLS %s record detected (%s)", versionName, contentType),
		Confidence:  confidence,
		Details:     details,
	}
}

// DetectDTLS checks if UDP payload data appears to be a DTLS record.
// DTLS record header: ContentType(1) + Version(2) + Epoch(2) + SequenceNumber(6) + Length(2) = 13 bytes.
func DetectDTLS(data []byte) *SecurityIndicator {
	const dtlsRecordHeaderSize = 13
	if len(data) < dtlsRecordHeaderSize {
		return nil
	}

	contentType := TLSRecordType(data[0])
	version := binary.BigEndian.Uint16(data[1:3])
	length := binary.BigEndian.Uint16(data[11:13])

	// Validate content type.
	if contentType < TLSChangeCipherSpec || contentType > TLSApplicationData {
		return nil
	}

	// Validate DTLS version.
	versionName, ok := knownDTLSVersions[version]
	if !ok {
		return nil
	}

	if length == 0 || length > 18432 {
		return nil
	}

	confidence := 0.8
	details := map[string]string{
		"content_type": contentType.String(),
		"version":      versionName,
		"length":       fmt.Sprintf("%d", length),
		"epoch":        fmt.Sprintf("%d", binary.BigEndian.Uint16(data[3:5])),
	}

	if contentType == TLSHandshake && len(data) > dtlsRecordHeaderSize {
		handshakeType := data[dtlsRecordHeaderSize]
		if handshakeType == 0x01 {
			confidence = 0.95
			details["handshake_type"] = "ClientHello"
		}
	}

	return &SecurityIndicator{
		Type:        SecurityDTLS,
		Description: fmt.Sprintf("DTLS %s record detected (%s)", versionName, contentType),
		Confidence:  confidence,
		Details:     details,
	}
}

// DetectCIPSecurityObject checks if a CIP request targets a CIP Security object class.
// classID is the class from the CIP request path.
func DetectCIPSecurityObject(classID uint16) *SecurityIndicator {
	switch classID {
	case CIPSecurityObjectClass:
		return &SecurityIndicator{
			Type:        SecurityCIPSecurityObject,
			Description: "CIP Security Object (class 0x5D) access",
			Confidence:  1.0,
			Details:     map[string]string{"class_id": fmt.Sprintf("0x%04X", classID)},
		}
	case CertificateManagementClass:
		return &SecurityIndicator{
			Type:        SecurityCertificateManagement,
			Description: "Certificate Management Object (class 0x5E) access",
			Confidence:  1.0,
			Details:     map[string]string{"class_id": fmt.Sprintf("0x%04X", classID)},
		}
	case CIPSecurityInformationClass:
		return &SecurityIndicator{
			Type:        SecurityCIPSecurityObject,
			Description: "CIP Security Information Object (class 0x5F) access",
			Confidence:  1.0,
			Details:     map[string]string{"class_id": fmt.Sprintf("0x%04X", classID)},
		}
	default:
		return nil
	}
}

// IsTLSOnENIPPort returns true if data on the standard EtherNet/IP port
// (44818) appears to be TLS rather than plaintext ENIP.
// ENIP frames start with a 16-bit command (0x0004-0x0070 typically),
// while TLS records start with content type 0x14-0x17.
func IsTLSOnENIPPort(data []byte) bool {
	if len(data) < tlsRecordHeaderSize {
		return false
	}
	// ENIP commands are little-endian uint16 in range 0x0004-0x0070.
	// TLS content types are single bytes 0x14-0x17.
	// The second byte of an ENIP command is typically 0x00 (commands < 256).
	// For TLS, the second byte is the major version (0x03 for TLS 1.x).
	//
	// Discriminator: if byte[0] is 0x14-0x17 and byte[1] is 0x03,
	// it's almost certainly TLS, not ENIP.
	contentType := data[0]
	if contentType < 0x14 || contentType > 0x17 {
		return false
	}
	majorVersion := data[1]
	return majorVersion == 0x03
}
