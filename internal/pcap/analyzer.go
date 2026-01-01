package pcap

// Packet capture analysis framework for CIPDIP
// This package provides tools for analyzing captured EtherNet/IP packets

import (
	"encoding/binary"
	"fmt"
)

// PacketInfo represents information about a captured packet
type PacketInfo struct {
	Timestamp   string
	SourceIP    string
	DestIP      string
	SourcePort  uint16
	DestPort    uint16
	Protocol    string // "TCP" or "UDP"
	ENIPCommand uint16
	SessionID   uint32
	Status      uint32
	DataLength  uint16
	IsValid     bool
	Errors      []string
}

// AnalyzeENIPPacket analyzes a raw packet and extracts ENIP information
func AnalyzeENIPPacket(packetData []byte) (*PacketInfo, error) {
	info := &PacketInfo{
		IsValid: true,
		Errors:  make([]string, 0),
	}

	// Minimum ENIP header size is 24 bytes
	if len(packetData) < 24 {
		info.IsValid = false
		info.Errors = append(info.Errors, fmt.Sprintf("packet too short: %d bytes (minimum 24)", len(packetData)))
		return info, fmt.Errorf("packet too short")
	}

	// Parse ENIP header
	// Offset 0-1: Command (2 bytes, big-endian)
	info.ENIPCommand = binary.BigEndian.Uint16(packetData[0:2])

	// Offset 2-3: Length (2 bytes, big-endian)
	info.DataLength = binary.BigEndian.Uint16(packetData[2:4])

	// Offset 4-7: Session Handle (4 bytes, big-endian)
	info.SessionID = binary.BigEndian.Uint32(packetData[4:8])

	// Offset 8-11: Status (4 bytes, big-endian)
	info.Status = binary.BigEndian.Uint32(packetData[8:12])

	// Validate packet length matches header
	expectedLength := 24 + int(info.DataLength)
	if len(packetData) < expectedLength {
		info.IsValid = false
		info.Errors = append(info.Errors, fmt.Sprintf("packet length mismatch: header says %d bytes, got %d", expectedLength, len(packetData)))
	}

	// Validate ENIP command codes
	validCommands := map[uint16]bool{
		0x0065: true, // RegisterSession
		0x0066: true, // UnregisterSession
		0x006F: true, // SendRRData
		0x0070: true, // SendUnitData
		0x0063: true, // ListIdentity
	}
	if !validCommands[info.ENIPCommand] {
		info.Errors = append(info.Errors, fmt.Sprintf("unknown ENIP command: 0x%04X", info.ENIPCommand))
	}

	return info, nil
}

// ValidateODVACompliance checks if a packet is ODVA-compliant
func ValidateODVACompliance(packetData []byte) (bool, []string) {
	info, err := AnalyzeENIPPacket(packetData)
	if err != nil {
		return false, []string{err.Error()}
	}

	errors := make([]string, 0)

	// Check header structure
	if len(packetData) < 24 {
		errors = append(errors, "ENIP header incomplete (must be 24 bytes)")
	}

	// Check length field consistency
	if len(packetData) < 24+int(info.DataLength) {
		errors = append(errors, "Packet length field inconsistent with actual length")
	}

	// Check status field (should be 0x00000000 for requests)
	// Note: This is a simplified check; responses may have non-zero status
	if info.Status != 0 && info.ENIPCommand != 0x0065 {
		// RegisterSession response may have non-zero status, but others should be 0 for requests
		errors = append(errors, fmt.Sprintf("Unexpected status value: 0x%08X", info.Status))
	}

	// Check sender context (bytes 12-19) - should not be all zeros for requests
	senderContext := packetData[12:20]
	allZeros := true
	for _, b := range senderContext {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros && info.ENIPCommand != 0x0063 {
		// ListIdentity may have zero sender context, but others should have unique context
		errors = append(errors, "Sender context is all zeros (should be unique)")
	}

	// Check options field (bytes 20-23) - should be 0x00000000
	options := binary.BigEndian.Uint32(packetData[20:24])
	if options != 0 {
		errors = append(errors, fmt.Sprintf("Options field non-zero: 0x%08X (should be 0x00000000)", options))
	}

	return len(errors) == 0, errors
}

// ExtractCIPData extracts CIP data from an ENIP packet
func ExtractCIPData(packetData []byte) ([]byte, error) {
	if len(packetData) < 24 {
		return nil, fmt.Errorf("packet too short for ENIP header")
	}

	// ENIP header is 24 bytes, CIP data follows
	if len(packetData) == 24 {
		return []byte{}, nil // No CIP data
	}

	// For SendRRData, CIP data starts after interface handle (4 bytes) and timeout (2 bytes)
	command := binary.BigEndian.Uint16(packetData[0:2])
	if command == 0x006F { // SendRRData
		if len(packetData) < 24+6 {
			return nil, fmt.Errorf("packet too short for SendRRData structure")
		}
		return packetData[24+6:], nil
	}

	// For SendUnitData, CIP data starts after connection ID (4 bytes)
	if command == 0x0070 { // SendUnitData
		if len(packetData) < 24+4 {
			return nil, fmt.Errorf("packet too short for SendUnitData structure")
		}
		return packetData[24+4:], nil
	}

	// For other commands, CIP data starts immediately after ENIP header
	return packetData[24:], nil
}

// ComparePackets compares two packets and reports differences
func ComparePackets(packet1, packet2 []byte) ([]string, error) {
	info1, err1 := AnalyzeENIPPacket(packet1)
	info2, err2 := AnalyzeENIPPacket(packet2)

	if err1 != nil {
		return nil, fmt.Errorf("error analyzing packet 1: %w", err1)
	}
	if err2 != nil {
		return nil, fmt.Errorf("error analyzing packet 2: %w", err2)
	}

	differences := make([]string, 0)

	if info1.ENIPCommand != info2.ENIPCommand {
		differences = append(differences, fmt.Sprintf("Command: 0x%04X vs 0x%04X", info1.ENIPCommand, info2.ENIPCommand))
	}

	if info1.SessionID != info2.SessionID {
		differences = append(differences, fmt.Sprintf("Session ID: 0x%08X vs 0x%08X", info1.SessionID, info2.SessionID))
	}

	if info1.DataLength != info2.DataLength {
		differences = append(differences, fmt.Sprintf("Data Length: %d vs %d", info1.DataLength, info2.DataLength))
	}

	if info1.Status != info2.Status {
		differences = append(differences, fmt.Sprintf("Status: 0x%08X vs 0x%08X", info1.Status, info2.Status))
	}

	// Compare sender context (bytes 12-19)
	senderCtx1 := packet1[12:20]
	senderCtx2 := packet2[12:20]
	if len(senderCtx1) == 8 && len(senderCtx2) == 8 {
		for i := 0; i < 8; i++ {
			if senderCtx1[i] != senderCtx2[i] {
				differences = append(differences, fmt.Sprintf("Sender context byte %d: 0x%02X vs 0x%02X", i, senderCtx1[i], senderCtx2[i]))
				break // Just note that sender context differs
			}
		}
	}

	// Compare CIP data if available
	cip1, err1 := ExtractCIPData(packet1)
	cip2, err2 := ExtractCIPData(packet2)
	if err1 == nil && err2 == nil {
		if len(cip1) != len(cip2) {
			differences = append(differences, fmt.Sprintf("CIP data length: %d vs %d", len(cip1), len(cip2)))
		} else {
			diffCount := 0
			for i := 0; i < len(cip1) && i < len(cip2); i++ {
				if cip1[i] != cip2[i] {
					if diffCount < 5 {
						differences = append(differences, fmt.Sprintf("CIP data byte %d: 0x%02X vs 0x%02X", i, cip1[i], cip2[i]))
						diffCount++
					}
				}
			}
			if diffCount >= 5 {
				differences = append(differences, fmt.Sprintf("... (%d more CIP data differences)", len(cip1)-diffCount))
			}
		}
	}

	return differences, nil
}
