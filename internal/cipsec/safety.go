package cipsec

// CIP Safety detection in CIP traffic.
//
// CIP Safety (ODVA Vol 5) uses classes 0x39-0x3F for safety applications.
// Safety connections have additional CRC and timestamp data appended to
// the standard CIP payload. This file detects safety-related traffic
// by examining CIP request paths and connection parameters.

import (
	"fmt"
)

// SafetyConnectionType classifies the type of safety connection.
type SafetyConnectionType int

const (
	// SafetyTypeUnknown is a safety connection of unknown type.
	SafetyTypeUnknown SafetyConnectionType = iota
	// SafetyTypeSinglecast is a point-to-point safety connection.
	SafetyTypeSinglecast
	// SafetyTypeMulticast is a multicast safety connection.
	SafetyTypeMulticast
)

// String returns a human-readable name.
func (t SafetyConnectionType) String() string {
	switch t {
	case SafetyTypeSinglecast:
		return "singlecast"
	case SafetyTypeMulticast:
		return "multicast"
	default:
		return "unknown"
	}
}

// DetectSafetyClass checks if a CIP path class is a CIP Safety class.
// Returns a SafetyIndicator if the class is safety-related.
func DetectSafetyClass(classID uint16) *SafetyIndicator {
	name, ok := SafetyClass[classID]
	if !ok {
		return nil
	}

	return &SafetyIndicator{
		ClassID:     classID,
		ClassName:   name,
		Description: fmt.Sprintf("CIP Safety class %s (0x%02X)", name, classID),
		Confidence:  1.0,
		Details:     map[string]string{"class_id": fmt.Sprintf("0x%04X", classID)},
	}
}

// DetectSafetyPayload checks if a CIP I/O payload contains a CIP Safety
// data format. Safety payloads have a specific structure:
//
//	For "short format" (base): actual_data + mode_byte + CRC_S_1(2) = data + 3 bytes
//	For "long format" (extended): actual_data + mode_byte + CRC_S_1(2) + timestamp(2) + CRC_S_2(2) = data + 7 bytes
//
// This is a heuristic: we check if the payload length is consistent with
// safety framing given a plausible actual data size.
func DetectSafetyPayload(payload []byte, expectedDataSize int) *SafetyIndicator {
	if len(payload) == 0 {
		return nil
	}

	payloadLen := len(payload)

	// Short format: data(N) + mode(1) + CRC_S_1(2) = N + 3
	shortOverhead := 3
	// Extended format: data(N) + mode(1) + CRC_S_1(2) + timestamp(2) + CRC_S_2(2) = N + 7
	extendedOverhead := 7

	if expectedDataSize > 0 {
		if payloadLen == expectedDataSize+shortOverhead {
			return &SafetyIndicator{
				ClassName:   "Safety_Payload",
				Description: "CIP Safety short format payload detected",
				Confidence:  0.7,
				Details: map[string]string{
					"format":    "short",
					"data_size": fmt.Sprintf("%d", expectedDataSize),
					"overhead":  fmt.Sprintf("%d", shortOverhead),
				},
			}
		}
		if payloadLen == expectedDataSize+extendedOverhead {
			return &SafetyIndicator{
				ClassName:   "Safety_Payload",
				Description: "CIP Safety extended format payload detected",
				Confidence:  0.7,
				Details: map[string]string{
					"format":    "extended",
					"data_size": fmt.Sprintf("%d", expectedDataSize),
					"overhead":  fmt.Sprintf("%d", extendedOverhead),
				},
			}
		}
	}

	// Without expected data size, check if the last byte looks like a mode byte.
	// Mode byte: bits 0-2 are run/idle, bits 3-7 vary.
	// Common mode byte values: 0x00 (idle), 0x01 (run), 0xFF (invalid/default).
	if payloadLen >= shortOverhead {
		modeByteIdx := payloadLen - shortOverhead
		modeByte := payload[modeByteIdx]
		// Mode byte run/idle field should be 0 or 1.
		if modeByte == 0x00 || modeByte == 0x01 {
			return &SafetyIndicator{
				ClassName:   "Safety_Payload",
				Description: "Possible CIP Safety payload (mode byte heuristic)",
				Confidence:  0.3,
				Details: map[string]string{
					"mode_byte":    fmt.Sprintf("0x%02X", modeByte),
					"payload_size": fmt.Sprintf("%d", payloadLen),
				},
			}
		}
	}

	return nil
}

// DetectSafetyForwardOpen checks if ForwardOpen connection parameters
// indicate a safety connection. Safety connections use:
//   - Connection type = 1 (point-to-point) or 2 (multicast)
//   - Safety network segment in the connection path
//   - Electronic key with Safety device profile (0x12)
//
// connectionPath is the raw connection path from the ForwardOpen request.
func DetectSafetyForwardOpen(connectionPath []byte) *SafetyIndicator {
	if len(connectionPath) < 2 {
		return nil
	}

	// Scan the connection path for safety-related segments.
	for i := 0; i+1 < len(connectionPath); {
		segType := connectionPath[i]

		// Check for electronic key segment (0x34).
		if segType == 0x34 && i+6 < len(connectionPath) {
			// Electronic key: vendor(2) + device_type(2) + ...
			// Device type 0x12 = Safety I/O device
			deviceType := uint16(connectionPath[i+3]) | uint16(connectionPath[i+4])<<8
			if deviceType == 0x12 {
				return &SafetyIndicator{
					ClassName:   "Safety_ForwardOpen",
					Description: "ForwardOpen with Safety device profile (device type 0x12)",
					Confidence:  0.9,
					Details: map[string]string{
						"device_type": "0x0012",
						"segment":     "electronic_key",
					},
				}
			}
			i += 2 + 8 // Skip key segment (type + size + 8 bytes of key data)
			continue
		}

		// Check for Safety Network Number segment.
		// Network segment type: 0x43 = Safety
		if segType == 0x43 {
			return &SafetyIndicator{
				ClassName:   "Safety_ForwardOpen",
				Description: "ForwardOpen with Safety Network Number segment",
				Confidence:  0.95,
				Details: map[string]string{
					"segment": "safety_network_number",
				},
			}
		}

		// Check for class path targeting safety classes.
		if segType == 0x20 && i+1 < len(connectionPath) {
			classID := uint16(connectionPath[i+1])
			if IsSafetyClass(classID) {
				return &SafetyIndicator{
					ClassID:     classID,
					ClassName:   SafetyClass[classID],
					Description: fmt.Sprintf("ForwardOpen targeting Safety class %s (0x%02X)", SafetyClass[classID], classID),
					Confidence:  0.9,
					Details: map[string]string{
						"class_id": fmt.Sprintf("0x%04X", classID),
						"segment":  "class_path",
					},
				}
			}
			i += 2
			continue
		}

		// 16-bit class segment.
		if segType == 0x21 && i+3 < len(connectionPath) {
			classID := uint16(connectionPath[i+2]) | uint16(connectionPath[i+3])<<8
			if IsSafetyClass(classID) {
				return &SafetyIndicator{
					ClassID:     classID,
					ClassName:   SafetyClass[classID],
					Description: fmt.Sprintf("ForwardOpen targeting Safety class %s (0x%04X)", SafetyClass[classID], classID),
					Confidence:  0.9,
					Details: map[string]string{
						"class_id": fmt.Sprintf("0x%04X", classID),
						"segment":  "class_path_16bit",
					},
				}
			}
			i += 4
			continue
		}

		// Advance: 8-bit segments are 2 bytes, 16-bit are 4 bytes.
		if segType&0x01 == 0 {
			i += 2
		} else {
			i += 4
		}
	}

	return nil
}

// AnalyzeSafetyClasses scans a set of class IDs and returns all that are
// safety-related. Useful for batch analysis of PCAP data.
func AnalyzeSafetyClasses(classIDs []uint16) []SafetyIndicator {
	var indicators []SafetyIndicator
	seen := make(map[uint16]bool)

	for _, id := range classIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		if ind := DetectSafetyClass(id); ind != nil {
			indicators = append(indicators, *ind)
		}
	}
	return indicators
}
