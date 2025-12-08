package cipclient

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ExtractENIPFromPCAP extracts ENIP packets from a PCAP file
func ExtractENIPFromPCAP(pcapFile string) ([]ENIPPacket, error) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil, fmt.Errorf("open pcap file: %w", err)
	}
	defer handle.Close()

	var packets []ENIPPacket
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		enipData := extractENIPFromPacket(packet)
		if enipData != nil {
			packets = append(packets, *enipData)
		}
	}

	return packets, nil
}

// ENIPPacket represents an extracted ENIP packet from a PCAP
type ENIPPacket struct {
	Command     uint16
	SessionID   uint32
	Data        []byte
	FullPacket  []byte // Full ENIP packet (24-byte header + data)
	IsRequest   bool   // true if request, false if response
	Description string // Description of the packet
}

// extractENIPFromPacket extracts ENIP data from a gopacket.Packet
func extractENIPFromPacket(packet gopacket.Packet) *ENIPPacket {
	// Check for TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		// Check if it's port 44818
		if tcp.DstPort == 44818 || tcp.SrcPort == 44818 {
			// Try ApplicationLayer first (gopacket may have reassembled it)
			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				payload := appLayer.Payload()
				if len(payload) > 0 {
					if result := extractENIPFromPayload(payload, tcp.DstPort == 44818); result != nil {
						return result
					}
				}
			}
			// Fall back to TCP payload (for non-reassembled packets)
			if len(tcp.Payload) > 0 {
				return extractENIPFromPayload(tcp.Payload, tcp.DstPort == 44818)
			}
			// If still nothing, this might be an ACK/SYN packet without data
			return nil
		}
	}

	// Check for UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		// Check if it's port 44818 or 2222
		if udp.DstPort == 44818 || udp.SrcPort == 44818 || udp.DstPort == 2222 || udp.SrcPort == 2222 {
			if len(udp.Payload) > 0 {
				return extractENIPFromPayload(udp.Payload, udp.DstPort == 44818 || udp.DstPort == 2222)
			}
		}
	}

	return nil
}

// extractENIPFromPayload extracts ENIP data from a payload
func extractENIPFromPayload(payload []byte, isToServer bool) *ENIPPacket {
	if len(payload) < 24 {
		return nil
	}

	// Check if it looks like an ENIP packet
	// ENIP header starts with command code
	command := binary.BigEndian.Uint16(payload[0:2])

	// Validate command code
	validCommands := map[uint16]bool{
		0x0065: true, // RegisterSession
		0x0066: true, // UnregisterSession
		0x006F: true, // SendRRData
		0x0070: true, // SendUnitData
		0x0063: true, // ListIdentity
	}
	if !validCommands[command] {
		return nil
	}

	// Extract length
	length := binary.BigEndian.Uint16(payload[2:4])

	// Validate length
	if len(payload) < 24+int(length) {
		return nil
	}

	// Extract full packet
	fullPacket := make([]byte, 24+int(length))
	copy(fullPacket, payload[:24+int(length)])

	// Extract data
	var data []byte
	if length > 0 {
		data = make([]byte, length)
		copy(data, payload[24:24+int(length)])
	}

	// Extract session ID
	sessionID := binary.BigEndian.Uint32(payload[4:8])

	// Determine if request or response
	// Requests typically have status = 0, responses may have non-zero status
	status := binary.BigEndian.Uint32(payload[8:12])

	// Special handling for RegisterSession:
	// - Request: status = 0 AND sessionID = 0
	// - Response: status = 0 AND sessionID != 0 (server assigns session ID)
	var isRequest bool
	if command == 0x0065 { // RegisterSession
		isRequest = (status == 0 && sessionID == 0)
	} else {
		// For other commands, status = 0 means request
		isRequest = (status == 0)
	}

	// Generate description
	description := generatePacketDescription(command, isRequest, data)

	return &ENIPPacket{
		Command:     command,
		SessionID:   sessionID,
		Data:        data,
		FullPacket:  fullPacket,
		IsRequest:   isRequest,
		Description: description,
	}
}

// generatePacketDescription generates a human-readable description of the packet
func generatePacketDescription(command uint16, isRequest bool, data []byte) string {
	var cmdName string
	switch command {
	case 0x0065:
		cmdName = "RegisterSession"
	case 0x0066:
		cmdName = "UnregisterSession"
	case 0x006F:
		cmdName = "SendRRData"
	case 0x0070:
		cmdName = "SendUnitData"
	case 0x0063:
		cmdName = "ListIdentity"
	default:
		cmdName = fmt.Sprintf("Unknown(0x%04X)", command)
	}

	dir := "Request"
	if !isRequest {
		dir = "Response"
	}

	// Try to identify CIP service if it's SendRRData
	if command == 0x006F && len(data) >= 6 {
		cipData := data[6:] // Skip interface handle and timeout
		if len(cipData) > 0 {
			serviceCode := cipData[0]
			serviceName := getCIPServiceName(serviceCode)
			if serviceName != "" {
				return fmt.Sprintf("%s %s (%s)", cmdName, dir, serviceName)
			}
		}
	}

	return fmt.Sprintf("%s %s", cmdName, dir)
}

// getCIPServiceName returns the name of a CIP service code
func getCIPServiceName(code uint8) string {
	switch CIPServiceCode(code) {
	case CIPServiceGetAttributeSingle:
		return "Get_Attribute_Single"
	case CIPServiceSetAttributeSingle:
		return "Set_Attribute_Single"
	case CIPServiceForwardOpen:
		return "Forward_Open"
	case CIPServiceForwardClose:
		return "Forward_Close"
	case CIPServiceGetAttributeAll:
		return "Get_Attribute_All"
	case CIPServiceSetAttributeAll:
		return "Set_Attribute_All"
	default:
		return ""
	}
}

// FindReferencePackets finds key reference packets from a PCAP file
func FindReferencePackets(pcapFile string) (map[string]ENIPPacket, error) {
	packets, err := ExtractENIPFromPCAP(pcapFile)
	if err != nil {
		return nil, err
	}

	referencePackets := make(map[string]ENIPPacket)

	// Look for key packet types
	for _, pkt := range packets {
		key := getReferenceKey(pkt)
		if key != "" {
			// Only keep the first occurrence of each type
			if _, exists := referencePackets[key]; !exists {
				referencePackets[key] = pkt
			}
		}
	}

	return referencePackets, nil
}

// getReferenceKey returns a key for the reference packet map
func getReferenceKey(pkt ENIPPacket) string {
	switch pkt.Command {
	case 0x0065: // RegisterSession
		if pkt.IsRequest {
			return "RegisterSession_Request"
		}
		return "RegisterSession_Response"
	case 0x006F: // SendRRData
		if len(pkt.Data) >= 6 {
			cipData := pkt.Data[6:]
			if len(cipData) > 0 {
				serviceCode := cipData[0]
				switch CIPServiceCode(serviceCode) {
				case CIPServiceGetAttributeSingle:
					if pkt.IsRequest {
						return "GetAttributeSingle_Request"
					}
					return "GetAttributeSingle_Response"
				case CIPServiceSetAttributeSingle:
					if pkt.IsRequest {
						return "SetAttributeSingle_Request"
					}
					return "SetAttributeSingle_Response"
				case CIPServiceForwardOpen:
					if pkt.IsRequest {
						return "ForwardOpen_Request"
					}
					return "ForwardOpen_Response"
				case CIPServiceForwardClose:
					if pkt.IsRequest {
						return "ForwardClose_Request"
					}
					return "ForwardClose_Response"
				}
			}
		}
		return ""
	case 0x0070: // SendUnitData
		if pkt.IsRequest {
			return "SendUnitData_Request"
		}
		return "SendUnitData_Response"
	case 0x0063: // ListIdentity
		return "ListIdentity_Request"
	default:
		return ""
	}
}

// PopulateReferenceLibraryFromPCAP populates the reference library from a PCAP file
func PopulateReferenceLibraryFromPCAP(pcapFile string, source string) error {
	refPackets, err := FindReferencePackets(pcapFile)
	if err != nil {
		return fmt.Errorf("find reference packets: %w", err)
	}

	// Update ReferencePackets map
	for key, pkt := range refPackets {
		// Normalize packet (remove session-specific fields for comparison)
		normalized := normalizePacket(pkt.FullPacket)

		ReferencePackets[key] = ReferencePacket{
			Name:        key,
			Description: pkt.Description,
			Data:        normalized,
			Source:      source,
		}
	}

	return nil
}

// normalizePacket normalizes a packet by zeroing out session-specific fields
// This allows comparison across different sessions
func normalizePacket(packet []byte) []byte {
	if len(packet) < 24 {
		return packet
	}

	normalized := make([]byte, len(packet))
	copy(normalized, packet)

	// Zero out session ID (bytes 4-7)
	for i := 4; i < 8; i++ {
		normalized[i] = 0
	}

	// Zero out sender context (bytes 12-19) - keep structure but normalize
	// Actually, keep sender context as-is for now, as it's part of the protocol

	return normalized
}

// WriteReferencePacketsToFile writes reference packets to a Go source file
func WriteReferencePacketsToFile(w io.Writer) error {
	fmt.Fprintf(w, "// Code generated by pcap extraction tool. DO NOT EDIT.\n\n")
	fmt.Fprintf(w, "package cipclient\n\n")
	fmt.Fprintf(w, "func init() {\n")
	fmt.Fprintf(w, "\t// Populate reference packets from PCAP files\n")

	for key, ref := range ReferencePackets {
		if len(ref.Data) == 0 {
			continue
		}
		fmt.Fprintf(w, "\tReferencePackets[%q] = ReferencePacket{\n", key)
		fmt.Fprintf(w, "\t\tName:        %q,\n", ref.Name)
		fmt.Fprintf(w, "\t\tDescription: %q,\n", ref.Description)
		fmt.Fprintf(w, "\t\tSource:      %q,\n", ref.Source)
		fmt.Fprintf(w, "\t\tData:        []byte{\n")

		// Write bytes in chunks of 16
		for i := 0; i < len(ref.Data); i += 16 {
			fmt.Fprintf(w, "\t\t\t")
			for j := 0; j < 16 && i+j < len(ref.Data); j++ {
				if j > 0 {
					fmt.Fprintf(w, ", ")
				}
				fmt.Fprintf(w, "0x%02X", ref.Data[i+j])
			}
			fmt.Fprintf(w, ",\n")
		}
		fmt.Fprintf(w, "\t\t},\n")
		fmt.Fprintf(w, "\t}\n\n")
	}

	fmt.Fprintf(w, "}\n")
	return nil
}
