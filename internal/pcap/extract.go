package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
	legacy "github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/enip"
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
	streams := make(map[string][]byte)

	for packet := range packetSource.Packets() {
		meta := extractPacketMeta(packet)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if !isENIPPort(uint16(tcp.SrcPort), uint16(tcp.DstPort)) {
				continue
			}
			if len(tcp.Payload) == 0 {
				continue
			}
			netLayer := packet.NetworkLayer()
			key := streamKey(netLayer, tcp)
			streams[key] = append(streams[key], tcp.Payload...)
			streamBuf := streams[key]
			meta.Transport = "tcp"
			meta.SrcPort = uint16(tcp.SrcPort)
			meta.DstPort = uint16(tcp.DstPort)
			parsed, remaining := extractENIPFrames(streamBuf, tcp.DstPort == 44818 || tcp.DstPort == 2222, meta)
			if len(parsed) > 0 {
				packets = append(packets, parsed...)
			}
			streams[key] = remaining
			continue
		}

		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			if !isENIPPort(uint16(udp.SrcPort), uint16(udp.DstPort)) {
				continue
			}
			if len(udp.Payload) == 0 {
				continue
			}
			meta.Transport = "udp"
			meta.SrcPort = uint16(udp.SrcPort)
			meta.DstPort = uint16(udp.DstPort)
			parsed, _ := extractENIPFrames(udp.Payload, udp.DstPort == 44818 || udp.DstPort == 2222, meta)
			if len(parsed) > 0 {
				packets = append(packets, parsed...)
			}
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
	Timestamp   time.Time
	Transport   string
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
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
					meta := extractPacketMeta(packet)
					meta.Transport = "tcp"
					meta.SrcPort = uint16(tcp.SrcPort)
					meta.DstPort = uint16(tcp.DstPort)
					if result := extractENIPFromPayload(payload, tcp.DstPort == 44818, meta); result != nil {
						return result
					}
				}
			}
			// Fall back to TCP payload (for non-reassembled packets)
			if len(tcp.Payload) > 0 {
				meta := extractPacketMeta(packet)
				meta.Transport = "tcp"
				meta.SrcPort = uint16(tcp.SrcPort)
				meta.DstPort = uint16(tcp.DstPort)
				return extractENIPFromPayload(tcp.Payload, tcp.DstPort == 44818, meta)
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
				meta := extractPacketMeta(packet)
				meta.Transport = "udp"
				meta.SrcPort = uint16(udp.SrcPort)
				meta.DstPort = uint16(udp.DstPort)
				return extractENIPFromPayload(udp.Payload, udp.DstPort == 44818 || udp.DstPort == 2222, meta)
			}
		}
	}

	return nil
}

// extractENIPFromPayload extracts ENIP data from a payload
func extractENIPFromPayload(payload []byte, isToServer bool, meta *ENIPMetadata) *ENIPPacket {
	packets, _ := extractENIPFrames(payload, isToServer, meta)
	if len(packets) == 0 {
		return nil
	}
	return &packets[0]
}

type ENIPMetadata struct {
	Timestamp time.Time
	Transport string
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
}

func extractENIPFrames(payload []byte, isToServer bool, meta *ENIPMetadata) ([]ENIPPacket, []byte) {
	var packets []ENIPPacket
	offset := 0
	for offset+24 <= len(payload) {
		command, length, ok, order := decodeENIPHeader(payload[offset:])
		if !ok {
			offset++
			continue
		}
		total := 24 + int(length)
		if offset+total > len(payload) {
			break
		}

		fullPacket := make([]byte, total)
		copy(fullPacket, payload[offset:offset+total])

		var data []byte
		if length > 0 {
			data = make([]byte, length)
			copy(data, payload[offset+24:offset+total])
		}

		sessionID := order.Uint32(payload[offset+4 : offset+8])
		status := order.Uint32(payload[offset+8 : offset+12])

		var isRequest bool
		if command == 0x0065 {
			isRequest = (status == 0 && sessionID == 0)
		} else if command == enip.ENIPCommandListIdentity {
			isRequest = isToServer
		} else {
			isRequest = (status == 0)
		}
		if command == enip.ENIPCommandSendRRData || command == enip.ENIPCommandSendUnitData {
			cipData, _, dataType := extractCIPFromENIP(ENIPPacket{Data: data})
			if dataType == "unconnected" && len(cipData) > 0 && cipData[0]&0x80 != 0 {
				isRequest = false
			}
		}

		description := generatePacketDescription(command, isRequest, data)
		packets = append(packets, ENIPPacket{
			Command:     command,
			SessionID:   sessionID,
			Data:        data,
			FullPacket:  fullPacket,
			IsRequest:   isRequest,
			Description: description,
			Timestamp:   metadataValue(meta, func(m *ENIPMetadata) time.Time { return m.Timestamp }),
			Transport:   metadataValue(meta, func(m *ENIPMetadata) string { return m.Transport }),
			SrcIP:       metadataValue(meta, func(m *ENIPMetadata) string { return m.SrcIP }),
			DstIP:       metadataValue(meta, func(m *ENIPMetadata) string { return m.DstIP }),
			SrcPort:     metadataValue(meta, func(m *ENIPMetadata) uint16 { return m.SrcPort }),
			DstPort:     metadataValue(meta, func(m *ENIPMetadata) uint16 { return m.DstPort }),
		})

		offset += total
	}

	if offset >= len(payload) {
		return packets, nil
	}
	remaining := make([]byte, len(payload)-offset)
	copy(remaining, payload[offset:])
	return packets, remaining
}

func decodeENIPHeader(payload []byte) (uint16, uint16, bool, binary.ByteOrder) {
	if len(payload) < 24 {
		return 0, 0, false, binary.LittleEndian
	}
	orders := []binary.ByteOrder{binary.LittleEndian, binary.BigEndian}
	for _, order := range orders {
		command := order.Uint16(payload[0:2])
		if !isValidENIPCommand(command) {
			continue
		}
		length := order.Uint16(payload[2:4])
		if len(payload) < 24+int(length) {
			continue
		}
		return command, length, true, order
	}
	return 0, 0, false, binary.LittleEndian
}

func isENIPPort(src, dst uint16) bool {
	return src == 44818 || dst == 44818 || src == 2222 || dst == 2222
}

func streamKey(netLayer gopacket.NetworkLayer, tcp *layers.TCP) string {
	if netLayer != nil {
		src, dst := netLayer.NetworkFlow().Endpoints()
		return fmt.Sprintf("%s:%d->%s:%d", src, tcp.SrcPort, dst, tcp.DstPort)
	}
	return fmt.Sprintf("unknown:%d->unknown:%d", tcp.SrcPort, tcp.DstPort)
}

func extractPacketMeta(packet gopacket.Packet) *ENIPMetadata {
	meta := &ENIPMetadata{}
	if packet.Metadata() != nil {
		meta.Timestamp = packet.Metadata().Timestamp
	}
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return meta
	}
	src, dst := netLayer.NetworkFlow().Endpoints()
	meta.SrcIP = src.String()
	meta.DstIP = dst.String()
	return meta
}

func metadataValue[T any](meta *ENIPMetadata, getter func(*ENIPMetadata) T) T {
	if meta == nil {
		var zero T
		return zero
	}
	return getter(meta)
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

	// Try to identify CIP service if it's SendRRData/SendUnitData
	if (command == 0x006F || command == 0x0070) && len(data) >= 6 {
		cipData, _, _ := extractCIPFromENIP(ENIPPacket{Data: data})
		if len(cipData) > 0 {
			serviceCode := cipData[0] &^ 0x80
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
	name := spec.ServiceName(protocol.CIPServiceCode(code))
	if spec.IsUnknownServiceLabel(name) {
		return ""
	}
	return name
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
	if !isLittleEndianENIP(pkt.FullPacket) {
		return ""
	}
	switch pkt.Command {
	case 0x0065: // RegisterSession
		if pkt.IsRequest {
			return "RegisterSession_Request"
		}
		return "RegisterSession_Response"
	case 0x006F: // SendRRData
		if len(pkt.Data) >= 6 {
			cipData, _, _ := extractCIPFromENIP(pkt)
			if len(cipData) > 0 {
				serviceCode := cipData[0] &^ 0x80
				isResponse := cipData[0]&0x80 != 0
				switch protocol.CIPServiceCode(serviceCode) {
				case spec.CIPServiceGetAttributeSingle:
					if isResponse {
						return "GetAttributeSingle_Response"
					}
					return "GetAttributeSingle_Request"
				case spec.CIPServiceSetAttributeSingle:
					if isResponse {
						return "SetAttributeSingle_Response"
					}
					return "SetAttributeSingle_Request"
				case spec.CIPServiceForwardOpen:
					if isResponse {
						return "ForwardOpen_Response"
					}
					return "ForwardOpen_Request"
				case spec.CIPServiceForwardClose:
					if isResponse {
						return "ForwardClose_Response"
					}
					return "ForwardClose_Request"
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

func isLittleEndianENIP(packet []byte) bool {
	if len(packet) < 24 {
		return false
	}
	command := binary.LittleEndian.Uint16(packet[0:2])
	if !isValidENIPCommand(command) {
		return false
	}
	length := binary.LittleEndian.Uint16(packet[2:4])
	return len(packet) >= 24+int(length)
}

func isValidENIPCommand(cmd uint16) bool {
	switch cmd {
	case enip.ENIPCommandRegisterSession,
		enip.ENIPCommandUnregisterSession,
		enip.ENIPCommandSendRRData,
		enip.ENIPCommandSendUnitData,
		enip.ENIPCommandListIdentity,
		enip.ENIPCommandListServices,
		enip.ENIPCommandListInterfaces:
		return true
	default:
		return false
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

		legacy.ReferencePackets[key] = legacy.ReferencePacket{
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

	for key, ref := range legacy.ReferencePackets {
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

// PCAPSummary provides high-level stats for ENIP traffic.
type PCAPSummary struct {
	TotalPackets            int
	ENIPPackets             int
	Requests                int
	Responses               int
	Commands                map[string]int
	CIPServices             map[string]int
	EmbeddedServices        map[string]int
	EmbeddedUnknown         map[uint8]*CIPUnknownStats
	RequestValidationErrors map[string]int
	RequestValidationTotal  int
	RequestValidationFailed int
	CIPRequests             int
	CIPResponses            int
	IOPayloads              int
	CIPPayloads             int
	CPFUsed                 int
	CPFMissing              int
	EPATH16Class            int
	EPATH16Instance         int
	EPATH16Attribute        int
	PathSizeUsed            int
	PathSizeMissing         int
	TopPaths                []string
	UnknownServices         map[uint8]*CIPUnknownStats
	UnknownPairs            map[string]int
	VendorID                uint16
	ProductName             string
}

// CIPUnknownStats captures metadata for unknown CIP services.
type CIPUnknownStats struct {
	Count           int
	ResponseCount   int
	StatusCounts    map[uint8]int
	ClassCounts     map[uint16]int
	InstanceCounts  map[uint16]int
	AttributeCounts map[uint16]int
}

// SummarizeENIPFromPCAP summarizes ENIP/CIP traffic from a PCAP.
func SummarizeENIPFromPCAP(pcapFile string) (*PCAPSummary, error) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil, fmt.Errorf("open pcap file: %w", err)
	}
	defer handle.Close()

	summary := &PCAPSummary{
		Commands:                make(map[string]int),
		CIPServices:             make(map[string]int),
		EmbeddedServices:        make(map[string]int),
		EmbeddedUnknown:         make(map[uint8]*CIPUnknownStats),
		UnknownServices:         make(map[uint8]*CIPUnknownStats),
		UnknownPairs:            make(map[string]int),
		RequestValidationErrors: make(map[string]int),
	}
	pathCounts := make(map[string]int)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	streams := make(map[string][]byte)
	validator := client.NewPacketValidator(true)

	for packet := range packetSource.Packets() {
		summary.TotalPackets++
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if !isENIPPort(uint16(tcp.SrcPort), uint16(tcp.DstPort)) {
				continue
			}
			if len(tcp.Payload) == 0 {
				continue
			}
			netLayer := packet.NetworkLayer()
			key := streamKey(netLayer, tcp)
			streams[key] = append(streams[key], tcp.Payload...)
			meta := extractPacketMeta(packet)
			meta.Transport = "tcp"
			meta.SrcPort = uint16(tcp.SrcPort)
			meta.DstPort = uint16(tcp.DstPort)
			parsed, remaining := extractENIPFrames(streams[key], tcp.DstPort == 44818 || tcp.DstPort == 2222, meta)
			streams[key] = remaining
			summarizePackets(parsed, summary, pathCounts, validator)
			if summary.ProductName == "" {
				updateVendorInfo(parsed, summary)
			}
			continue
		}

		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			if !isENIPPort(uint16(udp.SrcPort), uint16(udp.DstPort)) {
				continue
			}
			if len(udp.Payload) == 0 {
				continue
			}
			meta := extractPacketMeta(packet)
			meta.Transport = "udp"
			meta.SrcPort = uint16(udp.SrcPort)
			meta.DstPort = uint16(udp.DstPort)
			parsed, _ := extractENIPFrames(udp.Payload, udp.DstPort == 44818 || udp.DstPort == 2222, meta)
			summarizePackets(parsed, summary, pathCounts, validator)
			if summary.ProductName == "" {
				updateVendorInfo(parsed, summary)
			}
		}
	}

	summary.TopPaths = topPaths(pathCounts, 10)
	return summary, nil
}

func updateVendorInfo(packets []ENIPPacket, summary *PCAPSummary) {
	for _, pkt := range packets {
		if pkt.Command != enip.ENIPCommandListIdentity || len(pkt.Data) == 0 {
			continue
		}
		if pkt.IsRequest {
			continue
		}
		if vendorID, productName, ok := parseListIdentityIdentityItem(pkt.Data); ok {
			summary.VendorID = vendorID
			summary.ProductName = productName
			return
		}
	}
}

func parseListIdentityIdentityItem(data []byte) (uint16, string, bool) {
	if len(data) < 2 {
		return 0, "", false
	}
	count := int(binary.LittleEndian.Uint16(data[0:2]))
	offset := 2
	for i := 0; i < count; i++ {
		if len(data) < offset+2 {
			return 0, "", false
		}
		itemType := binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
		if len(data) < offset+2 {
			return 0, "", false
		}
		itemLength := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if len(data) < offset+itemLength {
			return 0, "", false
		}
		itemData := data[offset : offset+itemLength]
		offset += itemLength
		if itemType != 0x000C {
			continue
		}
		// ListIdentity item data layout (Identity Item)
		// Encapsulation version (2), SocketAddr (16), VendorID (2), DeviceType (2),
		// ProductCode (2), Revision (2), Status (2), Serial (4), NameLen (1), Name (N)
		if len(itemData) < 16+2+2+2+2+2+4+1 {
			return 0, "", false
		}
		pos := 2 + 16
		vendorID := binary.LittleEndian.Uint16(itemData[pos : pos+2])
		pos += 2
		pos += 2 // device type
		pos += 2 // product code
		pos += 2 // revision
		pos += 2 // status
		pos += 4 // serial
		if len(itemData) < pos+1 {
			return vendorID, "", true
		}
		nameLen := int(itemData[pos])
		pos++
		if nameLen == 0 || len(itemData) < pos+nameLen {
			return vendorID, "", true
		}
		productName := string(itemData[pos : pos+nameLen])
		return vendorID, productName, true
	}
	return 0, "", false
}

func summarizePackets(packets []ENIPPacket, summary *PCAPSummary, pathCounts map[string]int, validator *client.PacketValidator) {
	for _, pkt := range packets {
		summary.ENIPPackets++
		if pkt.IsRequest {
			summary.Requests++
		} else {
			summary.Responses++
		}
		summary.Commands[commandName(pkt.Command)]++

		if pkt.Command != enip.ENIPCommandSendRRData && pkt.Command != enip.ENIPCommandSendUnitData {
			continue
		}

		cipData, cpfUsed, dataType := extractCIPFromENIP(pkt)
		if cpfUsed {
			summary.CPFUsed++
		} else {
			summary.CPFMissing++
		}
		if len(cipData) == 0 {
			continue
		}
		if dataType == "connected" {
			summary.IOPayloads++
			continue
		}
		if dataType != "unconnected" {
			continue
		}

		summary.CIPPayloads++
		msgInfo, err := protocol.ParseCIPMessage(cipData)
		if err != nil {
			continue
		}
		if msgInfo.IsResponse {
			summary.CIPResponses++
		} else {
			summary.CIPRequests++
		}

		serviceLabel, _ := spec.LabelService(msgInfo.BaseService, msgInfo.PathInfo.Path, msgInfo.IsResponse)
		summary.CIPServices[serviceLabel]++

		if spec.IsUnknownServiceLabel(serviceLabel) {
			stats := summary.UnknownServices[msgInfo.BaseService]
			if stats == nil {
				stats = &CIPUnknownStats{
					StatusCounts:    make(map[uint8]int),
					ClassCounts:     make(map[uint16]int),
					InstanceCounts:  make(map[uint16]int),
					AttributeCounts: make(map[uint16]int),
				}
				summary.UnknownServices[msgInfo.BaseService] = stats
			}
			stats.Count++
			if msgInfo.IsResponse {
				stats.ResponseCount++
				if msgInfo.GeneralStatus != nil {
					stats.StatusCounts[*msgInfo.GeneralStatus]++
				}
			}
			if msgInfo.PathInfo.Path.Class != 0 {
				stats.ClassCounts[msgInfo.PathInfo.Path.Class]++
				pairKey := fmt.Sprintf("0x%02X/0x%04X", msgInfo.BaseService, msgInfo.PathInfo.Path.Class)
				summary.UnknownPairs[pairKey]++
			}
			if msgInfo.PathInfo.Path.Instance != 0 {
				stats.InstanceCounts[msgInfo.PathInfo.Path.Instance]++
			}
			if msgInfo.PathInfo.Path.Attribute != 0 {
				stats.AttributeCounts[msgInfo.PathInfo.Path.Attribute]++
			}
		}

		if msgInfo.BaseService == 0x52 && msgInfo.PathInfo.Path.Class == spec.CIPClassConnectionManager && msgInfo.PathInfo.Path.Instance == 0x0001 {
			var embedded []byte
			if msgInfo.IsResponse {
				if msgInfo.RequestData != nil {
					embedded, _ = protocol.ParseUnconnectedSendResponsePayload(msgInfo.RequestData)
				}
			} else {
				if msgInfo.DataOffset > 0 && msgInfo.DataOffset <= len(cipData) {
					embedded, _, _ = protocol.ParseUnconnectedSendRequestPayload(cipData[msgInfo.DataOffset:])
				}
			}
			if len(embedded) > 0 {
				embeddedInfo, err := protocol.ParseCIPMessage(embedded)
				if err == nil {
					embeddedLabel, _ := spec.LabelService(embeddedInfo.BaseService, embeddedInfo.PathInfo.Path, embeddedInfo.IsResponse)
					summary.EmbeddedServices[embeddedLabel]++
					if spec.IsUnknownServiceLabel(embeddedLabel) {
						stats := summary.EmbeddedUnknown[embeddedInfo.BaseService]
						if stats == nil {
							stats = &CIPUnknownStats{
								StatusCounts:    make(map[uint8]int),
								ClassCounts:     make(map[uint16]int),
								InstanceCounts:  make(map[uint16]int),
								AttributeCounts: make(map[uint16]int),
							}
							summary.EmbeddedUnknown[embeddedInfo.BaseService] = stats
						}
						stats.Count++
						if embeddedInfo.IsResponse {
							stats.ResponseCount++
							if embeddedInfo.GeneralStatus != nil {
								stats.StatusCounts[*embeddedInfo.GeneralStatus]++
							}
						}
						if embeddedInfo.PathInfo.Path.Class != 0 {
							stats.ClassCounts[embeddedInfo.PathInfo.Path.Class]++
						}
						if embeddedInfo.PathInfo.Path.Instance != 0 {
							stats.InstanceCounts[embeddedInfo.PathInfo.Path.Instance]++
						}
						if embeddedInfo.PathInfo.Path.Attribute != 0 {
							stats.AttributeCounts[embeddedInfo.PathInfo.Path.Attribute]++
						}
					}
				}
			}
		}

		if msgInfo.IsResponse {
			continue
		}

		summary.RequestValidationTotal++
		req, err := protocol.DecodeCIPRequest(cipData)
		if err != nil {
			summary.RequestValidationFailed++
			key := fmt.Sprintf("%s: decode error: %v", serviceLabel, err)
			summary.RequestValidationErrors[key]++
		} else if err := validator.ValidateCIPRequest(req); err != nil {
			summary.RequestValidationFailed++
			key := fmt.Sprintf("%s: %v", serviceLabel, err)
			summary.RequestValidationErrors[key]++
		}

		if msgInfo.UsedPathSize {
			summary.PathSizeUsed++
		} else {
			summary.PathSizeMissing++
		}
		if msgInfo.PathInfo.HasClassSegment {
			pathKey := fmt.Sprintf("0x%04X/0x%04X/0x%04X", msgInfo.PathInfo.Path.Class, msgInfo.PathInfo.Path.Instance, msgInfo.PathInfo.Path.Attribute)
			pathCounts[pathKey]++
			if msgInfo.PathInfo.ClassIs16 {
				summary.EPATH16Class++
			}
			if msgInfo.PathInfo.InstanceIs16 {
				summary.EPATH16Instance++
			}
			if msgInfo.PathInfo.AttributeIs16 {
				summary.EPATH16Attribute++
			}
		}
	}
}

func extractCIPFromENIP(pkt ENIPPacket) ([]byte, bool, string) {
	if len(pkt.Data) < 6 {
		return nil, false, ""
	}
	payload := pkt.Data[6:]
	if len(payload) == 0 {
		return nil, false, ""
	}
	items, err := enip.ParseCPFItems(payload)
	if err != nil {
		return payload, false, "raw"
	}
	for _, item := range items {
		if item.TypeID == enip.CPFItemUnconnectedData || item.TypeID == enip.CPFItemConnectedData {
			dataType := "connected"
			if item.TypeID == enip.CPFItemUnconnectedData {
				dataType = "unconnected"
			}
			return item.Data, true, dataType
		}
	}
	return payload, true, "raw"
}

// ExtractCIPFromENIPPacket returns CIP data from an ENIP packet.
func ExtractCIPFromENIPPacket(pkt ENIPPacket) ([]byte, bool, string) {
	return extractCIPFromENIP(pkt)
}

func extractEPATHFromRequest(cipData []byte) ([]byte, bool) {
	if len(cipData) < 2 {
		return nil, false
	}
	pathSizeWords := int(cipData[1])
	pathBytesLen := pathSizeWords * 2
	if pathBytesLen > 0 && len(cipData) >= 2+pathBytesLen {
		pathBytes := make([]byte, pathBytesLen)
		copy(pathBytes, cipData[2:2+pathBytesLen])
		if looksLikeEPATH(pathBytes) {
			return pathBytes, true
		}
	}

	// Fallback: attempt to parse without path size byte.
	pathBytes := cipData[1:]
	if looksLikeEPATH(pathBytes) {
		return pathBytes, false
	}
	return nil, false
}

func looksLikeEPATH(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	seg := data[0]
	switch seg {
	case 0x20, 0x21, 0x24, 0x25, 0x30, 0x31, 0x00:
	default:
		return false
	}
	_, err := protocol.ParseEPATH(data)
	return err == nil
}

func commandName(command uint16) string {
	switch command {
	case enip.ENIPCommandRegisterSession:
		return "RegisterSession"
	case enip.ENIPCommandUnregisterSession:
		return "UnregisterSession"
	case enip.ENIPCommandSendRRData:
		return "SendRRData"
	case enip.ENIPCommandSendUnitData:
		return "SendUnitData"
	case enip.ENIPCommandListIdentity:
		return "ListIdentity"
	case enip.ENIPCommandListServices:
		return "ListServices"
	case enip.ENIPCommandListInterfaces:
		return "ListInterfaces"
	default:
		return fmt.Sprintf("Unknown(0x%04X)", command)
	}
}

func topPaths(counts map[string]int, max int) []string {
	type kv struct {
		Key   string
		Value int
	}
	list := make([]kv, 0, len(counts))
	for k, v := range counts {
		list = append(list, kv{Key: k, Value: v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Value == list[j].Value {
			return strings.Compare(list[i].Key, list[j].Key) < 0
		}
		return list[i].Value > list[j].Value
	})
	if len(list) > max {
		list = list[:max]
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, fmt.Sprintf("%s (%d)", item.Key, item.Value))
	}
	return out
}
