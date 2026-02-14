package pcap

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
	"github.com/tonylturner/cipdip/internal/enip"
)

// ExtractENIPFromPCAP extracts ENIP packets from a PCAP file.
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

// ENIPPacket represents an extracted ENIP packet from a PCAP.
type ENIPPacket struct {
	Command     uint16
	SessionID   uint32
	Data        []byte
	FullPacket  []byte // Full ENIP packet (24-byte header + data).
	IsRequest   bool   // true if request, false if response.
	Description string // Description of the packet.
	Timestamp   time.Time
	Transport   string
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
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
		switch command {
		case 0x0065:
			isRequest = (status == 0 && sessionID == 0)
		case enip.ENIPCommandListIdentity:
			isRequest = isToServer
		default:
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

// generatePacketDescription generates a human-readable description of the packet.
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

	// Try to identify CIP service if it's SendRRData/SendUnitData.
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

// getCIPServiceName returns the name of a CIP service code.
func getCIPServiceName(code uint8) string {
	name := spec.ServiceName(protocol.CIPServiceCode(code))
	if spec.IsUnknownServiceLabel(name) {
		return ""
	}
	return name
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
