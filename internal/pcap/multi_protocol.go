package pcap

// Multi-protocol PCAP dispatcher: routes TCP/UDP packets to the appropriate
// protocol extractor based on port number.
//
// Supported protocols:
//   - ENIP (ports 44818, 2222): existing ExtractENIPFromPCAP
//   - Modbus TCP (port 502): ExtractModbusFromPCAP
//   - DH+ (best-effort heuristic on unknown ports)

import (
	"fmt"
	"sort"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/tonylturner/cipdip/internal/dhplus"
	"github.com/tonylturner/cipdip/internal/modbus"
)

// ProtocolMessage is a unified representation of a protocol message
// from any supported protocol, for multi-protocol timeline analysis.
type ProtocolMessage struct {
	Protocol    ProtocolHint
	Timestamp   time.Time
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Transport   string // "tcp" or "udp"
	IsRequest   bool
	Description string
	RawData     []byte

	// Protocol-specific payloads (at most one is set).
	ENIP   *ENIPPacket
	Modbus *ModbusPacket
	DHPlus *dhplus.Frame
}

// MultiProtocolResult holds the results of multi-protocol PCAP extraction.
type MultiProtocolResult struct {
	Messages     []ProtocolMessage // Sorted by timestamp
	ENIPCount    int
	ModbusCount  int
	DHPlusCount  int
	UnknownCount int
	TotalPackets int
	PortSummary  map[uint16]int // packets per destination port
}

// ExtractMultiProtocol extracts all supported protocols from a PCAP file
// and returns a unified, time-ordered message stream.
func ExtractMultiProtocol(pcapFile string) (*MultiProtocolResult, error) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil, fmt.Errorf("open pcap file: %w", err)
	}
	defer handle.Close()

	result := &MultiProtocolResult{
		PortSummary: make(map[uint16]int),
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Per-protocol TCP stream reassembly buffers.
	enipStreams := make(map[string][]byte)
	modbusStreams := make(map[string][]byte)
	dhplusDetector := dhplus.NewDetector()

	for packet := range packetSource.Packets() {
		result.TotalPackets++
		meta := extractPacketMeta(packet)

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			srcPort := uint16(tcp.SrcPort)
			dstPort := uint16(tcp.DstPort)

			if len(tcp.Payload) == 0 {
				continue
			}

			result.PortSummary[dstPort]++
			netLayer := packet.NetworkLayer()
			key := streamKey(netLayer, tcp)

			if meta != nil {
				meta.Transport = "tcp"
				meta.SrcPort = srcPort
				meta.DstPort = dstPort
			}

			// Route by port.
			switch {
			case isENIPPort(srcPort, dstPort):
				enipStreams[key] = append(enipStreams[key], tcp.Payload...)
				isToServer := dstPort == 44818 || dstPort == 2222
				parsed, remaining := extractENIPFrames(enipStreams[key], isToServer, meta)
				for i := range parsed {
					p := parsed[i]
					result.Messages = append(result.Messages, ProtocolMessage{
						Protocol:    ProtocolENIP,
						Timestamp:   p.Timestamp,
						SrcIP:       p.SrcIP,
						DstIP:       p.DstIP,
						SrcPort:     p.SrcPort,
						DstPort:     p.DstPort,
						Transport:   p.Transport,
						IsRequest:   p.IsRequest,
						Description: p.Description,
						RawData:     p.FullPacket,
						ENIP:        &parsed[i],
					})
					result.ENIPCount++
				}
				enipStreams[key] = remaining

			case isModbusPort(srcPort, dstPort):
				modbusStreams[key] = append(modbusStreams[key], tcp.Payload...)
				isToServer := dstPort == ModbusPort
				parsed, remaining := extractModbusFrames(modbusStreams[key], isToServer, meta)
				for i := range parsed {
					p := parsed[i]
					result.Messages = append(result.Messages, ProtocolMessage{
						Protocol:    ProtocolModbus,
						Timestamp:   p.Timestamp,
						SrcIP:       p.SrcIP,
						DstIP:       p.DstIP,
						SrcPort:     p.SrcPort,
						DstPort:     p.DstPort,
						Transport:   p.Transport,
						IsRequest:   p.IsRequest,
						Description: p.Description,
						RawData:     p.FullFrame,
						Modbus:      &parsed[i],
					})
					result.ModbusCount++
				}
				modbusStreams[key] = remaining

			default:
				// Best-effort DH+ detection on unknown ports.
				det := dhplusDetector.Analyze(tcp.Payload)
				if det.Confidence >= 0.5 {
					frame, fErr := dhplus.DecodeFrame(tcp.Payload)
					if fErr == nil {
						result.Messages = append(result.Messages, ProtocolMessage{
							Protocol:    ProtocolDHPlus,
							Timestamp:   metadataValue(meta, func(m *ENIPMetadata) time.Time { return m.Timestamp }),
							SrcIP:       metadataValue(meta, func(m *ENIPMetadata) string { return m.SrcIP }),
							DstIP:       metadataValue(meta, func(m *ENIPMetadata) string { return m.DstIP }),
							SrcPort:     srcPort,
							DstPort:     dstPort,
							Transport:   "tcp",
							Description: fmt.Sprintf("DH+ %s (node %d→%d)", frame.Command.String(), frame.Src, frame.Dst),
							RawData:     tcp.Payload,
							DHPlus:      &frame,
						})
						result.DHPlusCount++
					}
				} else {
					result.UnknownCount++
				}
			}
			continue
		}

		// UDP handling
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			srcPort := uint16(udp.SrcPort)
			dstPort := uint16(udp.DstPort)

			if len(udp.Payload) == 0 {
				continue
			}

			result.PortSummary[dstPort]++

			if meta != nil {
				meta.Transport = "udp"
				meta.SrcPort = srcPort
				meta.DstPort = dstPort
			}

			switch {
			case isENIPPort(srcPort, dstPort):
				isToServer := dstPort == 44818 || dstPort == 2222
				parsed, _ := extractENIPFrames(udp.Payload, isToServer, meta)
				for i := range parsed {
					p := parsed[i]
					result.Messages = append(result.Messages, ProtocolMessage{
						Protocol:    ProtocolENIP,
						Timestamp:   p.Timestamp,
						SrcIP:       p.SrcIP,
						DstIP:       p.DstIP,
						SrcPort:     p.SrcPort,
						DstPort:     p.DstPort,
						Transport:   p.Transport,
						IsRequest:   p.IsRequest,
						Description: p.Description,
						RawData:     p.FullPacket,
						ENIP:        &parsed[i],
					})
					result.ENIPCount++
				}

			case isModbusPort(srcPort, dstPort):
				isToServer := dstPort == ModbusPort
				parsed, _ := extractModbusFrames(udp.Payload, isToServer, meta)
				for i := range parsed {
					p := parsed[i]
					result.Messages = append(result.Messages, ProtocolMessage{
						Protocol:    ProtocolModbus,
						Timestamp:   p.Timestamp,
						SrcIP:       p.SrcIP,
						DstIP:       p.DstIP,
						SrcPort:     p.SrcPort,
						DstPort:     p.DstPort,
						Transport:   p.Transport,
						IsRequest:   p.IsRequest,
						Description: p.Description,
						RawData:     p.FullFrame,
						Modbus:      &parsed[i],
					})
					result.ModbusCount++
				}

			default:
				result.UnknownCount++
			}
		}
	}

	// Sort messages by timestamp.
	sort.Slice(result.Messages, func(i, j int) bool {
		return result.Messages[i].Timestamp.Before(result.Messages[j].Timestamp)
	})

	return result, nil
}

// ProtocolSummary returns a human-readable summary of detected protocols.
func (r *MultiProtocolResult) ProtocolSummary() string {
	return fmt.Sprintf("ENIP: %d, Modbus: %d, DH+: %d, Unknown: %d (total packets: %d)",
		r.ENIPCount, r.ModbusCount, r.DHPlusCount, r.UnknownCount, r.TotalPackets)
}

// HasProtocol returns true if the result contains messages of the given protocol.
func (r *MultiProtocolResult) HasProtocol(proto ProtocolHint) bool {
	switch proto {
	case ProtocolENIP:
		return r.ENIPCount > 0
	case ProtocolModbus:
		return r.ModbusCount > 0
	case ProtocolDHPlus:
		return r.DHPlusCount > 0
	default:
		return false
	}
}

// FilterByProtocol returns only messages of the specified protocol.
func (r *MultiProtocolResult) FilterByProtocol(proto ProtocolHint) []ProtocolMessage {
	var filtered []ProtocolMessage
	for _, msg := range r.Messages {
		if msg.Protocol == proto {
			filtered = append(filtered, msg)
		}
	}
	return filtered
}

// ModbusFunctionDistribution returns a frequency map of Modbus function codes.
func (r *MultiProtocolResult) ModbusFunctionDistribution() map[modbus.FunctionCode]int {
	dist := make(map[modbus.FunctionCode]int)
	for _, msg := range r.Messages {
		if msg.Modbus != nil {
			fc := msg.Modbus.Function & 0x7F // strip exception bit
			dist[fc]++
		}
	}
	return dist
}
