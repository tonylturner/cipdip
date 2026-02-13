package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
	"github.com/tonylturner/cipdip/internal/enip"
)

// findTshark looks for tshark in common locations.
func findTshark() string {
	paths := []string{
		"tshark",
		"/usr/bin/tshark",
		"/usr/local/bin/tshark",
		"/opt/homebrew/bin/tshark",
		"/Applications/Wireshark.app/Contents/MacOS/tshark",
	}
	for _, p := range paths {
		if path, err := exec.LookPath(p); err == nil {
			return path
		}
	}
	return ""
}

// countTsharkFilter counts packets matching a display filter.
func countTsharkFilter(tsharkPath, pcapFile, filter string) (int, error) {
	cmd := exec.Command(tsharkPath, "-r", pcapFile, "-Y", filter)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return 0, err
	}
	// Count lines in output (each line = one packet)
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return 0, nil
	}
	return len(lines), nil
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

	// TCP-level metrics (populated via tshark if available)
	TCPRetransmits   int
	TCPResets        int
	TCPLostSegments  int
	CIPErrorResponses int
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

	// Enhance with TCP-level metrics if tshark is available
	summary.EnhanceWithTCPMetrics(pcapFile)

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
		// ListIdentity item data layout (Identity Item).
		// Encapsulation version (2), SocketAddr (16), VendorID (2), DeviceType (2),
		// ProductCode (2), Revision (2), Status (2), Serial (4), NameLen (1), Name (N).
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

// EnhanceWithTCPMetrics populates TCP-level metrics using tshark if available.
// This is optional - if tshark isn't found, metrics remain at 0.
func (s *PCAPSummary) EnhanceWithTCPMetrics(pcapFile string) {
	tsharkPath := findTshark()
	if tsharkPath == "" {
		return
	}

	// Count TCP retransmissions
	if count, err := countTsharkFilter(tsharkPath, pcapFile, "tcp.analysis.retransmission"); err == nil {
		s.TCPRetransmits = count
	}

	// Count TCP resets
	if count, err := countTsharkFilter(tsharkPath, pcapFile, "tcp.flags.reset==1"); err == nil {
		s.TCPResets = count
	}

	// Count TCP lost segments
	if count, err := countTsharkFilter(tsharkPath, pcapFile, "tcp.analysis.lost_segment"); err == nil {
		s.TCPLostSegments = count
	}

	// Count CIP error responses (non-zero status)
	if count, err := countTsharkFilter(tsharkPath, pcapFile, "cip.genstat != 0"); err == nil {
		s.CIPErrorResponses = count
	}
}
