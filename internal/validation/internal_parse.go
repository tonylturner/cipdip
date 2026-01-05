package validation

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/tturner/cipdip/internal/cipclient"
)

// InternalPacketInfo captures minimal internal parsing hints for a frame.
type InternalPacketInfo struct {
	HasENIP     bool
	HasCIP      bool
	ENIPCommand uint16
	ENIPSession uint32
	CPFItemCount int
	CPFItems     []CPFItem
	CIPData     []byte
	CIPType     string
	Layers      []string
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Transport   string
	CIPService  uint8
	CIPIsResponse bool
	CIPStatusPresent bool
}

// ParseInternalPCAP extracts basic ENIP/CIP payload data from a PCAP.
// This is a best-effort pass intended for synthetic validation PCAPs.
func ParseInternalPCAP(pcapFile string) ([]InternalPacketInfo, error) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil, fmt.Errorf("open pcap file: %w", err)
	}
	defer handle.Close()

	results := []InternalPacketInfo{}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		info := InternalPacketInfo{}
		var payload []byte

		if packet.Layer(layers.LayerTypeEthernet) != nil {
			info.Layers = append(info.Layers, "eth")
		}
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			info.Layers = append(info.Layers, "ip")
			if ip, ok := ipLayer.(*layers.IPv4); ok {
				info.SrcIP = ip.SrcIP.String()
				info.DstIP = ip.DstIP.String()
			}
		} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
			info.Layers = append(info.Layers, "ip")
			if ip, ok := ipLayer.(*layers.IPv6); ok {
				info.SrcIP = ip.SrcIP.String()
				info.DstIP = ip.DstIP.String()
			}
		}

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			if tcp, ok := tcpLayer.(*layers.TCP); ok {
				info.Layers = append(info.Layers, "tcp")
				info.Transport = "tcp"
				info.SrcPort = uint16(tcp.SrcPort)
				info.DstPort = uint16(tcp.DstPort)
				payload = tcp.Payload
			}
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			if udp, ok := udpLayer.(*layers.UDP); ok {
				info.Layers = append(info.Layers, "udp")
				info.Transport = "udp"
				info.SrcPort = uint16(udp.SrcPort)
				info.DstPort = uint16(udp.DstPort)
				payload = udp.Payload
			}
		}

		if len(payload) >= 24 {
			encap, err := cipclient.DecodeENIP(payload)
			if err == nil {
				info.HasENIP = true
				info.ENIPCommand = encap.Command
				info.ENIPSession = encap.SessionID
				info.Layers = append(info.Layers, "enip")
				if (encap.Command == cipclient.ENIPCommandSendRRData || encap.Command == cipclient.ENIPCommandSendUnitData) && len(encap.Data) >= 6 {
					if items, err := cipclient.ParseCPFItems(encap.Data[6:]); err == nil {
						info.CPFItemCount = len(items)
						info.CPFItems = make([]CPFItem, 0, len(items))
						for _, item := range items {
							info.CPFItems = append(info.CPFItems, CPFItem{
								TypeID: fmt.Sprintf("0x%04x", item.TypeID),
								Length: len(item.Data),
							})
						}
					}
				}
				cipData, _, dataType := cipclient.ExtractCIPFromENIPPacket(cipclient.ENIPPacket{Data: encap.Data})
				if len(cipData) > 0 {
					info.HasCIP = true
					info.CIPData = cipData
					info.CIPType = dataType
					info.Layers = append(info.Layers, "cip")
					info.CIPService = cipData[0]
					info.CIPIsResponse = (cipData[0] & 0x80) != 0
					if info.CIPIsResponse {
						if _, err := cipclient.DecodeCIPResponse(cipData, cipclient.CIPPath{}); err == nil {
							info.CIPStatusPresent = true
						}
					}
				}
			}
		}

		results = append(results, info)
	}

	return results, nil
}

// ValidatePCAPInternalOnly builds ValidateResult entries using internal parsing only.
func ValidatePCAPInternalOnly(pcapFile string) ([]ValidateResult, error) {
	internal, err := ParseInternalPCAP(pcapFile)
	if err != nil {
		return nil, err
	}
	results := make([]ValidateResult, 0, len(internal))
	for i := range internal {
		info := internal[i]
		result := ValidateResult{
			Valid:    true,
			Fields:   make(map[string]string),
			Layers:   append([]string(nil), info.Layers...),
			Internal: &internal[i],
		}
		results = append(results, result)
	}
	return results, nil
}
