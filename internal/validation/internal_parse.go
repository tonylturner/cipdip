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
	CIPData     []byte
	CIPType     string
	Layers      []string
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
		if packet.Layer(layers.LayerTypeIPv4) != nil || packet.Layer(layers.LayerTypeIPv6) != nil {
			info.Layers = append(info.Layers, "ip")
		}

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			if tcp, ok := tcpLayer.(*layers.TCP); ok {
				info.Layers = append(info.Layers, "tcp")
				payload = tcp.Payload
			}
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			if udp, ok := udpLayer.(*layers.UDP); ok {
				info.Layers = append(info.Layers, "udp")
				payload = udp.Payload
			}
		}

		if len(payload) >= 24 {
			encap, err := cipclient.DecodeENIP(payload)
			if err == nil {
				info.HasENIP = true
				info.ENIPCommand = encap.Command
				info.Layers = append(info.Layers, "enip")
				cipData, _, dataType := cipclient.ExtractCIPFromENIPPacket(cipclient.ENIPPacket{Data: encap.Data})
				if len(cipData) > 0 {
					info.HasCIP = true
					info.CIPData = cipData
					info.CIPType = dataType
					info.Layers = append(info.Layers, "cip")
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
