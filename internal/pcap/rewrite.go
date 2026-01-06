package pcap

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type RewriteOptions struct {
	SrcIP              net.IP
	DstIP              net.IP
	SrcPort            int
	DstPort            int
	SrcMAC             net.HardwareAddr
	DstMAC             net.HardwareAddr
	OnlyENIP           bool
	RecomputeChecksums bool
}

type RewriteStats struct {
	Total     int
	Rewritten int
	Skipped   int
	Errors    int
}

func RewritePCAP(inputPath, outputPath string, opts RewriteOptions) (RewriteStats, error) {
	handle, err := pcap.OpenOffline(inputPath)
	if err != nil {
		return RewriteStats{}, fmt.Errorf("open pcap: %w", err)
	}
	defer handle.Close()

	out, err := os.Create(outputPath)
	if err != nil {
		return RewriteStats{}, fmt.Errorf("create output: %w", err)
	}
	defer out.Close()

	writer := pcapgo.NewWriter(out)
	if err := writer.WriteFileHeader(65535, handle.LinkType()); err != nil {
		return RewriteStats{}, fmt.Errorf("write pcap header: %w", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	stats := RewriteStats{}

	for packet := range packetSource.Packets() {
		if packet == nil {
			continue
		}
		stats.Total++
		if !ShouldRewrite(packet, opts.OnlyENIP) {
			stats.Skipped++
			if err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				return stats, fmt.Errorf("write packet: %w", err)
			}
			continue
		}

		data, err := RewritePacket(packet, opts)
		if err != nil {
			stats.Errors++
			if err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				return stats, fmt.Errorf("write packet: %w", err)
			}
			continue
		}
		stats.Rewritten++

		ci := packet.Metadata().CaptureInfo
		if ci.Timestamp.IsZero() {
			ci.Timestamp = time.Now()
		}
		ci.CaptureLength = len(data)
		ci.Length = len(data)
		if err := writer.WritePacket(ci, data); err != nil {
			return stats, fmt.Errorf("write packet: %w", err)
		}
	}

	return stats, nil
}

func ShouldRewrite(packet gopacket.Packet, onlyENIP bool) bool {
	if !onlyENIP {
		return true
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp != nil && (tcp.SrcPort == 44818 || tcp.DstPort == 44818 || tcp.SrcPort == 2222 || tcp.DstPort == 2222) {
			return true
		}
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if udp != nil && (udp.SrcPort == 44818 || udp.DstPort == 44818 || udp.SrcPort == 2222 || udp.DstPort == 2222) {
			return true
		}
	}
	return false
}

func RewritePacket(packet gopacket.Packet, opts RewriteOptions) ([]byte, error) {
	var layersOut []gopacket.SerializableLayer

	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := *(ethLayer.(*layers.Ethernet))
		if len(opts.SrcMAC) > 0 {
			eth.SrcMAC = opts.SrcMAC
		}
		if len(opts.DstMAC) > 0 {
			eth.DstMAC = opts.DstMAC
		}
		layersOut = append(layersOut, &eth)
	}

	if vlanLayer := packet.Layer(layers.LayerTypeDot1Q); vlanLayer != nil {
		vlan := *(vlanLayer.(*layers.Dot1Q))
		layersOut = append(layersOut, &vlan)
	}

	var networkLayer gopacket.NetworkLayer

	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4 := *(ip4Layer.(*layers.IPv4))
		if opts.SrcIP != nil && opts.SrcIP.To4() != nil {
			ip4.SrcIP = opts.SrcIP.To4()
		}
		if opts.DstIP != nil && opts.DstIP.To4() != nil {
			ip4.DstIP = opts.DstIP.To4()
		}
		networkLayer = &ip4
		layersOut = append(layersOut, &ip4)
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6 := *(ip6Layer.(*layers.IPv6))
		if opts.SrcIP != nil && opts.SrcIP.To16() != nil {
			ip6.SrcIP = opts.SrcIP.To16()
		}
		if opts.DstIP != nil && opts.DstIP.To16() != nil {
			ip6.DstIP = opts.DstIP.To16()
		}
		networkLayer = &ip6
		layersOut = append(layersOut, &ip6)
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := *(tcpLayer.(*layers.TCP))
		if opts.SrcPort > 0 {
			tcp.SrcPort = layers.TCPPort(opts.SrcPort)
		}
		if opts.DstPort > 0 {
			tcp.DstPort = layers.TCPPort(opts.DstPort)
		}
		if networkLayer != nil {
			tcp.SetNetworkLayerForChecksum(networkLayer)
		}
		layersOut = append(layersOut, &tcp)
		layersOut = append(layersOut, gopacket.Payload(tcp.Payload))
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := *(udpLayer.(*layers.UDP))
		if opts.SrcPort > 0 {
			udp.SrcPort = layers.UDPPort(opts.SrcPort)
		}
		if opts.DstPort > 0 {
			udp.DstPort = layers.UDPPort(opts.DstPort)
		}
		if networkLayer != nil {
			udp.SetNetworkLayerForChecksum(networkLayer)
		}
		layersOut = append(layersOut, &udp)
		layersOut = append(layersOut, gopacket.Payload(udp.Payload))
	} else {
		return nil, fmt.Errorf("no TCP/UDP layer")
	}

	buffer := gopacket.NewSerializeBuffer()
	optsSerialize := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: opts.RecomputeChecksums,
	}
	if err := gopacket.SerializeLayers(buffer, optsSerialize, layersOut...); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func ParseMAC(input string) (net.HardwareAddr, error) {
	if input == "" {
		return nil, nil
	}
	addr, err := net.ParseMAC(input)
	if err != nil {
		return nil, fmt.Errorf("invalid mac address '%s'", input)
	}
	return addr, nil
}
