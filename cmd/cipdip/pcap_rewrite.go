package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/cobra"
)

type pcapRewriteFlags struct {
	input          string
	output         string
	srcIP          string
	dstIP          string
	srcPort        int
	dstPort        int
	srcMAC         string
	dstMAC         string
	onlyENIP       bool
	recomputeCksum bool
	report         bool
}

func newPcapRewriteCmd() *cobra.Command {
	flags := &pcapRewriteFlags{}

	cmd := &cobra.Command{
		Use:   "pcap-rewrite",
		Short: "Rewrite IP/port fields in a PCAP",
		Long: `Rewrite source/destination IPs and ports for ENIP/CIP traffic.
This is useful before tcpreplay when you need to map captures to lab endpoints.`,
		Example: `  # Rewrite IPs for ENIP traffic only
  cipdip pcap-rewrite --input capture.pcap --output rewritten.pcap --src-ip 10.0.0.20 --dst-ip 10.0.0.10`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if handleHelpArg(cmd, args) {
				return nil
			}
			if flags.input == "" {
				return missingFlagError(cmd, "--input")
			}
			if flags.output == "" {
				return missingFlagError(cmd, "--output")
			}
			return runPcapRewrite(flags)
		},
	}

	cmd.Flags().StringVar(&flags.input, "input", "", "Input PCAP file (required)")
	cmd.Flags().StringVar(&flags.output, "output", "", "Output PCAP file (required)")
	cmd.Flags().StringVar(&flags.srcIP, "src-ip", "", "Rewrite source IP address")
	cmd.Flags().StringVar(&flags.dstIP, "dst-ip", "", "Rewrite destination IP address")
	cmd.Flags().IntVar(&flags.srcPort, "src-port", 0, "Rewrite source port")
	cmd.Flags().IntVar(&flags.dstPort, "dst-port", 0, "Rewrite destination port")
	cmd.Flags().StringVar(&flags.srcMAC, "src-mac", "", "Rewrite source MAC address")
	cmd.Flags().StringVar(&flags.dstMAC, "dst-mac", "", "Rewrite destination MAC address")
	cmd.Flags().BoolVar(&flags.onlyENIP, "only-enip", true, "Only rewrite packets on 44818/2222 when enabled")
	cmd.Flags().BoolVar(&flags.recomputeCksum, "recompute-checksums", true, "Recompute IP/TCP/UDP checksums")
	cmd.Flags().BoolVar(&flags.report, "report", true, "Print a summary report after rewrite")

	return cmd
}

func runPcapRewrite(flags *pcapRewriteFlags) error {
	handle, err := pcap.OpenOffline(flags.input)
	if err != nil {
		return fmt.Errorf("open pcap: %w", err)
	}
	defer handle.Close()

	out, err := os.Create(flags.output)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer out.Close()

	writer := pcapgo.NewWriter(out)
	if err := writer.WriteFileHeader(65535, handle.LinkType()); err != nil {
		return fmt.Errorf("write pcap header: %w", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: flags.recomputeCksum,
	}

	srcIP := net.ParseIP(flags.srcIP)
	dstIP := net.ParseIP(flags.dstIP)
	srcMAC, err := parseMAC(flags.srcMAC)
	if err != nil {
		return err
	}
	dstMAC, err := parseMAC(flags.dstMAC)
	if err != nil {
		return err
	}

	stats := rewriteStats{}

	for packet := range packetSource.Packets() {
		if packet == nil {
			continue
		}
		stats.total++
		if !shouldRewrite(packet, flags.onlyENIP) {
			stats.skipped++
			if err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				return fmt.Errorf("write packet: %w", err)
			}
			continue
		}

		data, err := rewritePacket(packet, srcIP, dstIP, srcMAC, dstMAC, flags.srcPort, flags.dstPort, opts, &stats)
		if err != nil {
			stats.errors++
			if err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				return fmt.Errorf("write packet: %w", err)
			}
			continue
		}
		stats.rewritten++

		ci := packet.Metadata().CaptureInfo
		if ci.Timestamp.IsZero() {
			ci.Timestamp = time.Now()
		}
		ci.CaptureLength = len(data)
		ci.Length = len(data)
		if err := writer.WritePacket(ci, data); err != nil {
			return fmt.Errorf("write packet: %w", err)
		}
	}

	if flags.report {
		fmt.Fprintf(os.Stdout, "Rewrite summary: total=%d rewritten=%d skipped=%d errors=%d\n",
			stats.total, stats.rewritten, stats.skipped, stats.errors)
	}

	return nil
}

func shouldRewrite(packet gopacket.Packet, onlyENIP bool) bool {
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

type rewriteStats struct {
	total     int
	rewritten int
	skipped   int
	errors    int
}

func rewritePacket(packet gopacket.Packet, srcIP, dstIP net.IP, srcMAC, dstMAC net.HardwareAddr, srcPort, dstPort int, opts gopacket.SerializeOptions, stats *rewriteStats) ([]byte, error) {
	var layersOut []gopacket.SerializableLayer

	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := *(ethLayer.(*layers.Ethernet))
		if len(srcMAC) > 0 {
			eth.SrcMAC = srcMAC
		}
		if len(dstMAC) > 0 {
			eth.DstMAC = dstMAC
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
		if srcIP != nil && srcIP.To4() != nil {
			ip4.SrcIP = srcIP.To4()
		}
		if dstIP != nil && dstIP.To4() != nil {
			ip4.DstIP = dstIP.To4()
		}
		networkLayer = &ip4
		layersOut = append(layersOut, &ip4)
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6 := *(ip6Layer.(*layers.IPv6))
		if srcIP != nil && srcIP.To16() != nil {
			ip6.SrcIP = srcIP.To16()
		}
		if dstIP != nil && dstIP.To16() != nil {
			ip6.DstIP = dstIP.To16()
		}
		networkLayer = &ip6
		layersOut = append(layersOut, &ip6)
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := *(tcpLayer.(*layers.TCP))
		if srcPort > 0 {
			tcp.SrcPort = layers.TCPPort(srcPort)
		}
		if dstPort > 0 {
			tcp.DstPort = layers.TCPPort(dstPort)
		}
		if networkLayer != nil {
			tcp.SetNetworkLayerForChecksum(networkLayer)
		}
		layersOut = append(layersOut, &tcp)
		layersOut = append(layersOut, gopacket.Payload(tcp.Payload))
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := *(udpLayer.(*layers.UDP))
		if srcPort > 0 {
			udp.SrcPort = layers.UDPPort(srcPort)
		}
		if dstPort > 0 {
			udp.DstPort = layers.UDPPort(dstPort)
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
	if err := gopacket.SerializeLayers(buffer, opts, layersOut...); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func parseMAC(input string) (net.HardwareAddr, error) {
	if input == "" {
		return nil, nil
	}
	addr, err := net.ParseMAC(input)
	if err != nil {
		return nil, fmt.Errorf("invalid mac address '%s'", input)
	}
	return addr, nil
}
