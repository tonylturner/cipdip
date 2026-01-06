package pcap

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type FlowHandshakeStats struct {
	Total    int
	Complete int
}

type ReplaySummary struct {
	Total           int
	Enip            int
	EnipTCP         int
	EnipUDP         int
	Requests        int
	Responses       int
	MissingResponse int
	HandshakeAny    bool
	HandshakeFlows  bool
	FlowsTotal      int
	FlowsComplete   int
}

func SummarizePcapForReplay(path string) (*ReplaySummary, error) {
	total, err := countPcapPackets(path)
	if err != nil {
		return nil, err
	}
	packets, err := ExtractENIPFromPCAP(path)
	if err != nil {
		return nil, err
	}
	summary := &ReplaySummary{
		Total: total,
		Enip:  len(packets),
	}
	for _, pkt := range packets {
		if pkt.IsRequest {
			summary.Requests++
		} else {
			summary.Responses++
		}
		transport := strings.ToLower(pkt.Transport)
		if transport == "" {
			if pkt.DstPort == 2222 {
				transport = "udp"
			} else {
				transport = "tcp"
			}
		}
		switch transport {
		case "udp":
			summary.EnipUDP++
		default:
			summary.EnipTCP++
		}
	}
	if summary.Requests > summary.Responses {
		summary.MissingResponse = summary.Requests - summary.Responses
	}
	handshakeAny, _ := HasTCPHandshake(path)
	handshakeFlows, flowStats, _ := HasPerFlowTCPHandshake(path)
	summary.HandshakeAny = handshakeAny
	summary.HandshakeFlows = handshakeFlows
	if flowStats != nil {
		summary.FlowsTotal = flowStats.Total
		summary.FlowsComplete = flowStats.Complete
	}
	return summary, nil
}

func HasTCPHandshake(pcapFile string) (bool, error) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return false, fmt.Errorf("open pcap: %w", err)
	}
	defer handle.Close()

	var syn, synAck, ack bool
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		layer := packet.Layer(layers.LayerTypeTCP)
		if layer == nil {
			continue
		}
		tcp, _ := layer.(*layers.TCP)
		if tcp == nil {
			continue
		}
		if tcp.DstPort != 44818 && tcp.SrcPort != 44818 {
			continue
		}
		if tcp.SYN && !tcp.ACK {
			syn = true
		} else if tcp.SYN && tcp.ACK {
			synAck = true
		} else if tcp.ACK && !tcp.SYN {
			ack = true
		}
		if syn && synAck && ack {
			return true, nil
		}
	}
	return false, nil
}

type handshakeState struct {
	syn      bool
	synAck   bool
	ack      bool
	complete bool
}

func HasPerFlowTCPHandshake(pcapFile string) (bool, *FlowHandshakeStats, error) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return false, nil, fmt.Errorf("open pcap: %w", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	flows := make(map[string]*handshakeState)

	for packet := range packetSource.Packets() {
		layer := packet.Layer(layers.LayerTypeTCP)
		if layer == nil {
			continue
		}
		tcp, _ := layer.(*layers.TCP)
		if tcp == nil {
			continue
		}
		if tcp.DstPort != 44818 && tcp.SrcPort != 44818 {
			continue
		}
		netLayer := packet.NetworkLayer()
		if netLayer == nil {
			continue
		}
		src, dst := netLayer.NetworkFlow().Endpoints()
		key := CanonicalFlowKey(src.String(), uint16(tcp.SrcPort), dst.String(), uint16(tcp.DstPort))
		state := flows[key]
		if state == nil {
			state = &handshakeState{}
			flows[key] = state
		}
		if tcp.SYN && !tcp.ACK {
			state.syn = true
		} else if tcp.SYN && tcp.ACK {
			state.synAck = true
		} else if tcp.ACK && !tcp.SYN {
			state.ack = true
		}
		if state.syn && state.synAck && state.ack {
			state.complete = true
		}
	}

	if len(flows) == 0 {
		return false, &FlowHandshakeStats{}, nil
	}
	stats := &FlowHandshakeStats{Total: len(flows)}
	for _, state := range flows {
		if state.complete {
			stats.Complete++
		}
	}
	if stats.Complete != stats.Total {
		return false, stats, nil
	}
	return true, stats, nil
}

func CanonicalFlowKey(srcIP string, srcPort uint16, dstIP string, dstPort uint16) string {
	leftIP, rightIP := srcIP, dstIP
	leftPort, rightPort := srcPort, dstPort
	if leftIP > rightIP || (leftIP == rightIP && leftPort > rightPort) {
		leftIP, rightIP = rightIP, leftIP
		leftPort, rightPort = rightPort, leftPort
	}
	return fmt.Sprintf("%s:%d<->%s:%d", leftIP, leftPort, rightIP, rightPort)
}

func countPcapPackets(path string) (int, error) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return 0, fmt.Errorf("open pcap: %w", err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	total := 0
	for range packetSource.Packets() {
		total++
	}
	return total, nil
}
