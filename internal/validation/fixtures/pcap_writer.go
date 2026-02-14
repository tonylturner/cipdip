package fixtures

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/tonylturner/cipdip/internal/validation"
)

func WriteENIPPCAP(path string, packets []ValidationPacket) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create pcap: %w", err)
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return fmt.Errorf("write pcap header: %w", err)
	}

	type flowState struct {
		port      uint16
		clientSeq uint32
		serverSeq uint32
	}
	baseFlows := map[string]*flowState{}
	nextPort := uint16(50000)
	for _, packet := range packets {
		baseID := strings.TrimSuffix(strings.TrimSuffix(packet.Expect.ID, "/request"), "/response")
		flow, ok := baseFlows[baseID]
		if !ok {
			flow = &flowState{port: nextPort, clientSeq: 1, serverSeq: 1}
			baseFlows[baseID] = flow
			nextPort++
		}
		srcIP := []byte{192, 168, 100, 10}
		dstIP := []byte{192, 168, 100, 20}
		srcPort := flow.port
		dstPort := uint16(44818)
		seq := flow.clientSeq
		ack := uint32(0)
		if packet.Expect.Direction == "response" {
			srcIP, dstIP = dstIP, srcIP
			srcPort, dstPort = dstPort, srcPort
			seq = flow.serverSeq
			ack = flow.clientSeq
		}
		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		ethernet := &layers.Ethernet{
			SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    srcIP,
			DstIP:    dstIP,
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
			SYN:     false,
			ACK:     true,
			PSH:     true,
			Seq:     seq,
			Ack:     ack,
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)

		if packet.Expect.Direction == "response" {
			flow.serverSeq += uint32(len(packet.Data))
		} else {
			flow.clientSeq += uint32(len(packet.Data))
		}

		if err := gopacket.SerializeLayers(buffer, opts, ethernet, ip, tcp, gopacket.Payload(packet.Data)); err != nil {
			return fmt.Errorf("serialize packet: %w", err)
		}
		if err := writer.WritePacket(gopacket.CaptureInfo{
			CaptureLength: len(buffer.Bytes()),
			Length:        len(buffer.Bytes()),
		}, buffer.Bytes()); err != nil {
			return fmt.Errorf("write packet: %w", err)
		}
	}

	return nil
}

func GenerateValidationPCAPs(outputDir string) ([]string, error) {
	specs, err := DefaultValidationPCAPSpecs()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}
	paths := make([]string, 0, len(specs))
	for _, spec := range specs {
		packets, err := BuildValidationPackets(spec)
		if err != nil {
			return nil, err
		}
		path := filepath.Join(outputDir, fmt.Sprintf("validation_%s.pcap", spec.Name))
		expectations := make([]PacketExpectation, 0, len(packets))
		for _, pkt := range packets {
			expectations = append(expectations, pkt.Expect)
		}
		if err := WriteENIPPCAP(path, packets); err != nil {
			return nil, err
		}
		manifest := ValidationManifest{
			PCAP:    filepath.Base(path),
			Packets: expectations,
		}
		if err := validation.WriteValidationManifest(validation.ValidationManifestPath(path), manifest); err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}
