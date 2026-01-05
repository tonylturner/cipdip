package cipclient

import (
	"github.com/tturner/cipdip/internal/enip"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestExtractENIPFromPCAPMetadataTCP(t *testing.T) {
	payload := enip.BuildRegisterSession([8]byte{0x01})
	packet := buildENIPTCPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 44818, payload)
	pcapPath := writeENIPPCAP(t, packet)

	packets, err := ExtractENIPFromPCAP(pcapPath)
	if err != nil {
		t.Fatalf("ExtractENIPFromPCAP error: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	if packets[0].Transport != "tcp" {
		t.Fatalf("expected tcp transport, got %s", packets[0].Transport)
	}
	if packets[0].SrcPort != 12000 || packets[0].DstPort != 44818 {
		t.Fatalf("unexpected ports: src=%d dst=%d", packets[0].SrcPort, packets[0].DstPort)
	}
	if packets[0].Timestamp.IsZero() {
		t.Fatalf("expected timestamp to be set")
	}
}

func TestExtractENIPFromPCAPMetadataUDP(t *testing.T) {
	payload := enip.BuildListIdentity([8]byte{0x02})
	packet := buildENIPUDPPacket(t, "10.0.0.3", "10.0.0.4", 12001, 44818, payload)
	pcapPath := writeENIPPCAP(t, packet)

	packets, err := ExtractENIPFromPCAP(pcapPath)
	if err != nil {
		t.Fatalf("ExtractENIPFromPCAP error: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	if packets[0].Transport != "udp" {
		t.Fatalf("expected udp transport, got %s", packets[0].Transport)
	}
	if packets[0].SrcPort != 12001 || packets[0].DstPort != 44818 {
		t.Fatalf("unexpected ports: src=%d dst=%d", packets[0].SrcPort, packets[0].DstPort)
	}
}

func TestExtractENIPFromPCAPTCPReassembly(t *testing.T) {
	payload := enip.BuildRegisterSession([8]byte{0x03})
	if len(payload) < 10 {
		t.Fatalf("unexpected ENIP payload length: %d", len(payload))
	}
	part1 := payload[:10]
	part2 := payload[10:]

	packet1 := buildENIPTCPPacket(t, "10.0.0.1", "10.0.0.2", 12002, 44818, part1)
	packet2 := buildENIPTCPPacket(t, "10.0.0.1", "10.0.0.2", 12002, 44818, part2)

	pcapPath := writeENIPPCAP(t, packet1, packet2)

	packets, err := ExtractENIPFromPCAP(pcapPath)
	if err != nil {
		t.Fatalf("ExtractENIPFromPCAP error: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 reassembled packet, got %d", len(packets))
	}
	if len(packets[0].FullPacket) != len(payload) {
		t.Fatalf("expected full packet length %d, got %d", len(payload), len(packets[0].FullPacket))
	}
}

func TestExtractENIPFromPCAPResponseDetection(t *testing.T) {
	prev := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prev)

	cipResp := []byte{0x8E, 0x00, 0x00, 0x00, 0x11, 0x22}
	sendData := enip.BuildSendRRDataPayload(cipResp)
	encap := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandSendRRData,
		Length:        uint16(len(sendData)),
		SessionID:     0x12345678,
		Status:        0,
		SenderContext: [8]byte{0x01},
		Options:       0,
		Data:          sendData,
	}
	packetBytes := enip.EncodeENIP(encap)
	packet := buildENIPTCPPacket(t, "10.0.0.1", "10.0.0.2", 12003, 44818, packetBytes)
	pcapPath := writeENIPPCAP(t, packet)

	packets, err := ExtractENIPFromPCAP(pcapPath)
	if err != nil {
		t.Fatalf("ExtractENIPFromPCAP error: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	if packets[0].IsRequest {
		t.Fatalf("expected IsRequest=false for response CIP service")
	}
}

func buildENIPTCPPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     1,
		ACK:     true,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize tcp packet: %v", err)
	}
	return buf.Bytes()
}

func buildENIPUDPPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize udp packet: %v", err)
	}
	return buf.Bytes()
}

func writeENIPPCAP(t *testing.T, packets ...[]byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "enip.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	for i, packet := range packets {
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Unix(1700000000, int64(i)*int64(time.Millisecond)),
			CaptureLength: len(packet),
			Length:        len(packet),
		}
		if err := writer.WritePacket(ci, packet); err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}
	return path
}
