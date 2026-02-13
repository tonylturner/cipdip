package pcap

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/enip"
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
	prev := client.CurrentProtocolProfile()
	client.SetProtocolProfile(client.StrictODVAProfile)
	defer client.SetProtocolProfile(prev)

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

// --- IPv6 packet builders ---

func buildENIPTCPPacket6(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      net.ParseIP(srcIP),
		DstIP:      net.ParseIP(dstIP),
		NextHeader: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     1,
		ACK:     true,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ip6)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip6, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize ipv6 tcp packet: %v", err)
	}
	return buf.Bytes()
}

func buildENIPUDPPacket6(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      net.ParseIP(srcIP),
		DstIP:      net.ParseIP(dstIP),
		NextHeader: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip6)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip6, udp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize ipv6 udp packet: %v", err)
	}
	return buf.Bytes()
}

// --- IPv6 extraction tests ---

func TestExtractENIPFromPCAPMetadataTCPIPv6(t *testing.T) {
	payload := enip.BuildRegisterSession([8]byte{0x10})
	packet := buildENIPTCPPacket6(t, "2001:db8::1", "2001:db8::2", 12000, 44818, payload)
	pcapPath := writeENIPPCAP(t, packet)

	packets, err := ExtractENIPFromPCAP(pcapPath)
	if err != nil {
		t.Fatalf("ExtractENIPFromPCAP error: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	pkt := packets[0]
	if pkt.Transport != "tcp" {
		t.Errorf("Transport = %q, want tcp", pkt.Transport)
	}
	if pkt.SrcPort != 12000 || pkt.DstPort != 44818 {
		t.Errorf("ports: src=%d dst=%d", pkt.SrcPort, pkt.DstPort)
	}
	// Verify IPv6 addresses are extracted.
	if pkt.SrcIP != "2001:db8::1" {
		t.Errorf("SrcIP = %q, want 2001:db8::1", pkt.SrcIP)
	}
	if pkt.DstIP != "2001:db8::2" {
		t.Errorf("DstIP = %q, want 2001:db8::2", pkt.DstIP)
	}
	if pkt.Timestamp.IsZero() {
		t.Error("expected timestamp to be set")
	}
}

func TestExtractENIPFromPCAPMetadataUDPIPv6(t *testing.T) {
	payload := enip.BuildListIdentity([8]byte{0x11})
	packet := buildENIPUDPPacket6(t, "fd00::10", "fd00::20", 12001, 44818, payload)
	pcapPath := writeENIPPCAP(t, packet)

	packets, err := ExtractENIPFromPCAP(pcapPath)
	if err != nil {
		t.Fatalf("ExtractENIPFromPCAP error: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	pkt := packets[0]
	if pkt.Transport != "udp" {
		t.Errorf("Transport = %q, want udp", pkt.Transport)
	}
	if pkt.SrcIP != "fd00::10" {
		t.Errorf("SrcIP = %q, want fd00::10", pkt.SrcIP)
	}
	if pkt.DstIP != "fd00::20" {
		t.Errorf("DstIP = %q, want fd00::20", pkt.DstIP)
	}
}

func TestExtractENIPFromPCAPTCPReassemblyIPv6(t *testing.T) {
	payload := enip.BuildRegisterSession([8]byte{0x12})
	if len(payload) < 10 {
		t.Fatalf("unexpected ENIP payload length: %d", len(payload))
	}
	part1 := payload[:10]
	part2 := payload[10:]

	pkt1 := buildENIPTCPPacket6(t, "2001:db8::1", "2001:db8::2", 12002, 44818, part1)
	pkt2 := buildENIPTCPPacket6(t, "2001:db8::1", "2001:db8::2", 12002, 44818, part2)
	pcapPath := writeENIPPCAP(t, pkt1, pkt2)

	packets, err := ExtractENIPFromPCAP(pcapPath)
	if err != nil {
		t.Fatalf("ExtractENIPFromPCAP error: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 reassembled packet, got %d", len(packets))
	}
	if len(packets[0].FullPacket) != len(payload) {
		t.Fatalf("full packet length = %d, want %d", len(packets[0].FullPacket), len(payload))
	}
	if packets[0].SrcIP != "2001:db8::1" {
		t.Errorf("SrcIP = %q, want 2001:db8::1", packets[0].SrcIP)
	}
}

func TestStreamKeyIPv6Format(t *testing.T) {
	// Verify that IPv6 packets produce distinct, consistent stream keys
	// for TCP reassembly (colons in addresses don't cause issues).
	payload := enip.BuildRegisterSession([8]byte{0x13})

	// Two packets from same flow (same IPs+ports).
	pkt1 := buildENIPTCPPacket6(t, "2001:db8::100", "2001:db8::200", 12003, 44818, payload)
	// One packet from a different flow (different source IP).
	pkt2 := buildENIPTCPPacket6(t, "2001:db8::101", "2001:db8::200", 12003, 44818, payload)

	pcapPath := writeENIPPCAP(t, pkt1, pkt2)

	packets, err := ExtractENIPFromPCAP(pcapPath)
	if err != nil {
		t.Fatalf("ExtractENIPFromPCAP error: %v", err)
	}
	// Both packets are complete ENIP frames, so we expect 2.
	if len(packets) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(packets))
	}
	// Verify they have different source IPs (meaning stream keys differentiated them).
	if packets[0].SrcIP == packets[1].SrcIP {
		t.Error("expected different SrcIPs for different flows")
	}
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
