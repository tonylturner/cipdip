package main

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/tturner/cipdip/internal/cip/codec"
	"github.com/tturner/cipdip/internal/pcap"
)

func TestHasPerFlowTCPHandshake(t *testing.T) {
	pcapPath := writeTestPCAP(t, buildHandshakePCAPPackets(t, true))
	ok, stats, err := pcap.HasPerFlowTCPHandshake(pcapPath)
	if err != nil {
		t.Fatalf("hasPerFlowTCPHandshake error: %v", err)
	}
	if !ok {
		t.Fatalf("expected per-flow handshake to be true")
	}
	if stats == nil || stats.Total != 1 || stats.Complete != 1 {
		t.Fatalf("unexpected stats: %#v", stats)
	}

	pcapPath = writeTestPCAP(t, buildHandshakePCAPPackets(t, false))
	ok, stats, err = pcap.HasPerFlowTCPHandshake(pcapPath)
	if err != nil {
		t.Fatalf("hasPerFlowTCPHandshake error (missing ack): %v", err)
	}
	if ok {
		t.Fatalf("expected per-flow handshake to be false for missing ack")
	}
	if stats == nil || stats.Total != 1 || stats.Complete != 0 {
		t.Fatalf("unexpected stats (missing ack): %#v", stats)
	}
}

func TestSummarizePcapForReplay(t *testing.T) {
	packets := buildHandshakePCAPPackets(t, true)
	packets = append(packets, buildENIPDataPacket(t, "10.0.0.1", "10.0.0.2", 12000, 44818, buildENIPRegisterSession(true))...)
	packets = append(packets, buildENIPDataPacket(t, "10.0.0.2", "10.0.0.1", 44818, 12000, buildENIPRegisterSession(false))...)

	pcapPath := writeTestPCAP(t, packets)
	summary, err := pcap.SummarizePcapForReplay(pcapPath)
	if err != nil {
		t.Fatalf("summarizePcapForReplay error: %v", err)
	}
	if summary.Total != 5 {
		t.Fatalf("expected total packets 5, got %d", summary.Total)
	}
	if summary.Enip != 2 || summary.Requests != 1 || summary.Responses != 1 {
		t.Fatalf("unexpected ENIP counts: enip=%d req=%d resp=%d", summary.Enip, summary.Requests, summary.Responses)
	}
	if summary.MissingResponse != 0 {
		t.Fatalf("expected missingResponse 0, got %d", summary.MissingResponse)
	}
	if !summary.HandshakeAny || !summary.HandshakeFlows {
		t.Fatalf("expected handshake flags to be true, got any=%t flows=%t", summary.HandshakeAny, summary.HandshakeFlows)
	}
	if summary.FlowsTotal != 1 || summary.FlowsComplete != 1 {
		t.Fatalf("unexpected flow stats: total=%d complete=%d", summary.FlowsTotal, summary.FlowsComplete)
	}
}

func TestCanonicalFlowKey(t *testing.T) {
	key1 := pcap.CanonicalFlowKey("10.0.0.1", 12000, "10.0.0.2", 44818)
	key2 := pcap.CanonicalFlowKey("10.0.0.2", 44818, "10.0.0.1", 12000)
	if key1 != key2 {
		t.Fatalf("expected canonical flow keys to match: %s vs %s", key1, key2)
	}
}

func buildHandshakePCAPPackets(t *testing.T, includeAck bool) [][]byte {
	t.Helper()
	srcIP := "10.0.0.1"
	dstIP := "10.0.0.2"
	srcPort := uint16(12000)
	dstPort := uint16(44818)

	var packets [][]byte
	packets = append(packets, buildTCPPacket(t, srcIP, dstIP, srcPort, dstPort, 1, 0, true, false, nil))
	packets = append(packets, buildTCPPacket(t, dstIP, srcIP, dstPort, srcPort, 2, 2, true, true, nil))
	if includeAck {
		packets = append(packets, buildTCPPacket(t, srcIP, dstIP, srcPort, dstPort, 2, 3, false, true, nil))
	}
	return packets
}

func buildENIPDataPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) [][]byte {
	t.Helper()
	return [][]byte{
		buildTCPPacket(t, srcIP, dstIP, srcPort, dstPort, 10, 0, false, true, payload),
	}
}

func buildTCPPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, syn, ackFlag bool, payload []byte) []byte {
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
		Seq:     seq,
		Ack:     ack,
		SYN:     syn,
		ACK:     ackFlag,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}
	return buf.Bytes()
}

func buildENIPRegisterSession(isRequest bool) []byte {
	data := []byte{0x01, 0x00, 0x00, 0x00}
	sessionID := uint32(0)
	if !isRequest {
		sessionID = 0x11223344
	}
	header := make([]byte, 24+len(data))
	codec.PutUint16(binary.LittleEndian, header[0:2], 0x0065)
	codec.PutUint16(binary.LittleEndian, header[2:4], uint16(len(data)))
	codec.PutUint32(binary.LittleEndian, header[4:8], sessionID)
	codec.PutUint32(binary.LittleEndian, header[8:12], 0)
	copy(header[24:], data)
	return header
}

func writeTestPCAP(t *testing.T, packets [][]byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	for i, data := range packets {
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Unix(1700000000, int64(i)*int64(time.Millisecond)),
			CaptureLength: len(data),
			Length:        len(data),
		}
		if err := writer.WritePacket(ci, data); err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}

	return path
}
