package main

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/tonylturner/cipdip/internal/pcap"
)

func TestRewritePacketTCP(t *testing.T) {
	original := buildTCPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 44818, 1, 0, true, false, []byte{0x01, 0x02})
	packet := gopacket.NewPacket(original, layers.LayerTypeEthernet, gopacket.Default)

	srcIP := net.ParseIP("192.168.1.10")
	dstIP := net.ParseIP("192.168.1.20")
	srcMAC, _ := pcap.ParseMAC("aa:bb:cc:dd:ee:ff")
	dstMAC, _ := pcap.ParseMAC("11:22:33:44:55:66")

	data, err := pcap.RewritePacket(packet, pcap.RewriteOptions{
		SrcIP:              srcIP,
		DstIP:              dstIP,
		SrcPort:            15000,
		DstPort:            44819,
		SrcMAC:             srcMAC,
		DstMAC:             dstMAC,
		RecomputeChecksums: true,
	})
	if err != nil {
		t.Fatalf("rewritePacket error: %v", err)
	}

	decoded := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	eth := decoded.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if eth.SrcMAC.String() != srcMAC.String() || eth.DstMAC.String() != dstMAC.String() {
		t.Fatalf("unexpected MAC rewrite: src=%s dst=%s", eth.SrcMAC, eth.DstMAC)
	}
	ip4 := decoded.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ip4.SrcIP.Equal(srcIP.To4()) || !ip4.DstIP.Equal(dstIP.To4()) {
		t.Fatalf("unexpected IP rewrite: src=%s dst=%s", ip4.SrcIP, ip4.DstIP)
	}
	tcp := decoded.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if uint16(tcp.SrcPort) != 15000 || uint16(tcp.DstPort) != 44819 {
		t.Fatalf("unexpected port rewrite: src=%d dst=%d", tcp.SrcPort, tcp.DstPort)
	}
}

func TestShouldRewriteENIPFilter(t *testing.T) {
	tcpENIP := gopacket.NewPacket(
		buildTCPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 44818, 1, 0, true, false, nil),
		layers.LayerTypeEthernet,
		gopacket.Default,
	)
	if !pcap.ShouldRewrite(tcpENIP, true) {
		t.Fatalf("expected ENIP TCP packet to be rewriteable")
	}

	tcpOther := gopacket.NewPacket(
		buildTCPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 12345, 1, 0, true, false, nil),
		layers.LayerTypeEthernet,
		gopacket.Default,
	)
	if pcap.ShouldRewrite(tcpOther, true) {
		t.Fatalf("expected non-ENIP TCP packet to be skipped")
	}
	if !pcap.ShouldRewrite(tcpOther, false) {
		t.Fatalf("expected rewrite when onlyENIP is false")
	}

	udpENIP := gopacket.NewPacket(
		buildUDPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 2222, []byte{0x01}),
		layers.LayerTypeEthernet,
		gopacket.Default,
	)
	if !pcap.ShouldRewrite(udpENIP, true) {
		t.Fatalf("expected ENIP UDP packet to be rewriteable")
	}
}

func buildUDPPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) []byte {
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
		t.Fatalf("serialize UDP packet: %v", err)
	}
	return buf.Bytes()
}
