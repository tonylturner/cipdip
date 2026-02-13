package pcap

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/tonylturner/cipdip/internal/modbus"
)

func skipIfNoPcap(t *testing.T, err error) {
	t.Helper()
	if err != nil && (strings.Contains(err.Error(), "wpcap.dll") || strings.Contains(err.Error(), "couldn't load")) {
		t.Skip("Skipping: pcap library not available")
	}
}

// buildModbusTCPPacket builds a synthetic Ethernet+IPv4+TCP packet for Modbus traffic.
func buildModbusTCPPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) []byte {
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
		t.Fatalf("serialize modbus tcp packet: %v", err)
	}
	return buf.Bytes()
}

// buildModbusRequestFrame builds a Modbus TCP (MBAP) request frame.
func buildModbusRequestFrame(txnID uint16, unitID uint8, fc modbus.FunctionCode, data []byte) []byte {
	return modbus.EncodeRequestTCP(modbus.Request{
		TransactionID: txnID,
		UnitID:        unitID,
		Function:      fc,
		Data:          data,
	})
}

// buildModbusExceptionFrame builds a Modbus TCP exception response frame.
func buildModbusExceptionFrame(txnID uint16, unitID uint8, fc modbus.FunctionCode, exCode modbus.ExceptionCode) []byte {
	return modbus.EncodeResponseTCP(modbus.Response{
		TransactionID: txnID,
		UnitID:        unitID,
		Function:      fc | 0x80,
		Data:          []byte{byte(exCode)},
	})
}

// buildReadHoldingRegistersData builds the FC3 request data: start address + quantity.
func buildReadHoldingRegistersData(startAddr, quantity uint16) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:2], startAddr)
	binary.BigEndian.PutUint16(data[2:4], quantity)
	return data
}

func TestExtractModbusFromPCAP_ReadHoldingRegisters(t *testing.T) {
	data := buildReadHoldingRegistersData(0, 10)
	frame := buildModbusRequestFrame(1, 1, modbus.FcReadHoldingRegisters, data)
	packet := buildModbusTCPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 502, frame)
	pcapPath := writeENIPPCAP(t, packet)

	packets, err := ExtractModbusFromPCAP(pcapPath)
	skipIfNoPcap(t, err)
	if err != nil {
		t.Fatalf("ExtractModbusFromPCAP: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	pkt := packets[0]
	if pkt.TransactionID != 1 {
		t.Errorf("TransactionID = %d, want 1", pkt.TransactionID)
	}
	if pkt.UnitID != 1 {
		t.Errorf("UnitID = %d, want 1", pkt.UnitID)
	}
	if pkt.Function != modbus.FcReadHoldingRegisters {
		t.Errorf("Function = 0x%02X, want 0x03", pkt.Function)
	}
	if !pkt.IsRequest {
		t.Error("expected IsRequest=true for client→server")
	}
	if pkt.IsException {
		t.Error("expected IsException=false")
	}
	if pkt.Transport != "tcp" {
		t.Errorf("Transport = %q, want tcp", pkt.Transport)
	}
	if pkt.SrcPort != 12000 || pkt.DstPort != 502 {
		t.Errorf("ports: src=%d dst=%d", pkt.SrcPort, pkt.DstPort)
	}
	if pkt.Mode != modbus.ModeTCP {
		t.Errorf("Mode = %v, want ModeTCP", pkt.Mode)
	}
}

func TestExtractModbusFromPCAP_MultipleFrames(t *testing.T) {
	// Three different function codes in one pcap.
	frame1 := buildModbusRequestFrame(1, 1, modbus.FcReadCoils, buildReadHoldingRegistersData(0, 8))
	frame2 := buildModbusRequestFrame(2, 1, modbus.FcReadHoldingRegisters, buildReadHoldingRegistersData(100, 5))
	frame3 := buildModbusRequestFrame(3, 1, modbus.FcWriteSingleRegister, buildReadHoldingRegistersData(50, 0x1234))

	pkt1 := buildModbusTCPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 502, frame1)
	pkt2 := buildModbusTCPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 502, frame2)
	pkt3 := buildModbusTCPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 502, frame3)

	pcapPath := writeENIPPCAP(t, pkt1, pkt2, pkt3)

	packets, err := ExtractModbusFromPCAP(pcapPath)
	skipIfNoPcap(t, err)
	if err != nil {
		t.Fatalf("ExtractModbusFromPCAP: %v", err)
	}
	if len(packets) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(packets))
	}
	if packets[0].Function != modbus.FcReadCoils {
		t.Errorf("pkt0 FC = 0x%02X, want 0x01", packets[0].Function)
	}
	if packets[1].Function != modbus.FcReadHoldingRegisters {
		t.Errorf("pkt1 FC = 0x%02X, want 0x03", packets[1].Function)
	}
	if packets[2].Function != modbus.FcWriteSingleRegister {
		t.Errorf("pkt2 FC = 0x%02X, want 0x06", packets[2].Function)
	}
	for i, p := range packets {
		if p.TransactionID != uint16(i+1) {
			t.Errorf("pkt%d TransactionID = %d, want %d", i, p.TransactionID, i+1)
		}
	}
}

func TestExtractModbusFromPCAP_TCPReassembly(t *testing.T) {
	frame := buildModbusRequestFrame(42, 1, modbus.FcReadHoldingRegisters, buildReadHoldingRegistersData(0, 10))
	if len(frame) < 6 {
		t.Fatalf("frame too short: %d", len(frame))
	}

	// Split the MBAP frame across two TCP segments.
	mid := len(frame) / 2
	part1 := frame[:mid]
	part2 := frame[mid:]

	pkt1 := buildModbusTCPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 502, part1)
	pkt2 := buildModbusTCPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 502, part2)
	pcapPath := writeENIPPCAP(t, pkt1, pkt2)

	packets, err := ExtractModbusFromPCAP(pcapPath)
	skipIfNoPcap(t, err)
	if err != nil {
		t.Fatalf("ExtractModbusFromPCAP: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 reassembled packet, got %d", len(packets))
	}
	if packets[0].TransactionID != 42 {
		t.Errorf("TransactionID = %d, want 42", packets[0].TransactionID)
	}
	if packets[0].Function != modbus.FcReadHoldingRegisters {
		t.Errorf("Function = 0x%02X, want 0x03", packets[0].Function)
	}
}

func TestExtractModbusFromPCAP_ExceptionResponse(t *testing.T) {
	frame := buildModbusExceptionFrame(7, 1, modbus.FcReadHoldingRegisters, modbus.ExceptionIllegalDataAddress)
	// Exception comes from server (port 502 → client).
	packet := buildModbusTCPPacket(t, "10.0.0.2", "10.0.0.1", 502, 12000, frame)
	pcapPath := writeENIPPCAP(t, packet)

	packets, err := ExtractModbusFromPCAP(pcapPath)
	skipIfNoPcap(t, err)
	if err != nil {
		t.Fatalf("ExtractModbusFromPCAP: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	pkt := packets[0]
	if !pkt.IsException {
		t.Error("expected IsException=true")
	}
	if pkt.IsRequest {
		t.Error("expected IsRequest=false for server→client")
	}
	if pkt.Function != (modbus.FcReadHoldingRegisters | 0x80) {
		t.Errorf("Function = 0x%02X, want 0x83", pkt.Function)
	}
}

func TestExtractModbusFromPCAP_DirectionDetection(t *testing.T) {
	reqData := buildReadHoldingRegistersData(0, 1)
	reqFrame := buildModbusRequestFrame(1, 1, modbus.FcReadHoldingRegisters, reqData)

	// Request: client (port 12000) → server (port 502)
	reqPkt := buildModbusTCPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 502, reqFrame)

	// Response: server (port 502) → client (port 12000)
	respFrame := modbus.EncodeResponseTCP(modbus.Response{
		TransactionID: 1,
		UnitID:        1,
		Function:      modbus.FcReadHoldingRegisters,
		Data:          []byte{0x02, 0x00, 0x64}, // byte count + data
	})
	respPkt := buildModbusTCPPacket(t, "10.0.0.2", "10.0.0.1", 502, 12000, respFrame)

	pcapPath := writeENIPPCAP(t, reqPkt, respPkt)

	packets, err := ExtractModbusFromPCAP(pcapPath)
	skipIfNoPcap(t, err)
	if err != nil {
		t.Fatalf("ExtractModbusFromPCAP: %v", err)
	}
	if len(packets) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(packets))
	}
	if !packets[0].IsRequest {
		t.Error("pkt0 should be request")
	}
	if packets[1].IsRequest {
		t.Error("pkt1 should be response")
	}
}
