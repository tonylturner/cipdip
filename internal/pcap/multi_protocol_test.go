package pcap

import (
	"strings"
	"testing"

	"github.com/tonylturner/cipdip/internal/enip"
	"github.com/tonylturner/cipdip/internal/modbus"
)

func skipIfNoPcapLib(t *testing.T, err error) {
	t.Helper()
	if err != nil && (strings.Contains(err.Error(), "wpcap.dll") || strings.Contains(err.Error(), "couldn't load")) {
		t.Skip("Skipping: pcap library not available")
	}
}

func TestExtractMultiProtocol_MixedENIPModbus(t *testing.T) {
	// Build one ENIP packet (port 44818) and one Modbus packet (port 502).
	enipPayload := enip.BuildRegisterSession([8]byte{0x01})
	enipPkt := buildENIPTCPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 44818, enipPayload)

	modbusFrame := buildModbusRequestFrame(1, 1, modbus.FcReadHoldingRegisters, buildReadHoldingRegistersData(0, 10))
	modbusPkt := buildModbusTCPPacket(t, "10.0.0.3", "10.0.0.4", 13000, 502, modbusFrame)

	pcapPath := writeENIPPCAP(t, enipPkt, modbusPkt)

	result, err := ExtractMultiProtocol(pcapPath)
	skipIfNoPcapLib(t, err)
	if err != nil {
		t.Fatalf("ExtractMultiProtocol: %v", err)
	}
	if result.ENIPCount != 1 {
		t.Errorf("ENIPCount = %d, want 1", result.ENIPCount)
	}
	if result.ModbusCount != 1 {
		t.Errorf("ModbusCount = %d, want 1", result.ModbusCount)
	}
	if len(result.Messages) != 2 {
		t.Fatalf("Messages = %d, want 2", len(result.Messages))
	}
	// Messages should be sorted by timestamp.
	if result.Messages[0].Timestamp.After(result.Messages[1].Timestamp) {
		t.Error("messages not sorted by timestamp")
	}
	// First message should be ENIP (earlier timestamp).
	if result.Messages[0].Protocol != ProtocolENIP {
		t.Errorf("msg0 protocol = %v, want ENIP", result.Messages[0].Protocol)
	}
	if result.Messages[1].Protocol != ProtocolModbus {
		t.Errorf("msg1 protocol = %v, want Modbus", result.Messages[1].Protocol)
	}
}

func TestExtractMultiProtocol_OnlyENIP(t *testing.T) {
	payload := enip.BuildRegisterSession([8]byte{0x01})
	pkt1 := buildENIPTCPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 44818, payload)
	pkt2 := buildENIPTCPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 44818, payload)
	pcapPath := writeENIPPCAP(t, pkt1, pkt2)

	result, err := ExtractMultiProtocol(pcapPath)
	skipIfNoPcapLib(t, err)
	if err != nil {
		t.Fatalf("ExtractMultiProtocol: %v", err)
	}
	if result.ENIPCount != 2 {
		t.Errorf("ENIPCount = %d, want 2", result.ENIPCount)
	}
	if result.ModbusCount != 0 {
		t.Errorf("ModbusCount = %d, want 0", result.ModbusCount)
	}
	if !result.HasProtocol(ProtocolENIP) {
		t.Error("HasProtocol(ENIP) should be true")
	}
	if result.HasProtocol(ProtocolModbus) {
		t.Error("HasProtocol(Modbus) should be false")
	}
}

func TestExtractMultiProtocol_OnlyModbus(t *testing.T) {
	frame1 := buildModbusRequestFrame(1, 1, modbus.FcReadCoils, buildReadHoldingRegistersData(0, 8))
	frame2 := buildModbusRequestFrame(2, 1, modbus.FcReadHoldingRegisters, buildReadHoldingRegistersData(0, 5))
	pkt1 := buildModbusTCPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 502, frame1)
	pkt2 := buildModbusTCPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 502, frame2)
	pcapPath := writeENIPPCAP(t, pkt1, pkt2)

	result, err := ExtractMultiProtocol(pcapPath)
	skipIfNoPcapLib(t, err)
	if err != nil {
		t.Fatalf("ExtractMultiProtocol: %v", err)
	}
	if result.ENIPCount != 0 {
		t.Errorf("ENIPCount = %d, want 0", result.ENIPCount)
	}
	if result.ModbusCount != 2 {
		t.Errorf("ModbusCount = %d, want 2", result.ModbusCount)
	}
}

func TestMultiProtocolResult_ProtocolSummary(t *testing.T) {
	r := &MultiProtocolResult{
		ENIPCount:    3,
		ModbusCount:  2,
		DHPlusCount:  1,
		UnknownCount: 0,
		TotalPackets: 6,
	}
	summary := r.ProtocolSummary()
	if summary == "" {
		t.Fatal("empty summary")
	}
	// Verify it contains the counts.
	expected := "ENIP: 3, Modbus: 2, DH+: 1, Unknown: 0 (total packets: 6)"
	if summary != expected {
		t.Errorf("summary = %q, want %q", summary, expected)
	}
}

func TestMultiProtocolResult_FilterByProtocol(t *testing.T) {
	r := &MultiProtocolResult{
		Messages: []ProtocolMessage{
			{Protocol: ProtocolENIP, Description: "ENIP1"},
			{Protocol: ProtocolModbus, Description: "Modbus1"},
			{Protocol: ProtocolENIP, Description: "ENIP2"},
			{Protocol: ProtocolModbus, Description: "Modbus2"},
			{Protocol: ProtocolDHPlus, Description: "DH+1"},
		},
		ENIPCount:   2,
		ModbusCount: 2,
		DHPlusCount: 1,
	}

	enipMsgs := r.FilterByProtocol(ProtocolENIP)
	if len(enipMsgs) != 2 {
		t.Errorf("ENIP filter count = %d, want 2", len(enipMsgs))
	}
	modbusMsgs := r.FilterByProtocol(ProtocolModbus)
	if len(modbusMsgs) != 2 {
		t.Errorf("Modbus filter count = %d, want 2", len(modbusMsgs))
	}
	dhpMsgs := r.FilterByProtocol(ProtocolDHPlus)
	if len(dhpMsgs) != 1 {
		t.Errorf("DH+ filter count = %d, want 1", len(dhpMsgs))
	}
	unknownMsgs := r.FilterByProtocol(ProtocolUnknown)
	if len(unknownMsgs) != 0 {
		t.Errorf("Unknown filter count = %d, want 0", len(unknownMsgs))
	}
}

func TestMultiProtocolResult_ModbusFunctionDistribution(t *testing.T) {
	r := &MultiProtocolResult{
		Messages: []ProtocolMessage{
			{Protocol: ProtocolModbus, Modbus: &ModbusPacket{Function: modbus.FcReadCoils}},
			{Protocol: ProtocolModbus, Modbus: &ModbusPacket{Function: modbus.FcReadHoldingRegisters}},
			{Protocol: ProtocolModbus, Modbus: &ModbusPacket{Function: modbus.FcReadHoldingRegisters}},
			{Protocol: ProtocolModbus, Modbus: &ModbusPacket{Function: modbus.FcReadHoldingRegisters | 0x80}}, // exception
			{Protocol: ProtocolENIP}, // should be ignored
		},
	}

	dist := r.ModbusFunctionDistribution()
	if dist[modbus.FcReadCoils] != 1 {
		t.Errorf("FC1 count = %d, want 1", dist[modbus.FcReadCoils])
	}
	// FC3 appears 3 times: 2 normal + 1 exception (0x83 & 0x7F = 0x03).
	if dist[modbus.FcReadHoldingRegisters] != 3 {
		t.Errorf("FC3 count = %d, want 3", dist[modbus.FcReadHoldingRegisters])
	}
	if len(dist) != 2 {
		t.Errorf("dist has %d entries, want 2", len(dist))
	}
}

func TestMultiProtocolResult_HasProtocol(t *testing.T) {
	r := &MultiProtocolResult{
		ENIPCount:   1,
		ModbusCount: 0,
		DHPlusCount: 0,
	}
	if !r.HasProtocol(ProtocolENIP) {
		t.Error("HasProtocol(ENIP) should be true")
	}
	if r.HasProtocol(ProtocolModbus) {
		t.Error("HasProtocol(Modbus) should be false")
	}
	if r.HasProtocol(ProtocolDHPlus) {
		t.Error("HasProtocol(DH+) should be false")
	}
	if r.HasProtocol(ProtocolUnknown) {
		t.Error("HasProtocol(Unknown) should be false")
	}
}

func TestMultiProtocolResult_PortSummary(t *testing.T) {
	enipPayload := enip.BuildRegisterSession([8]byte{0x01})
	enipPkt := buildENIPTCPPacket(t, "10.0.0.1", "10.0.0.2", 12000, 44818, enipPayload)

	modbusFrame := buildModbusRequestFrame(1, 1, modbus.FcReadCoils, buildReadHoldingRegistersData(0, 8))
	modbusPkt := buildModbusTCPPacket(t, "10.0.0.3", "10.0.0.4", 13000, 502, modbusFrame)

	pcapPath := writeENIPPCAP(t, enipPkt, modbusPkt)

	result, err := ExtractMultiProtocol(pcapPath)
	skipIfNoPcapLib(t, err)
	if err != nil {
		t.Fatalf("ExtractMultiProtocol: %v", err)
	}
	if result.PortSummary[44818] != 1 {
		t.Errorf("port 44818 count = %d, want 1", result.PortSummary[44818])
	}
	if result.PortSummary[502] != 1 {
		t.Errorf("port 502 count = %d, want 1", result.PortSummary[502])
	}
}
