package pcap

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/tturner/cipdip/internal/enip"
)

// buildSendUnitData constructs a synthetic SendUnitData ENIP packet
// with the given connection ID and connected data payload.
func buildSendUnitData(sessionID, connID uint32, cipData []byte, ts time.Time, srcIP, dstIP string) ENIPPacket {
	// Build CPF items manually:
	// Item count (2) + Connected Address (typeID=0x00A1, len=4, connID) + Connected Data (typeID=0x00B1, len, data)
	itemCount := make([]byte, 2)
	binary.LittleEndian.PutUint16(itemCount, 2)

	// Connected Address item
	addrItem := make([]byte, 8)
	binary.LittleEndian.PutUint16(addrItem[0:2], enip.CPFItemConnectedAddress)
	binary.LittleEndian.PutUint16(addrItem[2:4], 4)
	binary.LittleEndian.PutUint32(addrItem[4:8], connID)

	// Connected Data item
	dataItem := make([]byte, 4+len(cipData))
	binary.LittleEndian.PutUint16(dataItem[0:2], enip.CPFItemConnectedData)
	binary.LittleEndian.PutUint16(dataItem[2:4], uint16(len(cipData)))
	copy(dataItem[4:], cipData)

	// Interface handle (4) + timeout (2) + CPF
	data := make([]byte, 6)
	// Interface handle = 0, timeout = 0
	data = append(data, itemCount...)
	data = append(data, addrItem...)
	data = append(data, dataItem...)

	return ENIPPacket{
		Command:   enip.ENIPCommandSendUnitData,
		SessionID: sessionID,
		Data:      data,
		Timestamp: ts,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		IsRequest: true,
	}
}

func buildRegisterSession(sessionID uint32, ts time.Time) ENIPPacket {
	return ENIPPacket{
		Command:   enip.ENIPCommandRegisterSession,
		SessionID: sessionID,
		Timestamp: ts,
		IsRequest: true,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.50",
	}
}

func TestReconstructMidstreamSessionDiscovery(t *testing.T) {
	now := time.Now()

	packets := []ENIPPacket{
		buildRegisterSession(0x01, now),
		buildSendUnitData(0x01, 0xABCD, []byte{0x01, 0x00, 0x4C, 0x02}, now.Add(time.Second), "10.0.0.1", "10.0.0.50"),
		// Midstream session (no RegisterSession observed)
		buildSendUnitData(0x02, 0x1234, []byte{0x01, 0x00, 0x4C, 0x02}, now.Add(2*time.Second), "10.0.0.2", "10.0.0.50"),
	}

	result := ReconstructMidstream(packets)

	// Session 0x01 should be full confidence
	sess1, ok := result.Sessions[0x01]
	if !ok {
		t.Fatal("session 0x01 not found")
	}
	if sess1.Confidence != SessionFull {
		t.Errorf("session 0x01 confidence: got %v, want Full", sess1.Confidence)
	}

	// Session 0x02 should be midstream
	sess2, ok := result.Sessions[0x02]
	if !ok {
		t.Fatal("session 0x02 not found")
	}
	if sess2.Confidence != SessionMidstream {
		t.Errorf("session 0x02 confidence: got %v, want Midstream", sess2.Confidence)
	}
}

func TestReconstructMidstreamConnectionDiscovery(t *testing.T) {
	now := time.Now()

	// Generate 20 packets on connection 0xABCD with ~10ms intervals
	var packets []ENIPPacket
	for i := 0; i < 20; i++ {
		ts := now.Add(time.Duration(i) * 10 * time.Millisecond)
		// Sequence number + CIP service
		seqNum := uint16(i + 1)
		cipData := make([]byte, 10)
		binary.LittleEndian.PutUint16(cipData[0:2], seqNum)
		cipData[2] = 0x4C // Read Tag service
		cipData[3] = 0x02

		packets = append(packets, buildSendUnitData(0x01, 0xABCD, cipData, ts, "10.0.0.1", "10.0.0.50"))
	}

	result := ReconstructMidstream(packets)

	conn, ok := result.Connections[0xABCD]
	if !ok {
		t.Fatal("connection 0xABCD not found")
	}

	if conn.PacketCount != 20 {
		t.Errorf("packet count: got %d, want 20", conn.PacketCount)
	}

	// Should infer class 3 from monotonic sequences
	if conn.TransportClass != TransportClass3 {
		t.Errorf("transport class: got %v, want Class_3", conn.TransportClass)
	}

	// RPI should be approximately 10ms
	if conn.EstimatedRPI < 5*time.Millisecond || conn.EstimatedRPI > 15*time.Millisecond {
		t.Errorf("estimated RPI: got %v, want ~10ms", conn.EstimatedRPI)
	}

	// Data size mode should be 10
	if conn.EstimatedDataSize != 10 {
		t.Errorf("estimated data size: got %d, want 10", conn.EstimatedDataSize)
	}

	// Confidence should be reasonable
	if conn.Confidence < 0.3 {
		t.Errorf("confidence: got %f, want >= 0.3", conn.Confidence)
	}
}

func TestReconstructMidstreamPCCCDetection(t *testing.T) {
	now := time.Now()

	// PCCC typed read: CMD=0x0F, STS=0x00, TNS=0x0001, FNC=0x68, data...
	pcccPayload := []byte{
		0x01, 0x00, // Sequence number
		0x0F, 0x00, 0x01, 0x00, 0x68, // PCCC: CMD, STS, TNS(2), FNC
		0x02, 0x07, 0x89, 0x00, // Read N7:0, 2 bytes
	}

	packets := []ENIPPacket{
		buildSendUnitData(0x01, 0xBBBB, pcccPayload, now, "10.0.0.1", "10.0.0.50"),
		buildSendUnitData(0x01, 0xBBBB, pcccPayload, now.Add(100*time.Millisecond), "10.0.0.1", "10.0.0.50"),
		buildSendUnitData(0x01, 0xBBBB, pcccPayload, now.Add(200*time.Millisecond), "10.0.0.1", "10.0.0.50"),
	}

	result := ReconstructMidstream(packets)

	conn, ok := result.Connections[0xBBBB]
	if !ok {
		t.Fatal("connection 0xBBBB not found")
	}

	if conn.ProtocolHint != ProtocolPCCC {
		t.Errorf("protocol hint: got %v, want PCCC", conn.ProtocolHint)
	}
}

func TestReconstructMidstreamDHPlusDetection(t *testing.T) {
	now := time.Now()

	// DH+ frame: DST=0x20(node 32), SRC=0x10(node 16), CMD=0x68(typed read),
	// STS=0x00, TNS=0x0001.
	// Node addresses >0x0F avoid collision with PCCC command codes.
	dhplusPayload := []byte{
		0x01, 0x00, // Sequence number
		0x20, 0x10, 0x68, 0x00, 0x01, 0x00, // DH+ header
		0x02, 0x07, 0x89, 0x00, // Data
	}

	packets := []ENIPPacket{
		buildSendUnitData(0x01, 0xCCCC, dhplusPayload, now, "10.0.0.1", "10.0.0.50"),
	}

	result := ReconstructMidstream(packets)

	conn, ok := result.Connections[0xCCCC]
	if !ok {
		t.Fatal("connection 0xCCCC not found")
	}

	if conn.ProtocolHint != ProtocolDHPlus {
		t.Errorf("protocol hint: got %v, want DH+", conn.ProtocolHint)
	}
}

func TestReconstructMidstreamEmptyInput(t *testing.T) {
	result := ReconstructMidstream(nil)
	if len(result.Sessions) != 0 {
		t.Errorf("sessions: got %d, want 0", len(result.Sessions))
	}
	if len(result.Connections) != 0 {
		t.Errorf("connections: got %d, want 0", len(result.Connections))
	}
}

func TestEstimateRPI(t *testing.T) {
	now := time.Now()
	timestamps := []time.Time{
		now,
		now.Add(10 * time.Millisecond),
		now.Add(20 * time.Millisecond),
		now.Add(30 * time.Millisecond),
		now.Add(40 * time.Millisecond),
	}

	rpi := estimateRPI(timestamps)
	if rpi < 9*time.Millisecond || rpi > 11*time.Millisecond {
		t.Errorf("RPI: got %v, want ~10ms", rpi)
	}
}

func TestEstimateRPITooFew(t *testing.T) {
	now := time.Now()
	rpi := estimateRPI([]time.Time{now})
	if rpi != 0 {
		t.Errorf("RPI with 1 timestamp: got %v, want 0", rpi)
	}
}

func TestInferTransportClass(t *testing.T) {
	// Monotonic sequences -> Class 3
	monotonic := []uint16{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if tc := inferTransportClass(monotonic); tc != TransportClass3 {
		t.Errorf("monotonic: got %v, want Class_3", tc)
	}

	// Random sequences -> Class 1
	random := []uint16{100, 5, 300, 2, 700, 50, 1000}
	if tc := inferTransportClass(random); tc != TransportClass1 {
		t.Errorf("random: got %v, want Class_1", tc)
	}

	// Too few
	if tc := inferTransportClass([]uint16{1, 2}); tc != TransportClassUnknown {
		t.Errorf("too few: got %v, want Unknown", tc)
	}

	// Wrap-around at 0xFFFF -> still Class 3
	wraparound := []uint16{0xFFFD, 0xFFFE, 0xFFFF, 0x0000, 0x0001, 0x0002}
	if tc := inferTransportClass(wraparound); tc != TransportClass3 {
		t.Errorf("wraparound: got %v, want Class_3", tc)
	}
}

func TestPayloadSizeMode(t *testing.T) {
	histogram := map[int]int{
		10: 50,
		12: 3,
		8:  1,
	}
	if mode := payloadSizeMode(histogram); mode != 10 {
		t.Errorf("mode: got %d, want 10", mode)
	}
}

func TestSessionConfidenceString(t *testing.T) {
	if s := SessionFull.String(); s != "Full" {
		t.Errorf("SessionFull.String() = %q, want %q", s, "Full")
	}
	if s := SessionMidstream.String(); s != "Midstream" {
		t.Errorf("SessionMidstream.String() = %q, want %q", s, "Midstream")
	}
}

func TestTransportClassString(t *testing.T) {
	if s := TransportClass3.String(); s != "Class_3" {
		t.Errorf("TransportClass3.String() = %q, want %q", s, "Class_3")
	}
}

func TestProtocolHintString(t *testing.T) {
	if s := ProtocolPCCC.String(); s != "PCCC" {
		t.Errorf("ProtocolPCCC.String() = %q, want %q", s, "PCCC")
	}
	if s := ProtocolDHPlus.String(); s != "DH+" {
		t.Errorf("ProtocolDHPlus.String() = %q, want %q", s, "DH+")
	}
}
