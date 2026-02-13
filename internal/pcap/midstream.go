package pcap

// Midstream reconstruction engine.
//
// Infers session and connection parameters from observed ENIP traffic when
// the capture starts after initial handshakes (RegisterSession, ForwardOpen).
//
// Algorithm:
// 1. Session discovery: scan ENIP packets, extract session IDs. Sessions with
//    RegisterSession observed = full confidence. Sessions with only
//    SendRRData/SendUnitData = midstream-inferred.
// 2. Connection discovery: for SendUnitData packets, extract connection ID
//    from CPF Connected Address item. Build per-connection histograms.
// 3. Parameter inference: payload size mode = connection data size,
//    inter-packet interval median = estimated RPI, sequence number
//    monotonicity = transport class.
// 4. Protocol detection: check connected data payloads for PCCC function
//    codes and DH+ frame structure.

import (
	"encoding/binary"
	"math"
	"sort"
	"time"

	"github.com/tonylturner/cipdip/internal/dhplus"
	"github.com/tonylturner/cipdip/internal/enip"
	"github.com/tonylturner/cipdip/internal/pccc"
)

// SessionConfidence indicates how the session was observed.
type SessionConfidence int

const (
	SessionFull      SessionConfidence = iota // RegisterSession observed
	SessionMidstream                          // Inferred from data traffic
)

// TransportClass is the inferred CIP transport class.
type TransportClass int

const (
	TransportClassUnknown TransportClass = 0
	TransportClass1       TransportClass = 1 // Unsequenced (UDP I/O)
	TransportClass3       TransportClass = 3 // Sequenced (TCP connected)
)

// ProtocolHint identifies the payload protocol detected in connected data.
type ProtocolHint int

const (
	ProtocolCIP     ProtocolHint = iota // Standard CIP
	ProtocolPCCC                        // PCCC over CIP
	ProtocolDHPlus                      // DH+ over ENIP
	ProtocolENIP                        // EtherNet/IP encapsulation
	ProtocolModbus                      // Modbus TCP/RTU/ASCII
	ProtocolUnknown
)

// InferredSession represents a reconstructed ENIP session.
type InferredSession struct {
	SessionID  uint32
	Confidence SessionConfidence
	FirstSeen  time.Time
	LastSeen   time.Time
	PacketCount int
	ClientIP   string
	ServerIP   string
}

// InferredConnection represents a reconstructed CIP connection.
type InferredConnection struct {
	ConnectionID      uint32
	SessionID         uint32
	Confidence        float64 // 0.0-1.0
	FirstSeen         time.Time
	LastSeen          time.Time
	PacketCount       int
	TransportClass    TransportClass
	EstimatedRPI      time.Duration // Estimated Requested Packet Interval
	EstimatedDataSize int           // Mode of payload size histogram
	ProtocolHint      ProtocolHint
	PayloadSizes      map[int]int    // Size histogram
	PCCCFunctions     map[uint8]int  // PCCC function code distribution
	DHPlusCommands    map[uint8]int  // DH+ command distribution
}

// MidstreamResult contains the full reconstruction output.
type MidstreamResult struct {
	Sessions    map[uint32]*InferredSession
	Connections map[uint32]*InferredConnection
	TotalPackets int
}

// ReconstructMidstream analyzes a set of ENIP packets and reconstructs
// session and connection state, including for traffic captured midstream.
func ReconstructMidstream(packets []ENIPPacket) *MidstreamResult {
	result := &MidstreamResult{
		Sessions:    make(map[uint32]*InferredSession),
		Connections: make(map[uint32]*InferredConnection),
		TotalPackets: len(packets),
	}

	// Track per-connection timestamps for RPI estimation
	connTimestamps := make(map[uint32][]time.Time)
	// Track sequence numbers for transport class inference
	connSequences := make(map[uint32][]uint16)

	for _, pkt := range packets {
		// Phase 1: Session discovery
		result.processSession(pkt)

		// Phase 2: Connection discovery from SendUnitData
		if pkt.Command == enip.ENIPCommandSendUnitData && len(pkt.Data) >= 6 {
			connID, cipData := extractConnectedData(pkt.Data)
			if connID != 0 {
				conn := result.ensureConnection(connID, pkt)
				conn.PacketCount++
				conn.LastSeen = pkt.Timestamp

				if len(cipData) > 0 {
					conn.recordPayloadSize(len(cipData))
					connTimestamps[connID] = append(connTimestamps[connID], pkt.Timestamp)

					// Extract sequence number from connected data header
					if len(cipData) >= 2 {
						seqNum := binary.LittleEndian.Uint16(cipData[:2])
						connSequences[connID] = append(connSequences[connID], seqNum)
					}

					// Phase 4: Protocol detection
					detectProtocol(conn, cipData)
				}
			}
		}
	}

	// Phase 3: Parameter inference
	for connID, conn := range result.Connections {
		// Estimate RPI from inter-packet intervals
		if ts, ok := connTimestamps[connID]; ok && len(ts) >= 2 {
			conn.EstimatedRPI = estimateRPI(ts)
		}

		// Infer transport class from sequence numbers
		if seqs, ok := connSequences[connID]; ok && len(seqs) >= 3 {
			conn.TransportClass = inferTransportClass(seqs)
		}

		// Compute data size mode
		conn.EstimatedDataSize = payloadSizeMode(conn.PayloadSizes)

		// Compute confidence
		conn.Confidence = computeConnectionConfidence(conn, result.Sessions)
	}

	return result
}

// processSession tracks session state from ENIP packets.
func (r *MidstreamResult) processSession(pkt ENIPPacket) {
	if pkt.SessionID == 0 {
		return
	}

	sess, exists := r.Sessions[pkt.SessionID]
	if !exists {
		confidence := SessionMidstream
		if pkt.Command == enip.ENIPCommandRegisterSession {
			confidence = SessionFull
		}
		sess = &InferredSession{
			SessionID:  pkt.SessionID,
			Confidence: confidence,
			FirstSeen:  pkt.Timestamp,
			LastSeen:   pkt.Timestamp,
		}
		r.Sessions[pkt.SessionID] = sess
	}

	sess.PacketCount++
	if pkt.Timestamp.After(sess.LastSeen) {
		sess.LastSeen = pkt.Timestamp
	}
	if pkt.Command == enip.ENIPCommandRegisterSession && sess.Confidence != SessionFull {
		sess.Confidence = SessionFull
	}

	// Track client/server IPs
	if pkt.IsRequest {
		sess.ClientIP = pkt.SrcIP
		sess.ServerIP = pkt.DstIP
	} else {
		sess.ClientIP = pkt.DstIP
		sess.ServerIP = pkt.SrcIP
	}
}

// ensureConnection creates or returns an existing connection.
func (r *MidstreamResult) ensureConnection(connID uint32, pkt ENIPPacket) *InferredConnection {
	conn, exists := r.Connections[connID]
	if !exists {
		conn = &InferredConnection{
			ConnectionID:   connID,
			SessionID:      pkt.SessionID,
			FirstSeen:      pkt.Timestamp,
			LastSeen:       pkt.Timestamp,
			PayloadSizes:   make(map[int]int),
			PCCCFunctions:  make(map[uint8]int),
			DHPlusCommands: make(map[uint8]int),
		}
		r.Connections[connID] = conn
	}
	return conn
}

// recordPayloadSize adds to the payload size histogram.
func (c *InferredConnection) recordPayloadSize(size int) {
	c.PayloadSizes[size]++
}

// extractConnectedData parses SendUnitData payload to extract connection ID
// and connected CIP data from CPF items.
func extractConnectedData(data []byte) (uint32, []byte) {
	if len(data) < 6 {
		return 0, nil
	}

	// Skip interface handle (4 bytes) + timeout (2 bytes)
	payload := data[6:]
	items, err := enip.ParseCPFItems(payload)
	if err != nil {
		return 0, nil
	}

	var connID uint32
	var cipData []byte

	for _, item := range items {
		switch item.TypeID {
		case enip.CPFItemConnectedAddress:
			if len(item.Data) >= 4 {
				connID = binary.LittleEndian.Uint32(item.Data[:4])
			}
		case enip.CPFItemConnectedData:
			cipData = item.Data
		}
	}

	return connID, cipData
}

// detectProtocol performs heuristic protocol detection on connected data.
func detectProtocol(conn *InferredConnection, data []byte) {
	// Skip 2-byte sequence number if present (class 3 transport)
	payload := data
	if len(payload) > 2 {
		payload = payload[2:] // Skip sequence number
	}

	// Try PCCC detection
	if pccc.IsPCCCPayload(payload) {
		conn.ProtocolHint = ProtocolPCCC
		if len(payload) >= 5 && pccc.Command(payload[0]) == pccc.CmdExtended {
			conn.PCCCFunctions[payload[4]]++
		}
		return
	}

	// Try DH+ detection
	result := dhplus.CheckPayload(payload)
	if result.IsDHPlus {
		conn.ProtocolHint = ProtocolDHPlus
		if len(payload) >= 3 {
			conn.DHPlusCommands[payload[2]]++
		}
		return
	}

	// If we haven't determined protocol yet and this looks like standard CIP,
	// mark it (or leave as unknown)
	if conn.ProtocolHint == ProtocolUnknown && len(payload) >= 2 {
		// CIP service code in range 0x01-0x63 (common services)
		if payload[0] >= 0x01 && payload[0] <= 0x63 {
			conn.ProtocolHint = ProtocolCIP
		}
	}
}

// estimateRPI computes the median inter-packet interval.
func estimateRPI(timestamps []time.Time) time.Duration {
	if len(timestamps) < 2 {
		return 0
	}

	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i].Before(timestamps[j])
	})

	intervals := make([]time.Duration, 0, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		d := timestamps[i].Sub(timestamps[i-1])
		if d > 0 {
			intervals = append(intervals, d)
		}
	}

	if len(intervals) == 0 {
		return 0
	}

	sort.Slice(intervals, func(i, j int) bool {
		return intervals[i] < intervals[j]
	})

	return intervals[len(intervals)/2] // Median
}

// inferTransportClass determines the transport class from sequence numbers.
func inferTransportClass(seqs []uint16) TransportClass {
	if len(seqs) < 3 {
		return TransportClassUnknown
	}

	// Check for monotonic increasing sequences (class 3)
	monotonic := 0
	for i := 1; i < len(seqs); i++ {
		diff := seqs[i] - seqs[i-1]
		if diff == 1 || (seqs[i-1] == 0xFFFF && seqs[i] == 0) {
			monotonic++
		}
	}

	// If >80% of transitions are monotonic, likely class 3
	if float64(monotonic)/float64(len(seqs)-1) > 0.8 {
		return TransportClass3
	}

	// Otherwise assume class 1 (unsequenced)
	return TransportClass1
}

// payloadSizeMode returns the most common payload size.
func payloadSizeMode(histogram map[int]int) int {
	maxCount := 0
	modeSize := 0
	for size, count := range histogram {
		if count > maxCount {
			maxCount = count
			modeSize = size
		}
	}
	return modeSize
}

// computeConnectionConfidence computes an overall confidence score.
func computeConnectionConfidence(conn *InferredConnection, sessions map[uint32]*InferredSession) float64 {
	// Base: session confidence
	var sessionScore float64
	if sess, ok := sessions[conn.SessionID]; ok && sess.Confidence == SessionFull {
		sessionScore = 0.3
	} else {
		sessionScore = 0.1
	}

	// Packet count score
	var countScore float64
	switch {
	case conn.PacketCount >= 100:
		countScore = 0.3
	case conn.PacketCount >= 10:
		countScore = 0.2
	case conn.PacketCount >= 3:
		countScore = 0.1
	default:
		countScore = 0.05
	}

	// Consistency score: how concentrated is the payload size histogram?
	var consistencyScore float64
	if conn.EstimatedDataSize > 0 && len(conn.PayloadSizes) > 0 {
		modeCount := conn.PayloadSizes[conn.EstimatedDataSize]
		total := 0
		for _, c := range conn.PayloadSizes {
			total += c
		}
		if total > 0 {
			consistencyScore = float64(modeCount) / float64(total) * 0.2
		}
	}

	// Protocol detection score
	var protocolScore float64
	if conn.ProtocolHint != ProtocolUnknown {
		protocolScore = 0.2
	}

	confidence := sessionScore + countScore + consistencyScore + protocolScore
	return math.Min(confidence, 1.0)
}

// String returns a human-readable label for the transport class.
func (tc TransportClass) String() string {
	switch tc {
	case TransportClass1:
		return "Class_1"
	case TransportClass3:
		return "Class_3"
	default:
		return "Unknown"
	}
}

// String returns a human-readable label for the protocol hint.
func (ph ProtocolHint) String() string {
	switch ph {
	case ProtocolCIP:
		return "CIP"
	case ProtocolPCCC:
		return "PCCC"
	case ProtocolDHPlus:
		return "DH+"
	case ProtocolENIP:
		return "ENIP"
	case ProtocolModbus:
		return "Modbus"
	default:
		return "Unknown"
	}
}

// String returns a human-readable label for the session confidence.
func (sc SessionConfidence) String() string {
	switch sc {
	case SessionFull:
		return "Full"
	case SessionMidstream:
		return "Midstream"
	default:
		return "Unknown"
	}
}
