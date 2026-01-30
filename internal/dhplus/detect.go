package dhplus

// Heuristic detection of DH+ frames in raw traffic.
//
// DH+ frames can appear as payloads within EtherNet/IP SendUnitData packets
// when a gateway (e.g., 1761-NET-ENI, 1770-KF2) bridges between Ethernet
// and DH+. These payloads will fail CIP parsing because they are not CIP
// messages.
//
// Detection heuristics:
// 1. Both DST and SRC nodes must be 0-63
// 2. Command byte should be a known DH+ command
// 3. Status byte should be 0 (request) or a known error code
// 4. Consistency across multiple packets in the same stream
//
// A single packet match is low confidence; 3+ consistent matches is high.

// Confidence represents the detection confidence level.
type Confidence float64

const (
	ConfidenceNone    Confidence = 0.0
	ConfidenceLow     Confidence = 0.3
	ConfidenceMedium  Confidence = 0.5
	ConfidenceHigh    Confidence = 0.8
	ConfidenceCertain Confidence = 1.0
)

// DetectionResult holds the outcome of a DH+ detection attempt.
type DetectionResult struct {
	IsDHPlus     bool
	Confidence   Confidence
	Frame        Frame
	Reason       string
	CommandStats map[CommandCode]int // Command distribution across analyzed payloads
}

// Detector performs heuristic DH+ detection on byte payloads.
type Detector struct {
	// Accumulated frame statistics for multi-packet analysis
	nodesSeen    map[uint8]int
	commandsSeen map[CommandCode]int
	tnsSeen      map[uint16]int
	totalChecked int
	validCount   int
}

// NewDetector creates a new DH+ heuristic detector.
func NewDetector() *Detector {
	return &Detector{
		nodesSeen:    make(map[uint8]int),
		commandsSeen: make(map[CommandCode]int),
		tnsSeen:      make(map[uint16]int),
	}
}

// CheckPayload tests a single payload for DH+ characteristics.
// This is stateless - it only looks at this one payload.
func CheckPayload(data []byte) DetectionResult {
	if len(data) < HeaderSize {
		return DetectionResult{Reason: "payload too short for DH+ frame"}
	}

	dst := data[0]
	src := data[1]
	cmd := CommandCode(data[2])
	sts := data[3]

	// Check node address range
	if dst > MaxNodeAddress {
		return DetectionResult{Reason: "destination node out of DH+ range"}
	}
	if src > MaxNodeAddress {
		return DetectionResult{Reason: "source node out of DH+ range"}
	}

	// Source and destination shouldn't be the same
	if dst == src {
		return DetectionResult{Reason: "source equals destination"}
	}

	// Check command byte
	if !isKnownCommand(cmd) {
		return DetectionResult{Reason: "unknown DH+ command byte"}
	}

	// Status check: requests should be 0, responses should be valid
	if sts != 0 && !isKnownStatus(sts) {
		return DetectionResult{Reason: "unknown DH+ status byte"}
	}

	frame, err := DecodeFrame(data)
	if err != nil {
		return DetectionResult{Reason: "frame decode failed"}
	}

	return DetectionResult{
		IsDHPlus:   true,
		Confidence: ConfidenceLow, // Single packet = low confidence
		Frame:      frame,
		Reason:     "valid DH+ frame structure",
	}
}

// Analyze accumulates a payload and returns a detection result with
// confidence based on the consistency of all payloads seen so far.
func (d *Detector) Analyze(data []byte) DetectionResult {
	d.totalChecked++

	result := CheckPayload(data)
	if !result.IsDHPlus {
		return result
	}

	d.validCount++
	d.nodesSeen[result.Frame.Dst]++
	d.nodesSeen[result.Frame.Src]++
	d.commandsSeen[result.Frame.Command]++
	d.tnsSeen[result.Frame.TNS]++

	// Update confidence based on accumulated evidence
	result.Confidence = d.confidence()
	result.CommandStats = d.copyCommandStats()
	return result
}

// confidence computes the overall detection confidence.
func (d *Detector) confidence() Confidence {
	if d.validCount == 0 {
		return ConfidenceNone
	}

	// Basic count-based confidence
	switch {
	case d.validCount >= 10:
		// 10+ valid frames with consistent node addresses
		if d.hasConsistentNodes() {
			return ConfidenceHigh
		}
		return ConfidenceMedium
	case d.validCount >= 3:
		if d.hasConsistentNodes() {
			return ConfidenceMedium
		}
		return ConfidenceLow
	default:
		return ConfidenceLow
	}
}

// hasConsistentNodes returns true if the node addresses seen form a
// plausible DH+ network (small number of unique nodes, all in range).
func (d *Detector) hasConsistentNodes() bool {
	// A DH+ network typically has 2-64 nodes
	// If we see more than 20 unique nodes in a small sample, likely not DH+
	if d.totalChecked < 10 {
		return len(d.nodesSeen) <= 10
	}
	// For larger samples, node count should grow slowly relative to packets
	return len(d.nodesSeen) < d.totalChecked/2
}

// Stats returns the accumulated detection statistics.
func (d *Detector) Stats() (total, valid int, nodes map[uint8]int, commands map[CommandCode]int) {
	return d.totalChecked, d.validCount, d.copyNodeStats(), d.copyCommandStats()
}

func (d *Detector) copyCommandStats() map[CommandCode]int {
	out := make(map[CommandCode]int, len(d.commandsSeen))
	for k, v := range d.commandsSeen {
		out[k] = v
	}
	return out
}

func (d *Detector) copyNodeStats() map[uint8]int {
	out := make(map[uint8]int, len(d.nodesSeen))
	for k, v := range d.nodesSeen {
		out[k] = v
	}
	return out
}

// isKnownCommand returns true for recognized DH+ command bytes.
func isKnownCommand(c CommandCode) bool {
	switch c {
	case CmdProtectedWrite, CmdUnprotectedRead, CmdProtectedRead,
		CmdProtectedBitWrite, CmdUnprotectedWrite,
		CmdUploadAll, CmdUpload, CmdDownload, CmdDownloadAll,
		CmdTypedRead, CmdTypedWrite,
		CmdWordRangeRead, CmdWordRangeWrite,
		CmdDiagnosticStatus:
		return true
	default:
		return false
	}
}

// isKnownStatus returns true for known DH+ status/error codes.
func isKnownStatus(s uint8) bool {
	// Common DH+ error codes
	switch s {
	case 0x00: // Success
		return true
	case 0x01: // DST node out of range
		return true
	case 0x02: // Duplicate node detected
		return true
	case 0x03: // Not configured
		return true
	case 0x04: // Insufficient buffer
		return true
	case 0x05: // No response
		return true
	case 0x06: // Data too large
		return true
	case 0x07: // Disconnected
		return true
	case 0x10: // Illegal command
		return true
	case 0x20: // Remote error
		return true
	case 0x30: // Access denied
		return true
	case 0x40: // Reply too large
		return true
	case 0xF0: // Extended STS follows
		return true
	default:
		return false
	}
}
