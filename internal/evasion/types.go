package evasion

// DPI evasion techniques for testing stateful industrial protocol inspection.
//
// Each technique manipulates the network or application layer to confuse
// deep packet inspection engines while maintaining protocol correctness
// from the endpoint's perspective.
//
// Techniques:
//   - TCP segmentation: split CIP payloads across TCP segment boundaries
//   - IP fragmentation: fragment IP datagrams (requires elevated privileges)
//   - Connection fuzzing: out-of-order state transitions, duplicate sessions
//   - Protocol anomalies: structurally valid but semantically unusual packets
//   - Timing evasion: slow-rate injection, variable inter-packet delays

import "time"

// Technique identifies a DPI evasion technique.
type Technique string

const (
	TechniqueTCPSegment    Technique = "tcp_segment"
	TechniqueIPFragment    Technique = "ip_fragment"
	TechniqueConnFuzz      Technique = "connection_fuzz"
	TechniqueAnomaly       Technique = "anomaly"
	TechniqueTiming        Technique = "timing"
)

// SplitPoint defines where to split an ENIP/CIP payload across TCP segments.
type SplitPoint string

const (
	// SplitMidENIPHeader splits inside the 24-byte ENIP header.
	SplitMidENIPHeader SplitPoint = "mid_enip_header"
	// SplitBetweenENIPCPF splits between ENIP header and CPF items.
	SplitBetweenENIPCPF SplitPoint = "between_enip_cpf"
	// SplitMidCIPPath splits inside the CIP EPATH.
	SplitMidCIPPath SplitPoint = "mid_cip_path"
	// SplitMidCIPPayload splits inside the CIP service data.
	SplitMidCIPPayload SplitPoint = "mid_cip_payload"
	// SplitEveryNBytes splits at fixed N-byte intervals.
	SplitEveryNBytes SplitPoint = "every_n_bytes"
)

// TCPSegmentConfig configures TCP segmentation evasion.
type TCPSegmentConfig struct {
	SplitPoint     SplitPoint    // Where to split
	SplitOffset    int           // Byte offset for fixed splits (SplitEveryNBytes)
	InterSegDelay  time.Duration // Delay between segments (0 = no delay)
	MaxSegmentSize int           // Maximum segment size (0 = default TCP MSS)
}

// IPFragmentConfig configures IP-layer fragmentation evasion.
type IPFragmentConfig struct {
	FragmentSize  int  // Fragment size in bytes (e.g., 8 for minimum)
	Overlap       bool // Send overlapping fragments
	DecoyCount    int  // Number of decoy fragments to inject
	Reverse       bool // Send fragments in reverse order
}

// ConnFuzzConfig configures connection state machine fuzzing.
type ConnFuzzConfig struct {
	// SkipRegisterSession sends CIP data without RegisterSession.
	SkipRegisterSession bool
	// DuplicateSessionID reuses an existing session ID.
	DuplicateSessionID bool
	// ConflictingConnectionID sends ForwardOpen with a connection ID
	// that conflicts with an existing connection.
	ConflictingConnectionID bool
	// OutOfOrderTransitions sends state machine events out of order
	// (e.g., ForwardClose before ForwardOpen).
	OutOfOrderTransitions bool
	// StaleSessionReuse uses a previously closed session handle.
	StaleSessionReuse bool
}

// AnomalyConfig configures protocol anomaly injection.
type AnomalyConfig struct {
	// ZeroLengthPayload sends requests with zero-length CIP payloads.
	ZeroLengthPayload bool
	// MaxLengthEPATH sends requests with maximum-length EPATH segments.
	MaxLengthEPATH bool
	// ReservedServiceCodes uses reserved/unassigned CIP service codes.
	ReservedServiceCodes bool
	// UnusualCPFItems uses unusual but valid CPF item type IDs.
	UnusualCPFItems bool
	// MaxConnectionParams uses extreme values in ForwardOpen parameters.
	MaxConnectionParams bool
}

// TimingConfig configures timing-based evasion.
type TimingConfig struct {
	// SlowRate sends one byte per interval.
	SlowRate bool
	// SlowRateInterval is the delay between individual bytes.
	SlowRateInterval time.Duration
	// VariableTiming randomizes inter-packet delays.
	VariableTiming bool
	// MinDelay is the minimum inter-packet delay for variable timing.
	MinDelay time.Duration
	// MaxDelay is the maximum inter-packet delay for variable timing.
	MaxDelay time.Duration
	// KeepaliveAbuse sends TCP keepalive-like packets at high frequency.
	KeepaliveAbuse bool
	// KeepaliveInterval is the keepalive packet interval.
	KeepaliveInterval time.Duration
}

// EvasionResult records the outcome of an evasion attempt.
type EvasionResult struct {
	Technique   Technique
	Description string
	Success     bool   // True if the evasion was delivered successfully
	DPIDetected bool   // True if the DPI engine still detected the traffic
	Error       string // Non-empty on failure
	SegmentsSent int   // Number of TCP segments or IP fragments sent
	TotalBytes  int    // Total bytes transmitted
}
