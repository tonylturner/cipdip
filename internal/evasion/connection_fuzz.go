package evasion

// Connection state machine fuzzing for ENIP/CIP DPI evasion.
//
// CIP connections follow a well-defined state machine:
//   RegisterSession → SendRRData/SendUnitData → UnregisterSession
//   ForwardOpen → I/O data → ForwardClose
//
// Fuzzing these transitions tests whether DPI engines correctly
// handle out-of-order or invalid state transitions.

import (
	"encoding/binary"
)

// FuzzAction describes a single connection state fuzzing action.
type FuzzAction struct {
	Name        string
	Description string
	Payload     []byte // Raw ENIP frame to send
	ExpectError bool   // Whether the target should reject this
}

// BuildFuzzActions generates a sequence of fuzzing actions based on config.
func BuildFuzzActions(cfg ConnFuzzConfig) []FuzzAction {
	var actions []FuzzAction

	if cfg.SkipRegisterSession {
		actions = append(actions, buildSkipRegisterSessionAction())
	}
	if cfg.DuplicateSessionID {
		actions = append(actions, buildDuplicateSessionAction())
	}
	if cfg.ConflictingConnectionID {
		actions = append(actions, buildConflictingConnectionAction())
	}
	if cfg.OutOfOrderTransitions {
		actions = append(actions, buildOutOfOrderActions()...)
	}
	if cfg.StaleSessionReuse {
		actions = append(actions, buildStaleSessionAction())
	}

	return actions
}

// buildSkipRegisterSessionAction creates a SendRRData without prior RegisterSession.
func buildSkipRegisterSessionAction() FuzzAction {
	// Build a minimal SendRRData (0x006F) with a fabricated session ID.
	frame := buildENIPHeader(0x006F, 0xDEAD1234, nil)
	return FuzzAction{
		Name:        "skip_register_session",
		Description: "Send SendRRData without RegisterSession",
		Payload:     frame,
		ExpectError: true,
	}
}

// buildDuplicateSessionAction creates a RegisterSession that reuses
// a session ID that may already be in use.
func buildDuplicateSessionAction() FuzzAction {
	// RegisterSession request with protocol version and options.
	data := make([]byte, 4)
	binary.LittleEndian.PutUint16(data[0:2], 1) // Protocol version
	binary.LittleEndian.PutUint16(data[2:4], 0) // Options flags

	frame := buildENIPHeader(0x0065, 0, data)
	return FuzzAction{
		Name:        "duplicate_session_id",
		Description: "Register session that may duplicate existing ID",
		Payload:     frame,
		ExpectError: false, // Server assigns ID, but DPI may be confused
	}
}

// buildConflictingConnectionAction creates a ForwardOpen with a known connection ID.
func buildConflictingConnectionAction() FuzzAction {
	// This is a minimal ForwardOpen payload (not complete per spec,
	// but sufficient to test DPI reaction to connection ID conflicts).
	fwdOpen := make([]byte, 36)
	// Priority/Time_tick + Timeout_ticks
	fwdOpen[0] = 0x0A // Priority
	fwdOpen[1] = 0xE8 // Timeout ticks
	// O→T Connection ID (conflicting - uses 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(fwdOpen[2:6], 0xFFFFFFFF)
	// T→O Connection ID
	binary.LittleEndian.PutUint32(fwdOpen[6:10], 0xFFFFFFFE)
	// Connection serial number
	binary.LittleEndian.PutUint16(fwdOpen[10:12], 0xBEEF)

	return FuzzAction{
		Name:        "conflicting_connection_id",
		Description: "ForwardOpen with conflicting connection IDs (0xFFFFFFFF)",
		Payload:     fwdOpen,
		ExpectError: true,
	}
}

// buildOutOfOrderActions creates state transitions that violate the expected order.
func buildOutOfOrderActions() []FuzzAction {
	return []FuzzAction{
		{
			Name:        "forward_close_before_open",
			Description: "Send ForwardClose without prior ForwardOpen",
			Payload:     buildENIPHeader(0x006F, 0x12345678, buildMinimalForwardClose()),
			ExpectError: true,
		},
		{
			Name:        "unregister_without_register",
			Description: "Send UnregisterSession with fabricated handle",
			Payload:     buildENIPHeader(0x0066, 0xDEADBEEF, nil),
			ExpectError: true,
		},
		{
			Name:        "send_unit_data_no_connection",
			Description: "Send SendUnitData without established connection",
			Payload:     buildENIPHeader(0x0070, 0x12345678, buildMinimalSendUnitData()),
			ExpectError: true,
		},
	}
}

// buildStaleSessionAction creates a request using a previously-closed session handle.
func buildStaleSessionAction() FuzzAction {
	// Use session handle 0x00000001 (typically the first assigned).
	frame := buildENIPHeader(0x006F, 1, nil)
	return FuzzAction{
		Name:        "stale_session_reuse",
		Description: "Reuse a previously closed session handle",
		Payload:     frame,
		ExpectError: true,
	}
}

// buildENIPHeader constructs a 24-byte ENIP header + optional data.
func buildENIPHeader(command uint16, sessionHandle uint32, data []byte) []byte {
	header := make([]byte, 24+len(data))
	binary.LittleEndian.PutUint16(header[0:2], command)
	binary.LittleEndian.PutUint16(header[2:4], uint16(len(data)))
	binary.LittleEndian.PutUint32(header[4:8], sessionHandle)
	// Status, sender context, options: all zero
	if len(data) > 0 {
		copy(header[24:], data)
	}
	return header
}

// buildMinimalForwardClose builds a minimal ForwardClose CIP payload.
func buildMinimalForwardClose() []byte {
	// Wrap in SendRRData CPF structure.
	// Interface handle(4) + timeout(2) + CPF count(2) + null addr(4) + data item header(4) + CIP service(1) + path_size(1) + path(4)
	buf := make([]byte, 22)
	// Interface handle = 0
	// Timeout = 0
	binary.LittleEndian.PutUint16(buf[6:8], 2) // CPF item count
	// Item 0: Null Address (type=0x0000, len=0)
	// Item 1: Unconnected Data (type=0x00B2, len=6)
	binary.LittleEndian.PutUint16(buf[8:10], 0x0000)   // null addr type
	binary.LittleEndian.PutUint16(buf[10:12], 0x0000)   // null addr length
	binary.LittleEndian.PutUint16(buf[12:14], 0x00B2)   // unconnected data type
	binary.LittleEndian.PutUint16(buf[14:16], 6)         // data length
	buf[16] = 0x4E // ForwardClose service code
	buf[17] = 0x02 // Path size (2 words)
	buf[18] = 0x20 // Class segment
	buf[19] = 0x06 // Connection Manager
	buf[20] = 0x24 // Instance segment
	buf[21] = 0x01 // Instance 1
	return buf
}

// buildMinimalSendUnitData builds a minimal SendUnitData payload.
func buildMinimalSendUnitData() []byte {
	buf := make([]byte, 16)
	// Interface handle = 0
	// Timeout = 0
	binary.LittleEndian.PutUint16(buf[6:8], 2) // CPF count
	// Item 0: Connected Address (type=0x00A1, len=4)
	binary.LittleEndian.PutUint16(buf[8:10], 0x00A1)
	binary.LittleEndian.PutUint16(buf[10:12], 4)
	binary.LittleEndian.PutUint32(buf[12:16], 0xDEADBEEF) // Connection ID
	return buf
}
