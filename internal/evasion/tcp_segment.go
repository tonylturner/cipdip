package evasion

// TCP segmentation evasion: splits CIP/ENIP payloads across TCP segment
// boundaries to confuse stateful DPI engines.
//
// Many DPI engines reassemble TCP streams to inspect application-layer
// protocols. Splitting a single ENIP frame across multiple TCP segments
// (especially at protocol-significant boundaries) can cause reassembly
// failures or misclassification.

import (
	"fmt"
	"time"
)

// ENIPHeaderSize is the fixed ENIP encapsulation header size.
const ENIPHeaderSize = 24

// SegmentPlan describes how to split a payload into TCP segments.
type SegmentPlan struct {
	Segments      []Segment
	InterSegDelay time.Duration
}

// Segment is a single TCP segment in the plan.
type Segment struct {
	Data   []byte
	Offset int // Byte offset within the original payload
	Label  string
}

// PlanTCPSegmentation creates a segment plan for the given payload.
func PlanTCPSegmentation(payload []byte, cfg TCPSegmentConfig) (*SegmentPlan, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	var splitOffsets []int

	switch cfg.SplitPoint {
	case SplitMidENIPHeader:
		if len(payload) > 12 {
			splitOffsets = append(splitOffsets, 12) // Middle of ENIP header
		}

	case SplitBetweenENIPCPF:
		if len(payload) > ENIPHeaderSize {
			splitOffsets = append(splitOffsets, ENIPHeaderSize) // After ENIP header
		}

	case SplitMidCIPPath:
		// CIP path typically starts at ENIP header + 6 (interface handle + timeout)
		// + CPF header (~6-10 bytes). Estimate: offset ~36.
		cipPathOffset := estimateCIPPathOffset(payload)
		if cipPathOffset > 0 && cipPathOffset < len(payload) {
			splitOffsets = append(splitOffsets, cipPathOffset)
		}

	case SplitMidCIPPayload:
		// CIP payload follows the path. Estimate offset and split in the middle.
		cipPayloadOffset := estimateCIPPayloadOffset(payload)
		if cipPayloadOffset > 0 && cipPayloadOffset < len(payload) {
			mid := cipPayloadOffset + (len(payload)-cipPayloadOffset)/2
			splitOffsets = append(splitOffsets, mid)
		}

	case SplitEveryNBytes:
		n := cfg.SplitOffset
		if n <= 0 {
			n = 1
		}
		for offset := n; offset < len(payload); offset += n {
			splitOffsets = append(splitOffsets, offset)
		}

	default:
		// Default: split in the middle
		splitOffsets = append(splitOffsets, len(payload)/2)
	}

	if len(splitOffsets) == 0 {
		// No valid split point found - send as single segment.
		return &SegmentPlan{
			Segments: []Segment{
				{Data: payload, Offset: 0, Label: "full"},
			},
			InterSegDelay: cfg.InterSegDelay,
		}, nil
	}

	return buildSegmentPlan(payload, splitOffsets, cfg.InterSegDelay), nil
}

// buildSegmentPlan creates segments from the payload at the given split offsets.
func buildSegmentPlan(payload []byte, offsets []int, delay time.Duration) *SegmentPlan {
	plan := &SegmentPlan{InterSegDelay: delay}

	prev := 0
	for i, offset := range offsets {
		if offset <= prev || offset >= len(payload) {
			continue
		}
		seg := Segment{
			Data:   cloneSlice(payload[prev:offset]),
			Offset: prev,
			Label:  fmt.Sprintf("seg_%d", i),
		}
		plan.Segments = append(plan.Segments, seg)
		prev = offset
	}

	// Final segment
	if prev < len(payload) {
		plan.Segments = append(plan.Segments, Segment{
			Data:   cloneSlice(payload[prev:]),
			Offset: prev,
			Label:  fmt.Sprintf("seg_%d", len(plan.Segments)),
		})
	}

	return plan
}

// estimateCIPPathOffset estimates where the CIP EPATH begins in an ENIP frame.
// For SendRRData: ENIP header(24) + interface_handle(4) + timeout(2) + CPF_count(2)
//   + CPF item 0 header(4) + CPF item 1 header(4) + service(1) + path_size(1) = ~42
// This is approximate - precise offset depends on CPF item layout.
func estimateCIPPathOffset(payload []byte) int {
	if len(payload) < ENIPHeaderSize+10 {
		return 0
	}
	// After ENIP header: interface_handle(4) + timeout(2) = 6
	// CPF item count(2) + null addr item (typeID(2) + len(2)) = 6
	// Unconnected data item header (typeID(2) + len(2)) = 4
	// CIP service(1) + path_size(1) = 2
	// Total: 24 + 6 + 6 + 4 + 2 = 42
	offset := ENIPHeaderSize + 18 // approximate CIP path start
	if offset >= len(payload) {
		return 0
	}
	return offset
}

// estimateCIPPayloadOffset estimates where the CIP payload data begins.
func estimateCIPPayloadOffset(payload []byte) int {
	pathOffset := estimateCIPPathOffset(payload)
	if pathOffset == 0 {
		return 0
	}
	// After path offset: path bytes vary. Estimate 4-8 bytes of path.
	offset := pathOffset + 6
	if offset >= len(payload) {
		return 0
	}
	return offset
}

// SplitAtBoundaries splits payload at multiple protocol-significant boundaries.
// This is the most aggressive segmentation mode.
func SplitAtBoundaries(payload []byte, delay time.Duration) *SegmentPlan {
	var offsets []int

	// Split at every protocol boundary we can identify.
	if len(payload) > 12 {
		offsets = append(offsets, 12) // Mid ENIP header
	}
	if len(payload) > ENIPHeaderSize {
		offsets = append(offsets, ENIPHeaderSize) // ENIP/CPF boundary
	}
	cipPath := estimateCIPPathOffset(payload)
	if cipPath > 0 {
		offsets = append(offsets, cipPath) // CIP path start
	}
	cipPayload := estimateCIPPayloadOffset(payload)
	if cipPayload > 0 {
		offsets = append(offsets, cipPayload) // CIP payload start
	}

	if len(offsets) == 0 {
		return &SegmentPlan{
			Segments:      []Segment{{Data: payload, Offset: 0, Label: "full"}},
			InterSegDelay: delay,
		}
	}

	return buildSegmentPlan(payload, offsets, delay)
}

func cloneSlice(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
