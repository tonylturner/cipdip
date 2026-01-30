package evasion

// IP-layer fragmentation evasion.
//
// IP fragmentation splits datagrams at the IP layer, below TCP/UDP.
// DPI engines must reassemble IP fragments before inspecting
// application-layer protocols. Unusual fragmentation patterns can
// cause reassembly failures.
//
// NOTE: Sending actual IP fragments requires raw sockets and elevated
// privileges. This package provides fragment planning (for PCAP generation)
// and describes fragments that can be sent with golang.org/x/net/ipv4
// when running with appropriate permissions.

import "fmt"

// IPFragment represents a planned IP fragment.
type IPFragment struct {
	Offset int    // Fragment offset in 8-byte units
	Data   []byte // Fragment payload
	MF     bool   // More Fragments flag
	ID     uint16 // IP identification field
	Label  string // Human-readable label
}

// FragmentPlan describes how to fragment an IP datagram.
type FragmentPlan struct {
	Fragments []IPFragment
	OrigSize  int    // Original datagram size
	IPHeader  []byte // IP header template (20 bytes)
}

// PlanIPFragmentation creates a fragment plan for the given payload.
func PlanIPFragmentation(payload []byte, cfg IPFragmentConfig) (*FragmentPlan, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	fragSize := cfg.FragmentSize
	if fragSize <= 0 {
		fragSize = 8 // minimum fragment size (8 bytes)
	}
	// Fragment offset must be in 8-byte units, so align fragment size.
	fragSize = (fragSize / 8) * 8
	if fragSize == 0 {
		fragSize = 8
	}

	var fragments []IPFragment
	id := uint16(0x4242) // arbitrary IP identification

	if cfg.Reverse {
		fragments = planReverseFragments(payload, fragSize, id)
	} else {
		fragments = planForwardFragments(payload, fragSize, id)
	}

	if cfg.Overlap {
		fragments = injectOverlappingFragments(fragments, id)
	}

	if cfg.DecoyCount > 0 {
		fragments = injectDecoyFragments(fragments, cfg.DecoyCount, id)
	}

	return &FragmentPlan{
		Fragments: fragments,
		OrigSize:  len(payload),
	}, nil
}

// planForwardFragments creates fragments in normal order.
func planForwardFragments(payload []byte, fragSize int, id uint16) []IPFragment {
	var fragments []IPFragment
	for offset := 0; offset < len(payload); offset += fragSize {
		end := offset + fragSize
		if end > len(payload) {
			end = len(payload)
		}
		mf := end < len(payload)
		fragments = append(fragments, IPFragment{
			Offset: offset / 8,
			Data:   cloneSlice(payload[offset:end]),
			MF:     mf,
			ID:     id,
			Label:  fmt.Sprintf("frag_%d", offset/8),
		})
	}
	return fragments
}

// planReverseFragments creates fragments in reverse order.
// This can confuse DPI engines that expect sequential reassembly.
func planReverseFragments(payload []byte, fragSize int, id uint16) []IPFragment {
	forward := planForwardFragments(payload, fragSize, id)
	reversed := make([]IPFragment, len(forward))
	for i, f := range forward {
		reversed[len(forward)-1-i] = f
	}
	return reversed
}

// injectOverlappingFragments adds overlapping fragments.
// Overlapping fragments test whether DPI engines handle RFC 815
// reassembly correctly (first-copy-wins vs last-copy-wins).
func injectOverlappingFragments(fragments []IPFragment, id uint16) []IPFragment {
	if len(fragments) < 2 {
		return fragments
	}
	// Inject an overlapping fragment that duplicates the first fragment's
	// data range but with different content (zeros).
	overlap := IPFragment{
		Offset: fragments[0].Offset,
		Data:   make([]byte, len(fragments[0].Data)),
		MF:     true,
		ID:     id,
		Label:  "overlap_decoy",
	}
	// Insert before the real first fragment.
	result := make([]IPFragment, 0, len(fragments)+1)
	result = append(result, overlap)
	result = append(result, fragments...)
	return result
}

// injectDecoyFragments adds fragments with a different IP ID.
// DPI engines should ignore these (wrong ID), but some may be confused.
func injectDecoyFragments(fragments []IPFragment, count int, realID uint16) []IPFragment {
	decoyID := realID + 1
	result := make([]IPFragment, 0, len(fragments)+count)

	for i := 0; i < count; i++ {
		decoy := IPFragment{
			Offset: i, // Various offsets
			Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE},
			MF:     true,
			ID:     decoyID,
			Label:  fmt.Sprintf("decoy_%d", i),
		}
		result = append(result, decoy)
	}
	result = append(result, fragments...)
	return result
}

// TotalFragments returns the number of real (non-decoy) fragments needed
// for a payload of the given size at the specified fragment size.
func TotalFragments(payloadSize, fragSize int) int {
	if fragSize <= 0 {
		fragSize = 8
	}
	fragSize = (fragSize / 8) * 8
	if fragSize == 0 {
		fragSize = 8
	}
	return (payloadSize + fragSize - 1) / fragSize
}
