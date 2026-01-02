package cipclient

import "fmt"

// EPATHInfo captures parsed EPATH details for summaries.
type EPATHInfo struct {
	Path            CIPPath
	ClassIs16       bool
	InstanceIs16    bool
	AttributeIs16   bool
	BytesConsumed   int
	HasClassSegment bool
}

// ParseEPATH parses a CIP EPATH and returns parsed path info and bytes consumed.
// Note: Contextual service decoding uses (service, class) because vendor-specific
// services in the 0x4B–0x63 range are ambiguous without object class context.
func ParseEPATH(data []byte) (EPATHInfo, error) {
	order := currentCIPByteOrder()
	info := EPATHInfo{}
	offset := 0

	for offset < len(data) {
		seg := data[offset]
		if seg == 0x00 {
			offset++
			continue
		}
		switch seg {
		case 0x20: // 8-bit class
			if len(data) < offset+2 {
				return info, fmt.Errorf("incomplete class segment")
			}
			info.Path.Class = uint16(data[offset+1])
			info.HasClassSegment = true
			offset += 2
		case 0x21: // 16-bit class
			if len(data) < offset+3 {
				return info, fmt.Errorf("incomplete 16-bit class segment")
			}
			info.Path.Class = order.Uint16(data[offset+1 : offset+3])
			info.ClassIs16 = true
			info.HasClassSegment = true
			offset += 3
		case 0x24: // 8-bit instance
			if len(data) < offset+2 {
				return info, fmt.Errorf("incomplete instance segment")
			}
			info.Path.Instance = uint16(data[offset+1])
			offset += 2
		case 0x25: // 16-bit instance
			if len(data) < offset+3 {
				return info, fmt.Errorf("incomplete 16-bit instance segment")
			}
			info.Path.Instance = order.Uint16(data[offset+1 : offset+3])
			info.InstanceIs16 = true
			offset += 3
		case 0x30: // 8-bit attribute
			if len(data) < offset+2 {
				return info, fmt.Errorf("incomplete attribute segment")
			}
			info.Path.Attribute = uint16(data[offset+1])
			offset += 2
		case 0x31: // 16-bit attribute
			if len(data) < offset+3 {
				return info, fmt.Errorf("incomplete 16-bit attribute segment")
			}
			info.Path.Attribute = order.Uint16(data[offset+1 : offset+3])
			info.AttributeIs16 = true
			offset += 3
		default:
			if isPortSegment(seg) {
				next, err := skipPortSegment(data, offset)
				if err != nil {
					return info, err
				}
				offset = next
				continue
			}
			return info, fmt.Errorf("invalid EPATH segment: 0x%02X", seg)
		}
	}

	info.BytesConsumed = offset
	return info, nil
}

func isPortSegment(seg byte) bool {
	return seg&0xE0 == 0x00
}

func skipPortSegment(data []byte, offset int) (int, error) {
	seg := data[offset]
	offset++
	if offset > len(data) {
		return offset, fmt.Errorf("incomplete port segment")
	}

	portID := seg & 0x0F
	extendedLink := seg&0x10 != 0
	if portID == 0x0F {
		if len(data) < offset+2 {
			return offset, fmt.Errorf("incomplete extended port segment")
		}
		offset += 2
	}

	if extendedLink {
		if len(data) < offset+1 {
			return offset, fmt.Errorf("incomplete port link size")
		}
		linkSize := int(data[offset])
		offset++
		if len(data) < offset+linkSize {
			return offset, fmt.Errorf("incomplete port link address")
		}
		offset += linkSize
	} else {
		if len(data) < offset+1 {
			return offset, fmt.Errorf("incomplete port link address")
		}
		offset++
	}

	if offset%2 == 1 && offset < len(data) {
		offset++
	}
	return offset, nil
}
