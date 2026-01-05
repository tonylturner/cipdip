package protocol

import "fmt"

// BuildSymbolicEPATH builds an EPATH using ANSI extended symbolic segments (0x91).
func BuildSymbolicEPATH(tag string) []byte {
	if tag == "" {
		return nil
	}
	segments := splitSymbolicTag(tag)
	var epath []byte
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		epath = append(epath, 0x91, byte(len(seg)))
		epath = append(epath, []byte(seg)...)
		if len(seg)%2 != 0 {
			epath = append(epath, 0x00)
		}
	}
	return epath
}

// DecodeSymbolicEPATH decodes ANSI extended symbolic segments (0x91) into a tag name.
func DecodeSymbolicEPATH(data []byte) (string, error) {
	if len(data) < 2 || data[0] != 0x91 {
		return "", fmt.Errorf("not a symbolic EPATH")
	}
	offset := 0
	segments := make([]string, 0)
	for offset < len(data) {
		if data[offset] == 0x00 {
			offset++
			continue
		}
		if data[offset] != 0x91 {
			return "", fmt.Errorf("invalid symbolic segment: 0x%02X", data[offset])
		}
		if len(data) < offset+2 {
			return "", fmt.Errorf("incomplete symbolic segment length")
		}
		length := int(data[offset+1])
		offset += 2
		if len(data) < offset+length {
			return "", fmt.Errorf("incomplete symbolic segment data")
		}
		segment := string(data[offset : offset+length])
		segments = append(segments, segment)
		offset += length
		if length%2 != 0 && offset < len(data) {
			offset++
		}
	}
	return joinSymbolicTag(segments), nil
}

func splitSymbolicTag(tag string) []string {
	var segments []string
	current := ""
	for i := 0; i < len(tag); i++ {
		ch := tag[i]
		if ch == '.' {
			segments = append(segments, current)
			current = ""
			continue
		}
		current += string(ch)
	}
	if current != "" {
		segments = append(segments, current)
	}
	return segments
}

func joinSymbolicTag(segments []string) string {
	if len(segments) == 0 {
		return ""
	}
	out := segments[0]
	for i := 1; i < len(segments); i++ {
		out += "." + segments[i]
	}
	return out
}
