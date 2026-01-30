package pccc

// PCCC data table address parsing.
//
// Parses AB/SLC-500/PLC-5 address strings into structured Address values.
//
// Supported formats:
//   N7:0       - Integer file 7, element 0
//   B3:1/5     - Bit file 3, word 1, bit 5
//   F8:0       - Float file 8, element 0
//   ST9:0      - String file 9, element 0
//   T4:2.ACC   - Timer file 4, element 2, accumulator
//   T4:2.PRE   - Timer file 4, element 2, preset
//   C5:0.ACC   - Counter file 5, element 0, accumulator
//   R6:0.LEN   - Control file 6, element 0, length
//   R6:0.POS   - Control file 6, element 0, position
//   O:0/0      - Output word 0, bit 0
//   I:0/0      - Input word 0, bit 0
//   S:0        - Status word 0

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseAddress parses a PCCC data table address string.
func ParseAddress(addr string) (Address, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return Address{}, fmt.Errorf("empty address")
	}

	result := Address{RawAddress: addr, BitNumber: -1}

	// Determine file type prefix and extract file number
	remaining, err := parsePrefix(&result, addr)
	if err != nil {
		return Address{}, err
	}

	// Parse element number (after ':')
	if remaining == "" {
		return Address{}, fmt.Errorf("missing element number in %q", addr)
	}
	if remaining[0] != ':' {
		return Address{}, fmt.Errorf("expected ':' after file number in %q", addr)
	}
	remaining = remaining[1:]

	// Parse element, optional bit (/N), optional sub-element (.NAME)
	remaining, err = parseElement(&result, remaining, addr)
	if err != nil {
		return Address{}, err
	}

	if remaining != "" {
		return Address{}, fmt.Errorf("unexpected trailing characters %q in %q", remaining, addr)
	}

	return result, nil
}

// parsePrefix extracts the file type and file number from the address prefix.
// Returns the remaining string after the file number.
func parsePrefix(result *Address, addr string) (string, error) {
	upper := strings.ToUpper(addr)

	// Two-character prefixes first
	if strings.HasPrefix(upper, "ST") {
		result.FileType = FileTypeString
		return parseFileNumber(result, addr[2:], addr)
	}

	if len(addr) == 0 {
		return "", fmt.Errorf("empty address")
	}

	switch upper[0] {
	case 'N':
		result.FileType = FileTypeInteger
		return parseFileNumber(result, addr[1:], addr)
	case 'B':
		result.FileType = FileTypeBit
		return parseFileNumber(result, addr[1:], addr)
	case 'T':
		result.FileType = FileTypeTimer
		return parseFileNumber(result, addr[1:], addr)
	case 'C':
		result.FileType = FileTypeCounter
		return parseFileNumber(result, addr[1:], addr)
	case 'R':
		result.FileType = FileTypeControl
		return parseFileNumber(result, addr[1:], addr)
	case 'F':
		result.FileType = FileTypeFloat
		return parseFileNumber(result, addr[1:], addr)
	case 'A':
		result.FileType = FileTypeASCII
		return parseFileNumber(result, addr[1:], addr)
	case 'L':
		result.FileType = FileTypeLong
		return parseFileNumber(result, addr[1:], addr)
	case 'O':
		result.FileType = FileTypeOutput
		return parseFixedFile(result, addr[1:], 0, addr)
	case 'I':
		result.FileType = FileTypeInput
		return parseFixedFile(result, addr[1:], 1, addr)
	case 'S':
		result.FileType = FileTypeStatus
		return parseFixedFile(result, addr[1:], 2, addr)
	default:
		return "", fmt.Errorf("unknown file type prefix %q in %q", string(addr[0]), addr)
	}
}

// parseFileNumber extracts the numeric file number.
func parseFileNumber(result *Address, s string, fullAddr string) (string, error) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return "", fmt.Errorf("missing file number in %q", fullAddr)
	}
	n, err := strconv.ParseUint(s[:i], 10, 8)
	if err != nil {
		return "", fmt.Errorf("invalid file number in %q: %w", fullAddr, err)
	}
	result.FileNumber = uint8(n)
	return s[i:], nil
}

// parseFixedFile handles O, I, S files that have a fixed default file number.
// These can optionally specify a file number (e.g., O0:0) or just use the default (O:0).
func parseFixedFile(result *Address, s string, defaultNum uint8, fullAddr string) (string, error) {
	if len(s) > 0 && s[0] >= '0' && s[0] <= '9' {
		return parseFileNumber(result, s, fullAddr)
	}
	result.FileNumber = defaultNum
	return s, nil
}

// parseElement extracts element number, optional bit, optional sub-element.
func parseElement(result *Address, s string, fullAddr string) (string, error) {
	// Parse element number
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return "", fmt.Errorf("missing element number in %q", fullAddr)
	}
	n, err := strconv.ParseUint(s[:i], 10, 16)
	if err != nil {
		return "", fmt.Errorf("invalid element number in %q: %w", fullAddr, err)
	}
	result.Element = uint16(n)
	s = s[i:]

	// Check for bit specification (/N)
	if len(s) > 0 && s[0] == '/' {
		s = s[1:]
		i = 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == 0 {
			return "", fmt.Errorf("missing bit number after '/' in %q", fullAddr)
		}
		bit, err := strconv.ParseUint(s[:i], 10, 8)
		if err != nil || bit > 15 {
			return "", fmt.Errorf("invalid bit number in %q (must be 0-15)", fullAddr)
		}
		result.BitNumber = int8(bit)
		result.HasBit = true
		s = s[i:]
	}

	// Check for sub-element (.NAME or .N)
	if len(s) > 0 && s[0] == '.' {
		s = s[1:]
		sub, remaining, err := parseSubElement(result.FileType, s, fullAddr)
		if err != nil {
			return "", err
		}
		result.SubElement = sub
		result.HasSub = true
		s = remaining
	}

	return s, nil
}

// parseSubElement resolves a named or numeric sub-element.
func parseSubElement(ft FileType, s string, fullAddr string) (uint8, string, error) {
	// Try numeric sub-element first
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i > 0 {
		n, err := strconv.ParseUint(s[:i], 10, 8)
		if err != nil {
			return 0, "", fmt.Errorf("invalid sub-element number in %q: %w", fullAddr, err)
		}
		return uint8(n), s[i:], nil
	}

	// Named sub-element - extract the name
	for i < len(s) && ((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z')) {
		i++
	}
	if i == 0 {
		return 0, "", fmt.Errorf("missing sub-element name after '.' in %q", fullAddr)
	}
	name := strings.ToUpper(s[:i])

	sub, err := resolveNamedSubElement(ft, name, fullAddr)
	if err != nil {
		return 0, "", err
	}
	return sub, s[i:], nil
}

// resolveNamedSubElement maps named sub-elements to their offsets.
func resolveNamedSubElement(ft FileType, name string, fullAddr string) (uint8, error) {
	switch ft {
	case FileTypeTimer:
		switch name {
		case "CTL", "CON":
			return uint8(SubTimerControl), nil
		case "PRE":
			return uint8(SubTimerPRE), nil
		case "ACC":
			return uint8(SubTimerACC), nil
		case "EN", "TT", "DN":
			// Timer status bits are in the control word (sub-element 0)
			return uint8(SubTimerControl), nil
		default:
			return 0, fmt.Errorf("unknown timer sub-element %q in %q", name, fullAddr)
		}

	case FileTypeCounter:
		switch name {
		case "CTL", "CON":
			return uint8(SubCounterControl), nil
		case "PRE":
			return uint8(SubCounterPRE), nil
		case "ACC":
			return uint8(SubCounterACC), nil
		case "CU", "CD", "DN", "OV", "UN":
			return uint8(SubCounterControl), nil
		default:
			return 0, fmt.Errorf("unknown counter sub-element %q in %q", name, fullAddr)
		}

	case FileTypeControl:
		switch name {
		case "CTL", "CON":
			return uint8(SubControlControl), nil
		case "LEN":
			return uint8(SubControlLEN), nil
		case "POS":
			return uint8(SubControlPOS), nil
		case "EN", "EU", "DN", "EM", "ER", "UL", "IN", "FD":
			return uint8(SubControlControl), nil
		default:
			return 0, fmt.Errorf("unknown control sub-element %q in %q", name, fullAddr)
		}

	default:
		return 0, fmt.Errorf("file type %s does not support named sub-elements in %q", ft, fullAddr)
	}
}

// DefaultFileNumber returns the conventional default file number for a file type.
// For example, N7 is the default integer file, B3 is the default bit file.
func DefaultFileNumber(ft FileType) uint8 {
	switch ft {
	case FileTypeOutput:
		return 0
	case FileTypeInput:
		return 1
	case FileTypeStatus:
		return 2
	case FileTypeBit:
		return 3
	case FileTypeTimer:
		return 4
	case FileTypeCounter:
		return 5
	case FileTypeControl:
		return 6
	case FileTypeInteger:
		return 7
	case FileTypeFloat:
		return 8
	case FileTypeString:
		return 9
	case FileTypeASCII:
		return 10
	case FileTypeLong:
		return 11
	default:
		return 0
	}
}
