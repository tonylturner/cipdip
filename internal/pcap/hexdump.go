package pcap

// Hex dump utilities for packet analysis

import (
	"fmt"
	"strings"
)

// HexDump creates a hex dump of packet data
func HexDump(data []byte, width int) string {
	if width <= 0 {
		width = 16
	}

	var sb strings.Builder
	for i := 0; i < len(data); i += width {
		// Offset
		sb.WriteString(fmt.Sprintf("%04x: ", i))

		// Hex bytes
		for j := 0; j < width; j++ {
			if i+j < len(data) {
				sb.WriteString(fmt.Sprintf("%02x ", data[i+j]))
			} else {
				sb.WriteString("   ")
			}
		}

		// ASCII representation
		sb.WriteString(" |")
		for j := 0; j < width && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b < 127 {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}

	return sb.String()
}

// FormatPacketHex formats a packet as a hex string with optional annotations
func FormatPacketHex(data []byte, annotate bool) string {
	if !annotate {
		// Simple hex string
		var sb strings.Builder
		for i, b := range data {
			if i > 0 && i%16 == 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(fmt.Sprintf("%02x ", b))
		}
		return sb.String()
	}

	// Annotated hex dump with ENIP header labels
	if len(data) < 24 {
		return HexDump(data, 16)
	}

	var sb strings.Builder
	sb.WriteString("ENIP Header (24 bytes):\n")
	sb.WriteString(HexDump(data[0:24], 16))

	if len(data) > 24 {
		sb.WriteString("\nENIP Data:\n")
		sb.WriteString(HexDump(data[24:], 16))
	}

	return sb.String()
}
