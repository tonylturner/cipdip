package pcap

import (
	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/enip"
)

func extractCIPFromENIP(pkt ENIPPacket) ([]byte, bool, string) {
	if len(pkt.Data) < 6 {
		return nil, false, ""
	}
	payload := pkt.Data[6:]
	if len(payload) == 0 {
		return nil, false, ""
	}
	items, err := enip.ParseCPFItems(payload)
	if err != nil {
		return payload, false, "raw"
	}
	for _, item := range items {
		if item.TypeID == enip.CPFItemUnconnectedData || item.TypeID == enip.CPFItemConnectedData {
			dataType := "connected"
			if item.TypeID == enip.CPFItemUnconnectedData {
				dataType = "unconnected"
			}
			return item.Data, true, dataType
		}
	}
	return payload, true, "raw"
}

// ExtractCIPFromENIPPacket returns CIP data from an ENIP packet.
func ExtractCIPFromENIPPacket(pkt ENIPPacket) ([]byte, bool, string) {
	return extractCIPFromENIP(pkt)
}

func extractEPATHFromRequest(cipData []byte) ([]byte, bool) {
	if len(cipData) < 2 {
		return nil, false
	}
	pathSizeWords := int(cipData[1])
	pathBytesLen := pathSizeWords * 2
	if pathBytesLen > 0 && len(cipData) >= 2+pathBytesLen {
		pathBytes := make([]byte, pathBytesLen)
		copy(pathBytes, cipData[2:2+pathBytesLen])
		if looksLikeEPATH(pathBytes) {
			return pathBytes, true
		}
	}

	// Fallback: attempt to parse without path size byte.
	pathBytes := cipData[1:]
	if looksLikeEPATH(pathBytes) {
		return pathBytes, false
	}
	return nil, false
}

func looksLikeEPATH(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	seg := data[0]
	switch seg {
	case 0x20, 0x21, 0x24, 0x25, 0x30, 0x31, 0x00:
	default:
		return false
	}
	_, err := protocol.ParseEPATH(data)
	return err == nil
}
