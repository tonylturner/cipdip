package pcap

import (
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

