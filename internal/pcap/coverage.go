package pcap

import (
	"fmt"
	"sort"

	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
	"github.com/tturner/cipdip/internal/enip"
)

// CIPCoverageEntry captures a CIP request (service + path) observed in PCAPs.
type CIPCoverageEntry struct {
	Service    uint8
	Class      uint16
	Instance   uint16
	Attribute  uint16
	Embedded   bool
	Count      int
	ResponseCt int
}

// PCAPCoverageReport aggregates coverage stats across PCAPs.
type PCAPCoverageReport struct {
	ServiceCounts       map[uint8]int
	ServiceResponseCt   map[uint8]int
	RequestEntries      map[string]*CIPCoverageEntry
	EmbeddedEntries     map[string]*CIPCoverageEntry
	UnknownServicePairs map[string]int
}

// BuildPCAPCoverageReport extracts CIP request coverage from ENIP packets.
func BuildPCAPCoverageReport(packets []ENIPPacket) *PCAPCoverageReport {
	report := &PCAPCoverageReport{
		ServiceCounts:       make(map[uint8]int),
		ServiceResponseCt:   make(map[uint8]int),
		RequestEntries:      make(map[string]*CIPCoverageEntry),
		EmbeddedEntries:     make(map[string]*CIPCoverageEntry),
		UnknownServicePairs: make(map[string]int),
	}

	for _, pkt := range packets {
		if pkt.Command != enip.ENIPCommandSendRRData && pkt.Command != enip.ENIPCommandSendUnitData {
			continue
		}

		cipData, _, dataType := extractCIPFromENIP(pkt)
		if len(cipData) == 0 {
			continue
		}
		if dataType == "connected" {
			continue
		}
		if dataType != "unconnected" {
			continue
		}

		msgInfo, err := protocol.ParseCIPMessage(cipData)
		if err != nil {
			continue
		}

		baseService := msgInfo.BaseService
		report.ServiceCounts[baseService]++
		if msgInfo.IsResponse {
			report.ServiceResponseCt[baseService]++
			continue
		}

		if msgInfo.PathInfo.Path.Class != 0 {
			key := coverageKey(baseService, msgInfo.PathInfo.Path.Class, msgInfo.PathInfo.Path.Instance, msgInfo.PathInfo.Path.Attribute)
			entry := report.RequestEntries[key]
			if entry == nil {
				entry = &CIPCoverageEntry{
					Service:   baseService,
					Class:     msgInfo.PathInfo.Path.Class,
					Instance:  msgInfo.PathInfo.Path.Instance,
					Attribute: msgInfo.PathInfo.Path.Attribute,
				}
				report.RequestEntries[key] = entry
			}
			entry.Count++
			if msgInfo.PathInfo.Path.Class != 0 {
				pairKey := fmt.Sprintf("0x%02X/0x%04X", baseService, msgInfo.PathInfo.Path.Class)
				report.UnknownServicePairs[pairKey]++
			}
		}

		if baseService == 0x52 && msgInfo.PathInfo.Path.Class == spec.CIPClassConnectionManager && msgInfo.PathInfo.Path.Instance == 0x0001 {
			embedded := extractEmbeddedCIP(msgInfo, cipData)
			if len(embedded) > 0 {
				embeddedInfo, err := protocol.ParseCIPMessage(embedded)
				if err == nil && !embeddedInfo.IsResponse && embeddedInfo.PathInfo.Path.Class != 0 {
					embeddedKey := coverageKey(embeddedInfo.BaseService, embeddedInfo.PathInfo.Path.Class, embeddedInfo.PathInfo.Path.Instance, embeddedInfo.PathInfo.Path.Attribute)
					entry := report.EmbeddedEntries[embeddedKey]
					if entry == nil {
						entry = &CIPCoverageEntry{
							Service:   embeddedInfo.BaseService,
							Class:     embeddedInfo.PathInfo.Path.Class,
							Instance:  embeddedInfo.PathInfo.Path.Instance,
							Attribute: embeddedInfo.PathInfo.Path.Attribute,
							Embedded:  true,
						}
						report.EmbeddedEntries[embeddedKey] = entry
					}
					entry.Count++
				}
			}
		}
	}

	return report
}

// SummarizeCoverageFromPCAP reads a PCAP and returns a coverage report.
func SummarizeCoverageFromPCAP(pcapFile string) (*PCAPCoverageReport, error) {
	packets, err := ExtractENIPFromPCAP(pcapFile)
	if err != nil {
		return nil, err
	}
	return BuildPCAPCoverageReport(packets), nil
}

func coverageKey(service uint8, class, instance, attribute uint16) string {
	return fmt.Sprintf("0x%02X/0x%04X/0x%04X/0x%04X", service, class, instance, attribute)
}

func extractEmbeddedCIP(msgInfo protocol.CIPMessageInfo, cipData []byte) []byte {
	if msgInfo.IsResponse {
		if msgInfo.RequestData != nil {
			if embedded, ok := protocol.ParseUnconnectedSendResponsePayload(msgInfo.RequestData); ok {
				return embedded
			}
			return nil
		}
		return nil
	}
	if msgInfo.DataOffset > 0 && msgInfo.DataOffset <= len(cipData) {
		if embedded, _, ok := protocol.ParseUnconnectedSendRequestPayload(cipData[msgInfo.DataOffset:]); ok {
			return embedded
		}
		return nil
	}
	return nil
}

// SortedCoverageEntries returns sorted coverage keys for stable output.
func SortedCoverageEntries(entries map[string]*CIPCoverageEntry) []string {
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
