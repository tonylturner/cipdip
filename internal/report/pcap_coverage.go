package report

import (
	"fmt"
	"io"
	"sort"

	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
	"github.com/tonylturner/cipdip/internal/pcap"
)

// WritePCAPCoverageReport renders a coverage report in Markdown format.
func WritePCAPCoverageReport(w io.Writer, root string, report *pcap.PCAPCoverageReport, errors []pcap.CoverageFileError) {
	fmt.Fprintf(w, "# PCAP Coverage Report\n\nGenerated: %s\n\n", FormatTimestamp())
	fmt.Fprintf(w, "PCAP root: %s\n\n", root)

	for _, entry := range errors {
		fmt.Fprintf(w, "## %s\n\nError: %v\n\n", entry.Name, entry.Err)
	}

	fmt.Fprintf(w, "## CIP Service Counts\n\n```text\n")
	for _, svc := range sortedServiceKeys(report.ServiceCounts) {
		name := spec.ServiceName(protocol.CIPServiceCode(svc))
		fmt.Fprintf(w, "0x%02X %s: %d requests, %d responses\n", svc, name, report.ServiceCounts[svc]-report.ServiceResponseCt[svc], report.ServiceResponseCt[svc])
	}
	fmt.Fprintf(w, "```\n\n")

	fmt.Fprintf(w, "## CIP Request Coverage (Service/Class/Instance/Attribute)\n\n```text\n")
	for _, key := range pcap.SortedCoverageEntries(report.RequestEntries) {
		entry := report.RequestEntries[key]
		fmt.Fprintf(w, "%s (%d)\n", key, entry.Count)
	}
	fmt.Fprintf(w, "```\n\n")

	if len(report.EmbeddedEntries) > 0 {
		fmt.Fprintf(w, "## Embedded CIP Request Coverage (Unconnected Send)\n\n```text\n")
		for _, key := range pcap.SortedCoverageEntries(report.EmbeddedEntries) {
			entry := report.EmbeddedEntries[key]
			fmt.Fprintf(w, "%s (%d)\n", key, entry.Count)
		}
		fmt.Fprintf(w, "```\n\n")
	}
}

func sortedServiceKeys(values map[uint8]int) []uint8 {
	keys := make([]uint8, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	return keys
}
