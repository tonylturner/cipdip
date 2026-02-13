package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tonylturner/cipdip/internal/pcap"
)

func TestWritePCAPSummary(t *testing.T) {
	summary := &pcap.PCAPSummary{
		TotalPackets: 1000,
		ENIPPackets:  900,
		Requests:     450,
		Responses:    450,
		CPFUsed:      800,
		CPFMissing:   100,
		CIPRequests:  400,
		CIPResponses: 400,
		CIPPayloads:  300,
		IOPayloads:   100,
	}

	var buf bytes.Buffer
	WritePCAPSummary(&buf, summary)

	output := buf.String()

	// Verify header
	if !strings.Contains(output, "PCAP Summary:") {
		t.Error("Expected 'PCAP Summary:' header")
	}

	// Verify key metrics
	if !strings.Contains(output, "Total packets: 1000") {
		t.Error("Expected total packets count")
	}
	if !strings.Contains(output, "ENIP packets: 900") {
		t.Error("Expected ENIP packets count")
	}
	if !strings.Contains(output, "Requests: 450") {
		t.Error("Expected requests count")
	}
	if !strings.Contains(output, "CIP requests: 400") {
		t.Error("Expected CIP requests count")
	}
}

func TestWritePCAPSummaryWithVendor(t *testing.T) {
	summary := &pcap.PCAPSummary{
		TotalPackets: 100,
		VendorID:     0x0001,
		ProductName:  "1756-ENBT/A",
	}

	var buf bytes.Buffer
	WritePCAPSummary(&buf, summary)

	output := buf.String()

	if !strings.Contains(output, "Vendor ID: 0x0001") {
		t.Error("Expected vendor ID")
	}
	if !strings.Contains(output, "Product Name: 1756-ENBT/A") {
		t.Error("Expected product name")
	}
}

func TestWritePCAPSummaryWithCommands(t *testing.T) {
	summary := &pcap.PCAPSummary{
		TotalPackets: 100,
		Commands: map[string]int{
			"ListServices":      10,
			"RegisterSession":   5,
			"SendRRData":        80,
			"UnRegisterSession": 5,
		},
	}

	var buf bytes.Buffer
	WritePCAPSummary(&buf, summary)

	output := buf.String()

	if !strings.Contains(output, "Command Counts:") {
		t.Error("Expected command counts section")
	}
	if !strings.Contains(output, "SendRRData: 80") {
		t.Error("Expected SendRRData count")
	}
}

func TestWritePCAPSummaryWithCIPServices(t *testing.T) {
	summary := &pcap.PCAPSummary{
		TotalPackets: 100,
		CIPServices: map[string]int{
			"Get_Attribute_Single": 50,
			"Set_Attribute_Single": 30,
			"Read_Tag":             20,
		},
	}

	var buf bytes.Buffer
	WritePCAPSummary(&buf, summary)

	output := buf.String()

	if !strings.Contains(output, "CIP Service Counts:") {
		t.Error("Expected CIP service counts section")
	}
	if !strings.Contains(output, "Get_Attribute_Single: 50") {
		t.Error("Expected Get_Attribute_Single count")
	}
}

func TestWritePCAPSummaryWithValidationErrors(t *testing.T) {
	summary := &pcap.PCAPSummary{
		TotalPackets:             100,
		RequestValidationTotal:   90,
		RequestValidationFailed:  5,
		RequestValidationErrors: map[string]int{
			"invalid path size":  3,
			"unknown service":    2,
		},
	}

	var buf bytes.Buffer
	WritePCAPSummary(&buf, summary)

	output := buf.String()

	if !strings.Contains(output, "CIP Request Validation (strict): 90 total, 5 failed") {
		t.Error("Expected validation summary")
	}
	if !strings.Contains(output, "CIP Request Validation Errors:") {
		t.Error("Expected validation errors section")
	}
}

func TestWritePCAPSummaryWithTopPaths(t *testing.T) {
	summary := &pcap.PCAPSummary{
		TotalPackets: 100,
		TopPaths: []string{
			"[0x01:0x01:0x01] (100)",
			"[0x04:0x65:0x03] (50)",
			"[0x04:0x66:0x03] (25)",
		},
	}

	var buf bytes.Buffer
	WritePCAPSummary(&buf, summary)

	output := buf.String()

	if !strings.Contains(output, "Top Paths:") {
		t.Error("Expected top paths section")
	}
	if !strings.Contains(output, "[0x01:0x01:0x01]") {
		t.Error("Expected first path")
	}
}

func TestWritePCAPSummaryWithUnknownServices(t *testing.T) {
	summary := &pcap.PCAPSummary{
		TotalPackets: 100,
		UnknownServices: map[uint8]*pcap.CIPUnknownStats{
			0x51: {
				Count:         10,
				ResponseCount: 8,
				ClassCounts:   map[uint16]int{0x00A1: 10},
			},
			0x4C: {
				Count:         5,
				ResponseCount: 5,
			},
		},
	}

	var buf bytes.Buffer
	WritePCAPSummary(&buf, summary)

	output := buf.String()

	if !strings.Contains(output, "Unknown CIP Service Details:") {
		t.Error("Expected unknown services section")
	}
	if !strings.Contains(output, "Unknown(0x51)") {
		t.Error("Expected unknown service 0x51")
	}
}

func TestWritePCAPSummaryWithUnknownPairs(t *testing.T) {
	summary := &pcap.PCAPSummary{
		TotalPackets: 100,
		UnknownPairs: map[string]int{
			"Service=0x51+Class=0x00A1": 10,
			"Service=0x4C+Class=0x0067": 5,
		},
	}

	var buf bytes.Buffer
	WritePCAPSummary(&buf, summary)

	output := buf.String()

	if !strings.Contains(output, "Top Unknown Service+Class Pairs:") {
		t.Error("Expected unknown pairs section")
	}
}

func TestWritePCAPSummaryWithEmbeddedServices(t *testing.T) {
	summary := &pcap.PCAPSummary{
		TotalPackets: 100,
		EmbeddedServices: map[string]int{
			"Get_Attribute_Single": 30,
			"Read_Tag":             20,
		},
	}

	var buf bytes.Buffer
	WritePCAPSummary(&buf, summary)

	output := buf.String()

	if !strings.Contains(output, "Embedded CIP Service Counts:") {
		t.Error("Expected embedded services section")
	}
}

func TestWritePCAPSummaryEmpty(t *testing.T) {
	summary := &pcap.PCAPSummary{}

	var buf bytes.Buffer
	WritePCAPSummary(&buf, summary)

	output := buf.String()

	// Should still have the basic structure
	if !strings.Contains(output, "PCAP Summary:") {
		t.Error("Expected 'PCAP Summary:' header even for empty summary")
	}
	if !strings.Contains(output, "Total packets: 0") {
		t.Error("Expected total packets to be 0")
	}
}

func TestFormatUint16Counts(t *testing.T) {
	counts := map[uint16]int{
		0x0001: 10,
		0x0004: 5,
		0x0067: 20,
	}

	result := formatUint16Counts(counts)

	// Should be sorted by count descending
	if !strings.HasPrefix(result, "[0x0067:20") {
		t.Errorf("Expected highest count first, got: %s", result)
	}
	if !strings.Contains(result, "0x0001:10") {
		t.Errorf("Expected 0x0001:10 in result: %s", result)
	}
}

func TestFormatUint8Counts(t *testing.T) {
	counts := map[uint8]int{
		0x00: 100,
		0x01: 5,
		0x08: 10,
	}

	result := formatUint8Counts(counts)

	// Should be sorted by count descending
	if !strings.HasPrefix(result, "[0x00:100") {
		t.Errorf("Expected highest count first, got: %s", result)
	}
}

func TestTopUnknownPairs(t *testing.T) {
	pairs := map[string]int{
		"pair1":  100,
		"pair2":  50,
		"pair3":  25,
		"pair4":  10,
		"pair5":  5,
	}

	result := topUnknownPairs(pairs, 3)

	if len(result) != 3 {
		t.Errorf("Expected 3 results, got %d", len(result))
	}

	// Should start with highest count
	if !strings.Contains(result[0], "pair1") {
		t.Errorf("Expected pair1 first, got: %s", result[0])
	}
	if !strings.Contains(result[0], "(100)") {
		t.Errorf("Expected count in parentheses, got: %s", result[0])
	}
}

func TestPrintCountsSorting(t *testing.T) {
	values := map[string]int{
		"zeta":  10,
		"alpha": 10,  // Same count, should sort alphabetically
		"beta":  100,
	}

	var buf bytes.Buffer
	printCounts(&buf, values)

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// beta (100) should be first
	if !strings.Contains(lines[0], "beta: 100") {
		t.Errorf("Expected beta first, got: %s", lines[0])
	}

	// alpha should come before zeta (alphabetically) when counts are equal
	alphaIdx := strings.Index(output, "alpha")
	zetaIdx := strings.Index(output, "zeta")
	if alphaIdx > zetaIdx {
		t.Error("Expected alpha before zeta when counts are equal")
	}
}
