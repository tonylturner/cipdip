package report

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tonylturner/cipdip/internal/pcap"
)

func WritePCAPClassifyCSV(path string, rows []pcap.ClassifyRow) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return fmt.Errorf("create csv directory: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create csv file: %w", err)
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	header := []string{
		"File", "Path", "ENIP_Hits", "CIP_Hits", "ListIdentity", "UDP2222_IO",
		"Malformed", "ExpertErrors", "ExpertWarnings", "BadChecksums",
		"TCP_RST", "TCP_Retrans", "TCP_LostSeg",
		"CIP_Responses", "CIP_ErrorResponses", "CIP_ErrorRate",
		"Integrity", "IntegrityReasons", "Flags",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("write csv header: %w", err)
	}

	for _, row := range rows {
		record := []string{
			row.File,
			row.Path,
			fmt.Sprintf("%d", row.EnipHits),
			fmt.Sprintf("%d", row.CipHits),
			fmt.Sprintf("%d", row.ListIdentity),
			fmt.Sprintf("%d", row.UDP2222IO),
			fmt.Sprintf("%d", row.Malformed),
			fmt.Sprintf("%d", row.ExpertErrors),
			fmt.Sprintf("%d", row.ExpertWarnings),
			fmt.Sprintf("%d", row.BadChecksums),
			fmt.Sprintf("%d", row.TcpRst),
			fmt.Sprintf("%d", row.TcpRetrans),
			fmt.Sprintf("%d", row.TcpLostSeg),
			fmt.Sprintf("%d", row.CipResponses),
			fmt.Sprintf("%d", row.CipErrorResponses),
			fmt.Sprintf("%.4f", row.CipErrorRate),
			row.Integrity,
			row.IntegrityReasons,
			row.Flags,
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("write csv row: %w", err)
		}
	}

	return writer.Error()
}

func WritePCAPClassifySummary(path, outCSV, pcapDir, tsharkPath string, rows []pcap.ClassifyRow) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return fmt.Errorf("create summary directory: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create summary file: %w", err)
	}
	defer f.Close()

	var normal, noisy, anomalous, none int
	var fuzz, deform, opsbad int
	for _, row := range rows {
		switch row.Integrity {
		case "PROTOCOL_NORMAL":
			normal++
		case "TRANSPORT_NOISY":
			noisy++
		case "PROTOCOL_ANOMALOUS":
			anomalous++
		case "NOT_CIP_ENIP":
			none++
		}
		if strings.Contains(row.Flags, "fuzz_or_invalid") {
			fuzz++
		}
		if strings.Contains(row.Flags, "deformation") {
			deform++
		}
		if strings.Contains(row.Flags, "ops_bad") {
			opsbad++
		}
	}

	_, err = fmt.Fprintf(f, `CIP/ENIP PCAP Classification Summary
Generated: %s
PCAP directory: %s
tshark: %s

Integrity buckets:
  PROTOCOL_NORMAL
  TRANSPORT_NOISY
  PROTOCOL_ANOMALOUS
  NOT_CIP_ENIP

Counts:
  PROTOCOL_NORMAL:     %d
  TRANSPORT_NOISY:     %d
  PROTOCOL_ANOMALOUS:  %d
  NOT_CIP_ENIP:        %d

Additional flags:
  deformation:*         = malformed/expert errors/bad checksum signals
  fuzz_or_invalid:*     = high CIP error rate (unsupported/invalid/fuzz-like)
  ops_bad:*             = extreme transport conditions not conducive to normal ops
  has_discovery:*       = discovery present
  has_io:*              = UDP 2222 I/O present

Flagged sets:
  Deformation: %d
  Fuzz/Invalid: %d
  Ops bad: %d

CSV: %s
`, FormatTimestamp(), pcapDir, tsharkPath, normal, noisy, anomalous, none, deform, fuzz, opsbad, outCSV)
	if err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	return nil
}
