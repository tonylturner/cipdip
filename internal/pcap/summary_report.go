package pcap

import "path/filepath"

// SummaryEntry captures a per-PCAP summary result.
type SummaryEntry struct {
	Name    string
	Path    string
	Summary *PCAPSummary
	Err     error
}

// BuildSummaryEntries summarizes all PCAPs under the root directory.
func BuildSummaryEntries(root string) ([]SummaryEntry, error) {
	pcaps, err := CollectPcapFiles(root)
	if err != nil {
		return nil, err
	}
	entries := make([]SummaryEntry, 0, len(pcaps))
	for _, pcapPath := range pcaps {
		entry := SummaryEntry{
			Name: filepath.Base(pcapPath),
			Path: pcapPath,
		}
		summary, err := SummarizeENIPFromPCAP(pcapPath)
		if err != nil {
			entry.Err = err
		} else {
			entry.Summary = summary
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
