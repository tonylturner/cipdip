package pcap

import (
	"path/filepath"
)

// CoverageFileError captures a per-file coverage error.
type CoverageFileError struct {
	Name string
	Path string
	Err  error
}

// AggregateCoverageReport summarizes coverage across all PCAPs under root.
func AggregateCoverageReport(root string) (*PCAPCoverageReport, []CoverageFileError, error) {
	pcaps, err := CollectPcapFiles(root)
	if err != nil {
		return nil, nil, err
	}
	aggregate := &PCAPCoverageReport{
		ServiceCounts:       make(map[uint8]int),
		ServiceResponseCt:   make(map[uint8]int),
		RequestEntries:      make(map[string]*CIPCoverageEntry),
		EmbeddedEntries:     make(map[string]*CIPCoverageEntry),
		UnknownServicePairs: make(map[string]int),
	}
	fileErrors := make([]CoverageFileError, 0)

	for _, pcapPath := range pcaps {
		report, err := SummarizeCoverageFromPCAP(pcapPath)
		if err != nil {
			fileErrors = append(fileErrors, CoverageFileError{
				Name: filepath.Base(pcapPath),
				Path: pcapPath,
				Err:  err,
			})
			continue
		}
		mergeCoverage(aggregate, report)
	}

	return aggregate, fileErrors, nil
}

func mergeCoverage(dst, src *PCAPCoverageReport) {
	for svc, count := range src.ServiceCounts {
		dst.ServiceCounts[svc] += count
	}
	for svc, count := range src.ServiceResponseCt {
		dst.ServiceResponseCt[svc] += count
	}
	for key, entry := range src.RequestEntries {
		dstEntry := dst.RequestEntries[key]
		if dstEntry == nil {
			clone := *entry
			dst.RequestEntries[key] = &clone
			continue
		}
		dstEntry.Count += entry.Count
	}
	for key, entry := range src.EmbeddedEntries {
		dstEntry := dst.EmbeddedEntries[key]
		if dstEntry == nil {
			clone := *entry
			dst.EmbeddedEntries[key] = &clone
			continue
		}
		dstEntry.Count += entry.Count
	}
	for key, count := range src.UnknownServicePairs {
		dst.UnknownServicePairs[key] += count
	}
}
