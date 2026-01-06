package app

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/tturner/cipdip/internal/pcap"
	"github.com/tturner/cipdip/internal/reference"
)

type ExtractReferenceOptions struct {
	BaselineDir  string
	RealWorldDir string
	OutputFile   string
}

func RunExtractReference(opts ExtractReferenceOptions) error {
	fmt.Fprintf(os.Stdout, "Extracting reference packets from PCAP files...\n\n")
	reference.ResetReferencePackets()

	var pcapFiles []string

	if opts.BaselineDir != "" {
		baselineFiles, err := pcap.CollectPcapFiles(opts.BaselineDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not read baseline directory %s: %v\n", opts.BaselineDir, err)
		} else {
			fmt.Fprintf(os.Stdout, "Found %d baseline PCAP file(s) in %s\n", len(baselineFiles), opts.BaselineDir)
			pcapFiles = append(pcapFiles, baselineFiles...)
		}
	}

	if opts.RealWorldDir != "" {
		realWorldFiles, err := pcap.CollectPcapFiles(opts.RealWorldDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not read real-world directory %s: %v\n", opts.RealWorldDir, err)
		} else {
			fmt.Fprintf(os.Stdout, "Found %d real-world PCAP file(s) in %s\n", len(realWorldFiles), opts.RealWorldDir)
			pcapFiles = append(pcapFiles, realWorldFiles...)
		}
	}

	if len(pcapFiles) == 0 {
		return fmt.Errorf("no PCAP files found in specified directories")
	}

	fmt.Fprintf(os.Stdout, "\nProcessing %d PCAP file(s)...\n\n", len(pcapFiles))

	totalExtracted := 0
	for _, pcapFile := range pcapFiles {
		source := determineSource(pcapFile, opts.BaselineDir, opts.RealWorldDir)
		fmt.Fprintf(os.Stdout, "Processing: %s (%s)\n", filepath.Base(pcapFile), source)

		refPackets, err := pcap.FindReferencePackets(pcapFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: Failed to extract from %s: %v\n", pcapFile, err)
			continue
		}

		err = pcap.PopulateReferenceLibraryFromPCAP(pcapFile, source)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: Failed to populate from %s: %v\n", pcapFile, err)
			continue
		}

		extracted := len(refPackets)
		totalExtracted += extracted
		fmt.Fprintf(os.Stdout, "  Extracted %d reference packet(s)\n", extracted)
		for key := range refPackets {
			fmt.Fprintf(os.Stdout, "    - %s\n", key)
		}
	}

	fmt.Fprintf(os.Stdout, "\nTotal: %d reference packet(s) extracted\n\n", totalExtracted)

	fmt.Fprintf(os.Stdout, "Reference packets found:\n")
	for key, ref := range reference.ReferencePackets {
		if len(ref.Data) > 0 {
			fmt.Fprintf(os.Stdout, "  ƒo. %s (%d bytes) - %s\n", key, len(ref.Data), ref.Source)
		} else {
			fmt.Fprintf(os.Stdout, "  ƒ?3 %s (not yet populated)\n", key)
		}
	}

	if opts.OutputFile != "" {
		fmt.Fprintf(os.Stdout, "\nWriting to %s...\n", opts.OutputFile)
		file, err := os.Create(opts.OutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer file.Close()

		if err := pcap.WriteReferencePacketsToFile(file); err != nil {
			return fmt.Errorf("write reference packets: %w", err)
		}
		fmt.Fprintf(os.Stdout, "Done!\n")
	} else {
		fmt.Fprintf(os.Stdout, "\nNote: Use --output to write reference packets to a Go source file\n")
	}

	return nil
}

func determineSource(pcapFile, baselineDir, realWorldDir string) string {
	if baselineDir != "" && filepath.Dir(pcapFile) == baselineDir {
		return "CIPDIP Baseline Capture"
	}
	if realWorldDir != "" {
		relPath, err := filepath.Rel(realWorldDir, pcapFile)
		if err == nil && !filepath.IsAbs(relPath) && relPath != ".." {
			return "Real-World Capture"
		}
	}
	return "PCAP File"
}
