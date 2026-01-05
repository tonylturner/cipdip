package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/cipclient"
)

type extractFlags struct {
	pcapDir      string
	outputFile   string
	baselineDir  string
	realWorldDir string
}

func newExtractReferenceCmd() *cobra.Command {
	flags := &extractFlags{}

	cmd := &cobra.Command{
		Use:   "extract-reference",
		Short: "Extract reference packets from PCAP files",
		Long: `Extract reference packets from PCAP files and populate the reference library.

This command scans PCAP files for key CIP/ENIP packets (RegisterSession, GetAttributeSingle,
ForwardOpen, etc.) and extracts them as reference packets for validation.

It will look for PCAP files in:
  - baseline_captures/ (cipdip-generated captures)
  - pcaps/ (real-world captures, including normal/stress)
  - Or specify custom directories with --baseline-dir and --real-world-dir

The extracted packets are normalized (session IDs zeroed) so they can be used for comparison
across different sessions.`,
		Example: `  # Extract from default locations
  cipdip extract-reference

  # Extract from custom directories
  cipdip extract-reference --baseline-dir ./my_captures --real-world-dir ./real_pcaps

  # Extract and write to Go source file
  cipdip extract-reference --output internal/cipclient/reference_packets_gen.go`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExtractReference(flags)
		},
	}

	cmd.Flags().StringVar(&flags.baselineDir, "baseline-dir", "baseline_captures", "Directory containing baseline PCAP files")
	cmd.Flags().StringVar(&flags.realWorldDir, "real-world-dir", "pcaps", "Directory containing real-world PCAP files")
	cmd.Flags().StringVar(&flags.outputFile, "output", "", "Output Go source file (default: update reference.go directly)")

	return cmd
}

func runExtractReference(flags *extractFlags) error {
	fmt.Fprintf(os.Stdout, "Extracting reference packets from PCAP files...\n\n")
	cipclient.ResetReferencePackets()

	// Find PCAP files
	var pcapFiles []string

	// Baseline captures
	if flags.baselineDir != "" {
		baselineFiles, err := findPCAPFiles(flags.baselineDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not read baseline directory %s: %v\n", flags.baselineDir, err)
		} else {
			fmt.Fprintf(os.Stdout, "Found %d baseline PCAP file(s) in %s\n", len(baselineFiles), flags.baselineDir)
			pcapFiles = append(pcapFiles, baselineFiles...)
		}
	}

	// Real-world captures
	if flags.realWorldDir != "" {
		realWorldFiles, err := findPCAPFiles(flags.realWorldDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not read real-world directory %s: %v\n", flags.realWorldDir, err)
		} else {
			fmt.Fprintf(os.Stdout, "Found %d real-world PCAP file(s) in %s\n", len(realWorldFiles), flags.realWorldDir)
			pcapFiles = append(pcapFiles, realWorldFiles...)
		}
	}

	if len(pcapFiles) == 0 {
		return fmt.Errorf("no PCAP files found in specified directories")
	}

	fmt.Fprintf(os.Stdout, "\nProcessing %d PCAP file(s)...\n\n", len(pcapFiles))

	// Process each PCAP file
	totalExtracted := 0
	for _, pcapFile := range pcapFiles {
		source := determineSource(pcapFile, flags.baselineDir, flags.realWorldDir)
		fmt.Fprintf(os.Stdout, "Processing: %s (%s)\n", filepath.Base(pcapFile), source)

		refPackets, err := cipclient.FindReferencePackets(pcapFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: Failed to extract from %s: %v\n", pcapFile, err)
			continue
		}

		// Populate reference library
		err = cipclient.PopulateReferenceLibraryFromPCAP(pcapFile, source)
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

	// Show summary
	fmt.Fprintf(os.Stdout, "Reference packets found:\n")
	for key, ref := range cipclient.ReferencePackets {
		if len(ref.Data) > 0 {
			fmt.Fprintf(os.Stdout, "  ✅ %s (%d bytes) - %s\n", key, len(ref.Data), ref.Source)
		} else {
			fmt.Fprintf(os.Stdout, "  ⏳ %s (not yet populated)\n", key)
		}
	}

	// Write to file if requested
	if flags.outputFile != "" {
		fmt.Fprintf(os.Stdout, "\nWriting to %s...\n", flags.outputFile)
		file, err := os.Create(flags.outputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer file.Close()

		if err := cipclient.WriteReferencePacketsToFile(file); err != nil {
			return fmt.Errorf("write reference packets: %w", err)
		}
		fmt.Fprintf(os.Stdout, "Done!\n")
	} else {
		fmt.Fprintf(os.Stdout, "\nNote: Use --output to write reference packets to a Go source file\n")
	}

	return nil
}

func findPCAPFiles(dir string) ([]string, error) {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			ext := filepath.Ext(path)
			if ext == ".pcap" || ext == ".pcapng" {
				files = append(files, path)
			}
		}
		return nil
	})

	return files, err
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
