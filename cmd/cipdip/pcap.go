package main

// Packet capture analysis command

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/pcap"
)

type pcapFlags struct {
	inputFile  string
	outputFile string
	format     string
	validate   bool
	compare    string
	hexdump    bool
}

func newPcapCmd() *cobra.Command {
	flags := &pcapFlags{}

	cmd := &cobra.Command{
		Use:   "pcap",
		Short: "Analyze packet captures",
		Long: `Analyze raw EtherNet/IP packet data for compliance and structure validation.

This command reads raw binary packet files (exported from Wireshark or captured directly)
and provides detailed analysis of the EtherNet/IP packet structure.

Features:
  - Parse ENIP header (command, session ID, status, data length)
  - Validate ODVA compliance (header structure, length consistency)
  - Compare two packets to find differences
  - Display hex dump with ASCII representation
  - Output in text or JSON format

The input file should contain raw binary EtherNet/IP packet data (ENIP header + data).
To create packet files:
  1. Capture packets with tcpdump or Wireshark
  2. In Wireshark: Right-click packet → "Export Packet Bytes"
  3. Save as binary file (.bin)

Use --validate to check if packets conform to ODVA EtherNet/IP specifications.
Use --compare to find differences between two packets (useful for vendor research).
Use --hexdump to view raw packet bytes in hex format.`,
		Example: `  # Analyze a packet
  cipdip pcap --input packet.bin

  # Validate ODVA compliance
  cipdip pcap --input packet.bin --validate

  # Compare two packets
  cipdip pcap --input packet1.bin --compare packet2.bin

  # Display hex dump
  cipdip pcap --input packet.bin --hexdump

  # Output as JSON
  cipdip pcap --input packet.bin --format json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPcap(flags)
		},
	}

	cmd.Flags().StringVar(&flags.inputFile, "input", "", "Input packet file (raw binary, required)")
	cmd.MarkFlagRequired("input")
	cmd.Flags().StringVar(&flags.outputFile, "output", "", "Output analysis file (default: stdout)")
	cmd.Flags().StringVar(&flags.format, "format", "text", "Output format: text|json (default \"text\")")
	cmd.Flags().BoolVar(&flags.validate, "validate", false, "Validate ODVA compliance")
	cmd.Flags().StringVar(&flags.compare, "compare", "", "Compare with another packet file")
	cmd.Flags().BoolVar(&flags.hexdump, "hexdump", false, "Display raw packet hex dump")

	return cmd
}

func runPcap(flags *pcapFlags) error {
	// Read input file
	data, err := os.ReadFile(flags.inputFile)
	if err != nil {
		return fmt.Errorf("read input file: %w", err)
	}

	// Handle hexdump first if requested
	if flags.hexdump {
		fmt.Fprintf(os.Stdout, pcap.FormatPacketHex(data, true))
		return nil
	}

	// Analyze packet
	info, err := pcap.AnalyzeENIPPacket(data)
	if err != nil {
		return fmt.Errorf("analyze packet: %w", err)
	}

	// Validate if requested
	if flags.validate {
		valid, errors := pcap.ValidateODVACompliance(data)
		if !valid {
			fmt.Fprintf(os.Stderr, "ODVA Compliance: FAILED\n")
			for _, errMsg := range errors {
				fmt.Fprintf(os.Stderr, "  - %s\n", errMsg)
			}
		} else {
			fmt.Fprintf(os.Stdout, "ODVA Compliance: PASSED\n")
		}
	}

	// Compare if requested
	if flags.compare != "" {
		compareData, err := os.ReadFile(flags.compare)
		if err != nil {
			return fmt.Errorf("read compare file: %w", err)
		}

		differences, err := pcap.ComparePackets(data, compareData)
		if err != nil {
			return fmt.Errorf("compare packets: %w", err)
		}

		if len(differences) == 0 {
			fmt.Fprintf(os.Stdout, "Packets are identical\n")
		} else {
			fmt.Fprintf(os.Stdout, "Differences found:\n")
			for _, diff := range differences {
				fmt.Fprintf(os.Stdout, "  - %s\n", diff)
			}
		}
	}

	// Output packet info
	if flags.format == "json" {
		// JSON output (simplified for now)
		fmt.Fprintf(os.Stdout, "{\n")
		fmt.Fprintf(os.Stdout, "  \"command\": \"0x%04X\",\n", info.ENIPCommand)
		fmt.Fprintf(os.Stdout, "  \"session_id\": \"0x%08X\",\n", info.SessionID)
		fmt.Fprintf(os.Stdout, "  \"data_length\": %d,\n", info.DataLength)
		fmt.Fprintf(os.Stdout, "  \"status\": \"0x%08X\",\n", info.Status)
		fmt.Fprintf(os.Stdout, "  \"is_valid\": %t", info.IsValid)
		if len(info.Errors) > 0 {
			fmt.Fprintf(os.Stdout, ",\n  \"errors\": [\n")
			for i, errMsg := range info.Errors {
				if i > 0 {
					fmt.Fprintf(os.Stdout, ",\n")
				}
				fmt.Fprintf(os.Stdout, "    \"%s\"", errMsg)
			}
			fmt.Fprintf(os.Stdout, "\n  ]")
		}
		fmt.Fprintf(os.Stdout, "\n}\n")
	} else {
		// Text output
		fmt.Fprintf(os.Stdout, "ENIP Packet Analysis:\n")
		fmt.Fprintf(os.Stdout, "  Command: 0x%04X\n", info.ENIPCommand)
		fmt.Fprintf(os.Stdout, "  Session ID: 0x%08X\n", info.SessionID)
		fmt.Fprintf(os.Stdout, "  Data Length: %d bytes\n", info.DataLength)
		fmt.Fprintf(os.Stdout, "  Status: 0x%08X\n", info.Status)
		fmt.Fprintf(os.Stdout, "  Valid: %t\n", info.IsValid)
		if len(info.Errors) > 0 {
			fmt.Fprintf(os.Stdout, "  Errors:\n")
			for _, errMsg := range info.Errors {
				fmt.Fprintf(os.Stdout, "    - %s\n", errMsg)
			}
		}

		// Show hex dump
		fmt.Fprintf(os.Stdout, "\nPacket Hex Dump:\n")
		fmt.Fprintf(os.Stdout, pcap.FormatPacketHex(data, true))
	}

	return nil
}

