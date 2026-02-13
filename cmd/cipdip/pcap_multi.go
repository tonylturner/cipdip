package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/pcap"
)

type pcapMultiFlags struct {
	inputFile string
}

func newPcapMultiCmd() *cobra.Command {
	flags := &pcapMultiFlags{}

	cmd := &cobra.Command{
		Use:   "pcap-multi",
		Short: "Multi-protocol analysis of a PCAP file",
		Long: `Analyze a PCAP file for multiple industrial protocols (ENIP, Modbus TCP, DH+).
Produces a protocol breakdown with per-protocol message counts and port summary.

If --input is omitted, the first positional argument is used.`,
		Example: `  # Multi-protocol analysis
  cipdip pcap-multi --input pcaps/mixed_traffic.pcap`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if handleHelpArg(cmd, args) {
				return nil
			}
			if flags.inputFile == "" && len(args) > 0 {
				flags.inputFile = args[0]
			}
			if flags.inputFile == "" {
				return missingFlagError(cmd, "--input")
			}
			return runPcapMulti(flags)
		},
	}

	cmd.Flags().StringVar(&flags.inputFile, "input", "", "Input PCAP file (required)")

	return cmd
}

func runPcapMulti(flags *pcapMultiFlags) error {
	result, err := pcap.ExtractMultiProtocol(flags.inputFile)
	if err != nil {
		return fmt.Errorf("multi-protocol extraction: %w", err)
	}

	fmt.Fprintln(os.Stdout, "Multi-Protocol PCAP Analysis")
	fmt.Fprintln(os.Stdout, "============================")
	fmt.Fprintf(os.Stdout, "File: %s\n", flags.inputFile)
	fmt.Fprintf(os.Stdout, "Total packets: %d\n\n", result.TotalPackets)

	fmt.Fprintln(os.Stdout, "Protocol Breakdown:")
	fmt.Fprintf(os.Stdout, "  ENIP/CIP:    %d messages\n", result.ENIPCount)
	fmt.Fprintf(os.Stdout, "  Modbus TCP:  %d messages\n", result.ModbusCount)
	fmt.Fprintf(os.Stdout, "  DH+:         %d messages\n", result.DHPlusCount)
	fmt.Fprintf(os.Stdout, "  Unknown:     %d packets\n", result.UnknownCount)

	if len(result.PortSummary) > 0 {
		fmt.Fprintln(os.Stdout, "\nPort Summary:")
		// Sort ports for deterministic output
		ports := make([]int, 0, len(result.PortSummary))
		for port := range result.PortSummary {
			ports = append(ports, int(port))
		}
		sort.Ints(ports)
		for _, port := range ports {
			count := result.PortSummary[uint16(port)]
			fmt.Fprintf(os.Stdout, "  port %-6d: %d packets\n", port, count)
		}
	}

	if len(result.Messages) > 0 {
		fmt.Fprintf(os.Stdout, "\nTimeline: %d protocol messages (first → last)\n", len(result.Messages))
		first := result.Messages[0]
		last := result.Messages[len(result.Messages)-1]
		fmt.Fprintf(os.Stdout, "  First: %s %s\n", first.Timestamp.Format("15:04:05.000"), first.Description)
		fmt.Fprintf(os.Stdout, "  Last:  %s %s\n", last.Timestamp.Format("15:04:05.000"), last.Description)
		duration := last.Timestamp.Sub(first.Timestamp)
		fmt.Fprintf(os.Stdout, "  Duration: %v\n", duration)
	}

	return nil
}
