package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/cipclient"
)

type pcapSummaryFlags struct {
	inputFile string
}

func newPcapSummaryCmd() *cobra.Command {
	flags := &pcapSummaryFlags{}

	cmd := &cobra.Command{
		Use:   "pcap-summary",
		Short: "Summarize ENIP/CIP traffic in a PCAP file",
		Long: `Summarize ENIP/CIP traffic in a PCAP file, including command/service counts,
CPF usage, and common EPATHs.`,
		Example: `  # Summarize ENIP.pcap traffic
  cipdip pcap-summary --input pcaps/ENIP.pcap`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPcapSummary(flags)
		},
	}

	cmd.Flags().StringVar(&flags.inputFile, "input", "", "Input PCAP file (required)")
	cmd.MarkFlagRequired("input")

	return cmd
}

func runPcapSummary(flags *pcapSummaryFlags) error {
	summary, err := cipclient.SummarizeENIPFromPCAP(flags.inputFile)
	if err != nil {
		return fmt.Errorf("summarize pcap: %w", err)
	}

	fmt.Fprintf(os.Stdout, "PCAP Summary:\n")
	fmt.Fprintf(os.Stdout, "  Total packets: %d\n", summary.TotalPackets)
	fmt.Fprintf(os.Stdout, "  ENIP packets: %d\n", summary.ENIPPackets)
	fmt.Fprintf(os.Stdout, "  Requests: %d\n", summary.Requests)
	fmt.Fprintf(os.Stdout, "  Responses: %d\n", summary.Responses)
	fmt.Fprintf(os.Stdout, "  CPF used: %d\n", summary.CPFUsed)
	fmt.Fprintf(os.Stdout, "  CPF missing: %d\n", summary.CPFMissing)
	fmt.Fprintf(os.Stdout, "  CIP requests: %d\n", summary.CIPRequests)
	fmt.Fprintf(os.Stdout, "  CIP responses: %d\n", summary.CIPResponses)
	fmt.Fprintf(os.Stdout, "  CIP payloads (UCMM): %d\n", summary.CIPPayloads)
	fmt.Fprintf(os.Stdout, "  I/O payloads (connected): %d\n", summary.IOPayloads)
	fmt.Fprintf(os.Stdout, "  EPATH 16-bit class: %d\n", summary.EPATH16Class)
	fmt.Fprintf(os.Stdout, "  EPATH 16-bit instance: %d\n", summary.EPATH16Instance)
	fmt.Fprintf(os.Stdout, "  EPATH 16-bit attribute: %d\n", summary.EPATH16Attribute)
	fmt.Fprintf(os.Stdout, "  CIP path size used: %d\n", summary.PathSizeUsed)
	fmt.Fprintf(os.Stdout, "  CIP path size missing: %d\n", summary.PathSizeMissing)
	if summary.VendorID != 0 || summary.ProductName != "" {
		fmt.Fprintf(os.Stdout, "  Vendor ID: 0x%04X\n", summary.VendorID)
		if summary.ProductName != "" {
			fmt.Fprintf(os.Stdout, "  Product Name: %s\n", summary.ProductName)
		}
	}

	if len(summary.Commands) > 0 {
		fmt.Fprintf(os.Stdout, "\nCommand Counts:\n")
		printCounts(summary.Commands)
	}
	if len(summary.CIPServices) > 0 {
		fmt.Fprintf(os.Stdout, "\nCIP Service Counts:\n")
		printCounts(summary.CIPServices)
	}
	if len(summary.TopPaths) > 0 {
		fmt.Fprintf(os.Stdout, "\nTop Paths:\n")
		for _, path := range summary.TopPaths {
			fmt.Fprintf(os.Stdout, "  %s\n", path)
		}
	}

	return nil
}

func printCounts(values map[string]int) {
	type kv struct {
		Key   string
		Value int
	}
	list := make([]kv, 0, len(values))
	for k, v := range values {
		list = append(list, kv{Key: k, Value: v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Value == list[j].Value {
			return list[i].Key < list[j].Key
		}
		return list[i].Value > list[j].Value
	})
	for _, item := range list {
		fmt.Fprintf(os.Stdout, "  %s: %d\n", item.Key, item.Value)
	}
}
