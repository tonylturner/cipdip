package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

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
CPF usage, and common EPATHs.

If --input is omitted, the first positional argument is used.`,
		Example: `  # Summarize ENIP.pcap traffic
  cipdip pcap-summary --input pcaps/stress/ENIP.pcap`,
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
			return runPcapSummary(flags)
		},
	}

	cmd.Flags().StringVar(&flags.inputFile, "input", "", "Input PCAP file (required)")

	return cmd
}

func runPcapSummary(flags *pcapSummaryFlags) error {
	summary, err := cipclient.SummarizeENIPFromPCAP(flags.inputFile)
	if err != nil {
		return fmt.Errorf("summarize pcap: %w", err)
	}

	writePcapSummary(os.Stdout, summary)

	return nil
}

func writePcapSummary(w io.Writer, summary *cipclient.PCAPSummary) {
	fmt.Fprintf(w, "PCAP Summary:\n")
	fmt.Fprintf(w, "  Total packets: %d\n", summary.TotalPackets)
	fmt.Fprintf(w, "  ENIP packets: %d\n", summary.ENIPPackets)
	fmt.Fprintf(w, "  Requests: %d\n", summary.Requests)
	fmt.Fprintf(w, "  Responses: %d\n", summary.Responses)
	fmt.Fprintf(w, "  CPF used: %d\n", summary.CPFUsed)
	fmt.Fprintf(w, "  CPF missing: %d\n", summary.CPFMissing)
	fmt.Fprintf(w, "  CIP requests: %d\n", summary.CIPRequests)
	fmt.Fprintf(w, "  CIP responses: %d\n", summary.CIPResponses)
	fmt.Fprintf(w, "  CIP payloads (UCMM): %d\n", summary.CIPPayloads)
	fmt.Fprintf(w, "  I/O payloads (connected): %d\n", summary.IOPayloads)
	fmt.Fprintf(w, "  EPATH 16-bit class: %d\n", summary.EPATH16Class)
	fmt.Fprintf(w, "  EPATH 16-bit instance: %d\n", summary.EPATH16Instance)
	fmt.Fprintf(w, "  EPATH 16-bit attribute: %d\n", summary.EPATH16Attribute)
	fmt.Fprintf(w, "  CIP path size used: %d\n", summary.PathSizeUsed)
	fmt.Fprintf(w, "  CIP path size missing: %d\n", summary.PathSizeMissing)
	if summary.VendorID != 0 || summary.ProductName != "" {
		fmt.Fprintf(w, "  Vendor ID: 0x%04X\n", summary.VendorID)
		if summary.ProductName != "" {
			fmt.Fprintf(w, "  Product Name: %s\n", summary.ProductName)
		}
	}

	if len(summary.Commands) > 0 {
		fmt.Fprintf(w, "\nCommand Counts:\n")
		printCounts(w, summary.Commands)
	}
	if len(summary.CIPServices) > 0 {
		fmt.Fprintf(w, "\nCIP Service Counts:\n")
		printCounts(w, summary.CIPServices)
	}
	if summary.RequestValidationTotal > 0 {
		fmt.Fprintf(w, "\nCIP Request Validation (strict): %d total, %d failed\n", summary.RequestValidationTotal, summary.RequestValidationFailed)
		if len(summary.RequestValidationErrors) > 0 {
			fmt.Fprintf(w, "\nCIP Request Validation Errors:\n")
			printValidationErrors(w, summary.RequestValidationErrors)
		}
	}
	if len(summary.EmbeddedServices) > 0 {
		fmt.Fprintf(w, "\nEmbedded CIP Service Counts:\n")
		printCounts(w, summary.EmbeddedServices)
	}
	if len(summary.EmbeddedUnknown) > 0 {
		fmt.Fprintf(w, "\nEmbedded Unknown CIP Service Details:\n")
		printUnknownStats(w, summary.EmbeddedUnknown)
	}
	if len(summary.UnknownServices) > 0 {
		fmt.Fprintf(w, "\nUnknown CIP Service Details:\n")
		printUnknownStats(w, summary.UnknownServices)
	}
	if len(summary.UnknownPairs) > 0 {
		fmt.Fprintf(w, "\nTop Unknown Service+Class Pairs:\n")
		for _, item := range topUnknownPairs(summary.UnknownPairs, 10) {
			fmt.Fprintf(w, "  %s\n", item)
		}
	}
	if len(summary.TopPaths) > 0 {
		fmt.Fprintf(w, "\nTop Paths:\n")
		for _, path := range summary.TopPaths {
			fmt.Fprintf(w, "  %s\n", path)
		}
	}
}

func printCounts(w io.Writer, values map[string]int) {
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
		fmt.Fprintf(w, "  %s: %d\n", item.Key, item.Value)
	}
}

func printUnknownStats(w io.Writer, unknown map[uint8]*cipclient.CIPUnknownStats) {
	type kv struct {
		Key   uint8
		Value int
	}
	list := make([]kv, 0, len(unknown))
	for k, v := range unknown {
		list = append(list, kv{Key: k, Value: v.Count})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Value == list[j].Value {
			return list[i].Key < list[j].Key
		}
		return list[i].Value > list[j].Value
	})
	for _, item := range list {
		stats := unknown[item.Key]
		fmt.Fprintf(w, "  Unknown(0x%02X): count=%d responses=%d", item.Key, stats.Count, stats.ResponseCount)
		if len(stats.ClassCounts) > 0 {
			fmt.Fprintf(w, " classes=%s", formatUint16Counts(stats.ClassCounts))
		}
		if len(stats.InstanceCounts) > 0 {
			fmt.Fprintf(w, " instances=%s", formatUint16Counts(stats.InstanceCounts))
		}
		if len(stats.AttributeCounts) > 0 {
			fmt.Fprintf(w, " attributes=%s", formatUint16Counts(stats.AttributeCounts))
		}
		if len(stats.StatusCounts) > 0 {
			fmt.Fprintf(w, " status=%s", formatUint8Counts(stats.StatusCounts))
		}
		fmt.Fprint(w, "\n")
	}
}

func formatUint16Counts(values map[uint16]int) string {
	type kv struct {
		Key   uint16
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
	parts := make([]string, 0, len(list))
	for _, item := range list {
		parts = append(parts, fmt.Sprintf("0x%04X:%d", item.Key, item.Value))
	}
	return fmt.Sprintf("[%s]", strings.Join(parts, ", "))
}

func formatUint8Counts(values map[uint8]int) string {
	type kv struct {
		Key   uint8
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
	parts := make([]string, 0, len(list))
	for _, item := range list {
		parts = append(parts, fmt.Sprintf("0x%02X:%d", item.Key, item.Value))
	}
	return fmt.Sprintf("[%s]", strings.Join(parts, ", "))
}

func topUnknownPairs(values map[string]int, max int) []string {
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
	if len(list) > max {
		list = list[:max]
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, fmt.Sprintf("%s (%d)", item.Key, item.Value))
	}
	return out
}

func printValidationErrors(w io.Writer, errors map[string]int) {
	type kv struct {
		Key   string
		Value int
	}
	list := make([]kv, 0, len(errors))
	for k, v := range errors {
		list = append(list, kv{Key: k, Value: v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Value == list[j].Value {
			return list[i].Key < list[j].Key
		}
		return list[i].Value > list[j].Value
	})
	if len(list) > 10 {
		list = list[:10]
	}
	for _, item := range list {
		fmt.Fprintf(w, "  %s (%d)\n", item.Key, item.Value)
	}
}
