package main

import (
	"fmt"
	"net"
	"os"

	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/pcap"
)

type pcapRewriteFlags struct {
	input          string
	output         string
	srcIP          string
	dstIP          string
	srcPort        int
	dstPort        int
	srcMAC         string
	dstMAC         string
	onlyENIP       bool
	recomputeCksum bool
	report         bool
}

func newPcapRewriteCmd() *cobra.Command {
	flags := &pcapRewriteFlags{}

	cmd := &cobra.Command{
		Use:   "pcap-rewrite",
		Short: "Rewrite IP/port fields in a PCAP",
		Long: `Rewrite source/destination IPs and ports for ENIP/CIP traffic.
This is useful before tcpreplay when you need to map captures to lab endpoints.`,
		Example: `  # Rewrite IPs for ENIP traffic only
  cipdip pcap-rewrite --input capture.pcap --output rewritten.pcap --src-ip 10.0.0.20 --dst-ip 10.0.0.10`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if handleHelpArg(cmd, args) {
				return nil
			}
			if flags.input == "" {
				return missingFlagError(cmd, "--input")
			}
			if flags.output == "" {
				return missingFlagError(cmd, "--output")
			}
			return runPcapRewrite(flags)
		},
	}

	cmd.Flags().StringVar(&flags.input, "input", "", "Input PCAP file (required)")
	cmd.Flags().StringVar(&flags.output, "output", "", "Output PCAP file (required)")
	cmd.Flags().StringVar(&flags.srcIP, "src-ip", "", "Rewrite source IP address")
	cmd.Flags().StringVar(&flags.dstIP, "dst-ip", "", "Rewrite destination IP address")
	cmd.Flags().IntVar(&flags.srcPort, "src-port", 0, "Rewrite source port")
	cmd.Flags().IntVar(&flags.dstPort, "dst-port", 0, "Rewrite destination port")
	cmd.Flags().StringVar(&flags.srcMAC, "src-mac", "", "Rewrite source MAC address")
	cmd.Flags().StringVar(&flags.dstMAC, "dst-mac", "", "Rewrite destination MAC address")
	cmd.Flags().BoolVar(&flags.onlyENIP, "only-enip", true, "Only rewrite packets on 44818/2222 when enabled")
	cmd.Flags().BoolVar(&flags.recomputeCksum, "recompute-checksums", true, "Recompute IP/TCP/UDP checksums")
	cmd.Flags().BoolVar(&flags.report, "report", true, "Print a summary report after rewrite")

	return cmd
}

func runPcapRewrite(flags *pcapRewriteFlags) error {
	srcIP := net.ParseIP(flags.srcIP)
	dstIP := net.ParseIP(flags.dstIP)
	srcMAC, err := pcap.ParseMAC(flags.srcMAC)
	if err != nil {
		return err
	}
	dstMAC, err := pcap.ParseMAC(flags.dstMAC)
	if err != nil {
		return err
	}

	stats, err := pcap.RewritePCAP(flags.input, flags.output, pcap.RewriteOptions{
		SrcIP:              srcIP,
		DstIP:              dstIP,
		SrcPort:            flags.srcPort,
		DstPort:            flags.dstPort,
		SrcMAC:             srcMAC,
		DstMAC:             dstMAC,
		OnlyENIP:           flags.onlyENIP,
		RecomputeChecksums: flags.recomputeCksum,
	})
	if err != nil {
		return err
	}

	if flags.report {
		fmt.Fprintf(os.Stdout, "Rewrite summary: total=%d rewritten=%d skipped=%d errors=%d\n",
			stats.Total, stats.Rewritten, stats.Skipped, stats.Errors)
	}

	return nil
}
