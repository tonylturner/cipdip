package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/pcap"
	"github.com/tturner/cipdip/internal/report"
)

type pcapClassifyFlags struct {
	pcapDir         string
	tsharkPath      string
	outCSV          string
	outTxt          string
	maxTcpRst       int
	maxTcpRetrans   int
	maxTcpLostSeg   int
	maxCipErrorRate float64
	maxMalformed    int
	maxExpertErrors int
}

func newPcapClassifyCmd() *cobra.Command {
	flags := &pcapClassifyFlags{}

	cmd := &cobra.Command{
		Use:   "pcap-classify",
		Short: "Classify PCAPs with tshark-derived integrity signals",
		Long: `Classify PCAPs using tshark filters for ENIP/CIP presence,
transport noise, malformed frames, and CIP error rates.`,
		Example: `  # Classify all PCAPs under ./pcaps
  cipdip pcap-classify --pcap-dir pcaps`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPcapClassify(flags)
		},
	}

	cmd.Flags().StringVar(&flags.pcapDir, "pcap-dir", "pcaps", "Directory containing PCAP files")
	cmd.Flags().StringVar(&flags.tsharkPath, "tshark", "", "Optional path to tshark (defaults to PATH or Windows install)")
	cmd.Flags().StringVar(&flags.outCSV, "out-csv", "cip_pcap_summary.csv", "CSV output path")
	cmd.Flags().StringVar(&flags.outTxt, "out-txt", "cip_pcap_summary.txt", "Summary output path")
	cmd.Flags().IntVar(&flags.maxTcpRst, "max-tcp-rst", 5, "RST threshold for transport noise")
	cmd.Flags().IntVar(&flags.maxTcpRetrans, "max-tcp-retrans", 500, "Retransmission threshold for transport noise")
	cmd.Flags().IntVar(&flags.maxTcpLostSeg, "max-tcp-lostseg", 5, "Lost segment threshold for transport noise")
	cmd.Flags().Float64Var(&flags.maxCipErrorRate, "max-cip-error-rate", 0.05, "CIP error rate threshold")
	cmd.Flags().IntVar(&flags.maxMalformed, "max-malformed", 0, "Malformed frame threshold")
	cmd.Flags().IntVar(&flags.maxExpertErrors, "max-expert-errors", 0, "tshark expert error threshold")

	return cmd
}

func runPcapClassify(flags *pcapClassifyFlags) error {
	pcaps, err := pcap.CollectPcapFiles(flags.pcapDir)
	if err != nil {
		return err
	}
	if len(pcaps) == 0 {
		return fmt.Errorf("no .pcap/.pcapng files found under %s", flags.pcapDir)
	}

	tsharkPath, err := pcap.ResolveTsharkPath(flags.tsharkPath)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Found %d capture(s) under %s\n", len(pcaps), flags.pcapDir)
	fmt.Fprintf(os.Stdout, "Using tshark: %s\n", tsharkPath)
	fmt.Fprintf(os.Stdout, "Noise thresholds: RST>%d, Retrans>%d, LostSeg>%d\n",
		flags.maxTcpRst, flags.maxTcpRetrans, flags.maxTcpLostSeg)
	fmt.Fprintf(os.Stdout, "Fuzz thresholds: CipErrorRate>%.2f, Malformed>%d, ExpertErrors>%d\n\n",
		flags.maxCipErrorRate, flags.maxMalformed, flags.maxExpertErrors)

	rows, err := pcap.ClassifyPCAPs(tsharkPath, pcaps, pcap.ClassifyOptions{
		MaxTcpRst:       flags.maxTcpRst,
		MaxTcpRetrans:   flags.maxTcpRetrans,
		MaxTcpLostSeg:   flags.maxTcpLostSeg,
		MaxCipErrorRate: flags.maxCipErrorRate,
		MaxMalformed:    flags.maxMalformed,
		MaxExpertErrors: flags.maxExpertErrors,
	})
	if err != nil {
		return err
	}

	for _, row := range rows {
		reason := row.IntegrityReasons
		flagText := row.Flags
		switch {
		case flagText != "" && reason != "":
			fmt.Fprintf(os.Stdout, "[%s] %s :: %s :: %s\n", row.Integrity, row.File, reason, flagText)
		case reason != "":
			fmt.Fprintf(os.Stdout, "[%s] %s :: %s\n", row.Integrity, row.File, reason)
		case flagText != "":
			fmt.Fprintf(os.Stdout, "[%s] %s :: %s\n", row.Integrity, row.File, flagText)
		default:
			fmt.Fprintf(os.Stdout, "[%s] %s\n", row.Integrity, row.File)
		}
	}

	if err := report.WritePCAPClassifyCSV(flags.outCSV, rows); err != nil {
		return err
	}
	if err := report.WritePCAPClassifySummary(flags.outTxt, flags.outCSV, flags.pcapDir, tsharkPath, rows); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\nWrote:\n  %s\n  %s\n", flags.outCSV, flags.outTxt)
	return nil
}
