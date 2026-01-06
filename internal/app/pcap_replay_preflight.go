package app

import (
	"fmt"
	"os"
	"strings"

	pcappkg "github.com/tturner/cipdip/internal/pcap"
)

func warnIfMissingHandshake(opts *PCAPReplayOptions) error {
	mode := strings.ToLower(opts.Mode)
	if mode == "app" {
		return nil
	}
	ok, err := pcappkg.HasTCPHandshake(opts.Input)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(os.Stdout, "Warning: PCAP does not include a full TCP handshake for 44818; stateful firewalls may drop replay.")
	}
	ok, _, err = pcappkg.HasPerFlowTCPHandshake(opts.Input)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(os.Stdout, "Warning: PCAP missing per-flow SYN/SYN-ACK/ACK for 44818; stateful firewalls may drop replay.")
	}
	return nil
}

func runPcapPreflight(opts *PCAPReplayOptions) error {
	mode := strings.ToLower(opts.Mode)
	switch mode {
	case "app":
		if opts.ServerIP == "" {
			return fmt.Errorf("server-ip is required for app replay preflight")
		}
	case "raw", "tcpreplay":
		if opts.Iface == "" {
			return fmt.Errorf("iface is required for %s replay preflight", mode)
		}
	default:
		return fmt.Errorf("unknown replay mode '%s'; use app, raw, or tcpreplay", opts.Mode)
	}

	if opts.Report {
		if summary, err := pcappkg.SummarizePcapForReplay(opts.Input); err == nil {
			printReplaySummary("preflight", replaySummaryFromPCAP(summary))
		} else {
			return err
		}
	}

	if mode == "raw" || mode == "tcpreplay" {
		if opts.ARPRefreshMs > 0 && mode == "tcpreplay" {
			fmt.Fprintln(os.Stdout, "Warning: arp-refresh-ms is not supported in tcpreplay mode; ignoring.")
		}
		if err := primeARP(opts); err != nil {
			return err
		}
	}

	return nil
}
