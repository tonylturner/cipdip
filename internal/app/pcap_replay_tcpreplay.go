package app

import (
	"fmt"
	"os"

	pcappkg "github.com/tonylturner/cipdip/internal/pcap"
)

func runTcpreplay(opts *PCAPReplayOptions) error {
	if opts.Iface == "" {
		return fmt.Errorf("iface is required for tcpreplay mode")
	}

	if err := primeARP(opts); err != nil {
		return err
	}

	if opts.ARPRefreshMs > 0 {
		fmt.Fprintln(os.Stdout, "Warning: arp-refresh-ms is not supported in tcpreplay mode; ignoring.")
	}

	tcpreplayPath, err := ResolveExternalPath(opts.TcpreplayPath, "TCPREPLAY", "tcpreplay")
	if err != nil {
		return err
	}

	pcapPath := opts.Input
	if len(opts.TcprewriteArgs) > 0 || hasRewriteFlags(opts) {
		tcprewritePath, err := ResolveExternalPath(opts.TcprewritePath, "TCPREWRITE", "tcprewrite")
		if err != nil {
			return err
		}
		tmp, err := os.CreateTemp("", "cipdip_tcprewrite_*.pcap")
		if err != nil {
			return fmt.Errorf("create temp pcap: %w", err)
		}
		tmp.Close()
		defer os.Remove(tmp.Name())

		args := []string{"-i", opts.Input, "-o", tmp.Name()}
		args = append(args, buildTcprewriteArgs(opts)...)
		args = append(args, opts.TcprewriteArgs...)
		if err := runExternal(tcprewritePath, args); err != nil {
			return err
		}
		pcapPath = tmp.Name()
	}

	args := []string{"-i", opts.Iface}
	args = append(args, opts.TcpreplayArgs...)
	args = append(args, pcapPath)
	if opts.Report {
		if summary, err := pcappkg.SummarizePcapForReplay(opts.Input); err == nil {
			printReplaySummary("tcpreplay", replaySummaryFromPCAP(summary))
		}
	}
	return runExternal(tcpreplayPath, args)
}

func buildTcprewriteArgs(opts *PCAPReplayOptions) []string {
	args := make([]string, 0, 4)
	if opts.RewriteSrcIP != "" {
		args = append(args, fmt.Sprintf("--srcipmap=0.0.0.0/0:%s", opts.RewriteSrcIP))
	}
	if opts.RewriteDstIP != "" {
		args = append(args, fmt.Sprintf("--dstipmap=0.0.0.0/0:%s", opts.RewriteDstIP))
	}
	if opts.RewriteSrcPort > 0 {
		args = append(args, fmt.Sprintf("--portmap=0:%d", opts.RewriteSrcPort))
	}
	if opts.RewriteDstPort > 0 {
		args = append(args, fmt.Sprintf("--portmap=0:%d", opts.RewriteDstPort))
	}
	return args
}
