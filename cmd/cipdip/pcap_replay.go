package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/app"
	pcappkg "github.com/tonylturner/cipdip/internal/pcap"
)

type pcapReplayFlags struct {
	input           string
	preset          string
	presetDir       string
	listPresets     bool
	presetAll       bool
	mode            string
	serverIP        string
	serverPort      int
	udpPort         int
	clientIP        string
	rewriteSrcIP    string
	rewriteDstIP    string
	rewriteSrcPort  int
	rewriteDstPort  int
	rewriteSrcMAC   string
	rewriteDstMAC   string
	rewriteOnlyENIP bool
	arpTarget       string
	arpTimeoutMs    int
	arpRetries      int
	arpRequired     bool
	arpAutoRewrite  bool
	arpRefreshMs    int
	arpDriftFail    bool
	intervalMs      int
	realtime        bool
	includeResponse bool
	limit           int
	iface           string
	tcpreplayPath   string
	tcprewritePath  string
	tcpreplayArgs   []string
	tcprewriteArgs  []string
	report          bool
	preflightOnly   bool
}

func newPcapReplayCmd() *cobra.Command {
	flags := &pcapReplayFlags{}

	cmd := &cobra.Command{
		Use:   "pcap-replay",
		Short: "Replay ENIP/CIP traffic from a PCAP",
		Long: `Replay ENIP/CIP traffic from a PCAP using one of three modes:
  app      - Application-layer replay (default, cross-platform)
  raw      - Raw packet injection (requires OS/NIC support and privileges)
  tcpreplay - External tcpreplay/tcprewrite integration`,
		Example: `  # App-layer replay to server IP (default mode)
  cipdip pcap-replay --input pcaps/stress/ENIP.pcap --server-ip 10.0.0.10

  # Raw injection using a specific interface
  cipdip pcap-replay --input pcaps/stress/ENIP.pcap --mode raw --iface eth0

  # Use tcprewrite/tcpreplay with custom args
  cipdip pcap-replay --input pcaps/stress/ENIP.pcap --mode tcpreplay --iface eth0 \
    --tcprewrite-arg "--dstipmap=192.168.1.50:10.0.0.10" --tcpreplay-arg "--topspeed"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if handleHelpArg(cmd, args) {
				return nil
			}
			if flags.listPresets {
				printPcapPresets()
				return nil
			}
			if flags.input == "" && flags.preset == "" {
				return missingFlagError(cmd, "--input")
			}
			return runPcapReplay(flags)
		},
	}

	cmd.Flags().StringVar(&flags.input, "input", "", "Input PCAP file (required)")
	cmd.Flags().StringVar(&flags.preset, "preset", "", "Replay preset name (e.g., cl5000eip:firmware-change)")
	cmd.Flags().StringVar(&flags.presetDir, "preset-dir", "pcaps", "Root directory to search for preset PCAPs")
	cmd.Flags().BoolVar(&flags.listPresets, "list-presets", false, "List available presets and exit")
	cmd.Flags().BoolVar(&flags.presetAll, "preset-all", false, "Replay all matching preset files (when preset expands to multiple)")
	cmd.Flags().StringVar(&flags.mode, "mode", "app", "Replay mode: app|raw|tcpreplay")
	cmd.Flags().StringVar(&flags.serverIP, "server-ip", "", "Server IP for app-layer replay")
	cmd.Flags().IntVar(&flags.serverPort, "server-port", 44818, "Server TCP port for app-layer replay")
	cmd.Flags().IntVar(&flags.udpPort, "udp-port", 2222, "Server UDP port for app-layer replay")
	cmd.Flags().StringVar(&flags.clientIP, "client-ip", "", "Local client IP to bind for app-layer replay")
	cmd.Flags().StringVar(&flags.rewriteSrcIP, "rewrite-src-ip", "", "Rewrite source IP in replay PCAP (raw/tcpreplay)")
	cmd.Flags().StringVar(&flags.rewriteDstIP, "rewrite-dst-ip", "", "Rewrite destination IP in replay PCAP (raw/tcpreplay)")
	cmd.Flags().IntVar(&flags.rewriteSrcPort, "rewrite-src-port", 0, "Rewrite source port in replay PCAP (raw/tcpreplay)")
	cmd.Flags().IntVar(&flags.rewriteDstPort, "rewrite-dst-port", 0, "Rewrite destination port in replay PCAP (raw/tcpreplay)")
	cmd.Flags().StringVar(&flags.rewriteSrcMAC, "rewrite-src-mac", "", "Rewrite source MAC in replay PCAP (raw/tcpreplay)")
	cmd.Flags().StringVar(&flags.rewriteDstMAC, "rewrite-dst-mac", "", "Rewrite destination MAC in replay PCAP (raw/tcpreplay)")
	cmd.Flags().BoolVar(&flags.rewriteOnlyENIP, "rewrite-only-enip", true, "Only rewrite packets on 44818/2222 when enabled")
	cmd.Flags().StringVar(&flags.arpTarget, "arp-target", "", "Send ARP request before replay (raw/tcpreplay)")
	cmd.Flags().IntVar(&flags.arpTimeoutMs, "arp-timeout-ms", 1000, "ARP wait timeout in milliseconds")
	cmd.Flags().IntVar(&flags.arpRetries, "arp-retries", 2, "ARP retries before replay")
	cmd.Flags().BoolVar(&flags.arpRequired, "arp-required", false, "Fail replay if ARP resolution fails")
	cmd.Flags().BoolVar(&flags.arpAutoRewrite, "arp-auto-rewrite", true, "Auto-fill rewrite MACs from ARP (if unset)")
	cmd.Flags().IntVar(&flags.arpRefreshMs, "arp-refresh-ms", 0, "Refresh ARP during replay to detect MAC drift (raw mode)")
	cmd.Flags().BoolVar(&flags.arpDriftFail, "arp-drift-fail", false, "Fail replay if ARP MAC changes during replay")
	cmd.Flags().IntVar(&flags.intervalMs, "interval-ms", 5, "Fixed interval between packets (ms) when not using --realtime")
	cmd.Flags().BoolVar(&flags.realtime, "realtime", false, "Replay using PCAP timestamps when available")
	cmd.Flags().BoolVar(&flags.includeResponse, "include-responses", false, "Include response packets (default: requests only)")
	cmd.Flags().IntVar(&flags.limit, "limit", 0, "Optional max number of packets to replay")
	cmd.Flags().StringVar(&flags.iface, "iface", "", "Network interface for raw/tcpreplay modes")
	cmd.Flags().StringVar(&flags.tcpreplayPath, "tcpreplay", "", "Optional path to tcpreplay binary")
	cmd.Flags().StringVar(&flags.tcprewritePath, "tcprewrite", "", "Optional path to tcprewrite binary")
	cmd.Flags().StringArrayVar(&flags.tcpreplayArgs, "tcpreplay-arg", nil, "Pass-through arg to tcpreplay (repeatable)")
	cmd.Flags().StringArrayVar(&flags.tcprewriteArgs, "tcprewrite-arg", nil, "Pass-through arg to tcprewrite (repeatable)")
	cmd.Flags().BoolVar(&flags.report, "report", true, "Print a replay summary report")
	cmd.Flags().BoolVar(&flags.preflightOnly, "preflight-only", false, "Run replay preflight checks and exit")

	return cmd
}

func printPcapPresets() {
	fmt.Fprintln(os.Stdout, "Available presets:")
	for _, group := range pcappkg.ReplayPresetGroups() {
		fmt.Fprintf(os.Stdout, "  %s\n", group)
	}
	for _, preset := range pcappkg.ReplayPresetNames() {
		fmt.Fprintf(os.Stdout, "  %s\n", preset)
	}
}

func runPcapReplay(flags *pcapReplayFlags) error {
	return app.RunPCAPReplay(app.PCAPReplayOptions{
		Input:           flags.input,
		Preset:          flags.preset,
		PresetDir:       flags.presetDir,
		PresetAll:       flags.presetAll,
		Mode:            flags.mode,
		ServerIP:        flags.serverIP,
		ServerPort:      flags.serverPort,
		UDPPort:         flags.udpPort,
		ClientIP:        flags.clientIP,
		RewriteSrcIP:    flags.rewriteSrcIP,
		RewriteDstIP:    flags.rewriteDstIP,
		RewriteSrcPort:  flags.rewriteSrcPort,
		RewriteDstPort:  flags.rewriteDstPort,
		RewriteSrcMAC:   flags.rewriteSrcMAC,
		RewriteDstMAC:   flags.rewriteDstMAC,
		RewriteOnlyENIP: flags.rewriteOnlyENIP,
		ARPTarget:       flags.arpTarget,
		ARPTimeoutMs:    flags.arpTimeoutMs,
		ARPRetries:      flags.arpRetries,
		ARPRequired:     flags.arpRequired,
		ARPAutoRewrite:  flags.arpAutoRewrite,
		ARPRefreshMs:    flags.arpRefreshMs,
		ARPDriftFail:    flags.arpDriftFail,
		IntervalMs:      flags.intervalMs,
		Realtime:        flags.realtime,
		IncludeResponse: flags.includeResponse,
		Limit:           flags.limit,
		Iface:           flags.iface,
		TcpreplayPath:   flags.tcpreplayPath,
		TcprewritePath:  flags.tcprewritePath,
		TcpreplayArgs:   flags.tcpreplayArgs,
		TcprewriteArgs:  flags.tcprewriteArgs,
		Report:          flags.report,
		PreflightOnly:   flags.preflightOnly,
	})
}
