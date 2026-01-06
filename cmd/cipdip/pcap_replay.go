package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
	pcappkg "github.com/tturner/cipdip/internal/pcap"
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

func runPcapReplay(flags *pcapReplayFlags) error {
	if flags.preset != "" {
		files, err := pcappkg.ResolveReplayPreset(flags.preset, flags.presetDir, flags.presetAll)
		if err != nil {
			return err
		}
		for _, file := range files {
			copyFlags := *flags
			copyFlags.input = file
			if err := runReplayForFile(&copyFlags); err != nil {
				return err
			}
		}
		return nil
	}
	return runReplayForFile(flags)
}

func runReplayForFile(flags *pcapReplayFlags) error {
	if err := warnIfMissingHandshake(flags); err != nil {
		return err
	}
	if flags.preflightOnly {
		return runPcapPreflight(flags)
	}
	switch strings.ToLower(flags.mode) {
	case "app":
		return runAppReplay(flags)
	case "raw":
		return runRawReplay(flags)
	case "tcpreplay":
		return runTcpreplay(flags)
	default:
		return fmt.Errorf("unknown replay mode '%s'; use app, raw, or tcpreplay", flags.mode)
	}
}

func runAppReplay(flags *pcapReplayFlags) error {
	if flags.serverIP == "" {
		return fmt.Errorf("server-ip is required for app replay")
	}

	packets, err := pcappkg.ExtractENIPFromPCAP(flags.input)
	if err != nil {
		return err
	}

	var tcpConn net.Conn
	var udpConn *net.UDPConn

	dialer := &net.Dialer{}
	if flags.clientIP != "" {
		localIP := net.ParseIP(flags.clientIP)
		if localIP == nil {
			return fmt.Errorf("invalid client-ip: %s", flags.clientIP)
		}
		dialer.LocalAddr = &net.TCPAddr{IP: localIP}
	}
	tcpConn, err = dialer.DialContext(context.Background(), "tcp", fmt.Sprintf("%s:%d", flags.serverIP, flags.serverPort))
	if err != nil {
		return fmt.Errorf("tcp connect: %w", err)
	}
	defer tcpConn.Close()

	if flags.clientIP != "" {
		localIP := net.ParseIP(flags.clientIP)
		if localIP == nil {
			return fmt.Errorf("invalid client-ip: %s", flags.clientIP)
		}
		udpConn, err = net.DialUDP("udp", &net.UDPAddr{IP: localIP}, &net.UDPAddr{IP: net.ParseIP(flags.serverIP), Port: flags.udpPort})
	} else {
		udpConn, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(flags.serverIP), Port: flags.udpPort})
	}
	if err != nil {
		return fmt.Errorf("udp connect: %w", err)
	}
	defer udpConn.Close()

	var lastTs time.Time
	sent := 0
	skippedResponses := 0
	udpSent := 0
	tcpSent := 0
	requests := 0
	responses := 0
	for _, pkt := range packets {
		if !flags.includeResponse && !pkt.IsRequest {
			skippedResponses++
			continue
		}
		if flags.limit > 0 && sent >= flags.limit {
			break
		}

		if flags.realtime && !pkt.Timestamp.IsZero() {
			if !lastTs.IsZero() {
				sleep := pkt.Timestamp.Sub(lastTs)
				if sleep > 0 {
					time.Sleep(sleep)
				}
			}
			lastTs = pkt.Timestamp
		} else if flags.intervalMs > 0 {
			time.Sleep(time.Duration(flags.intervalMs) * time.Millisecond)
		}

		transport := strings.ToLower(pkt.Transport)
		if transport == "" {
			if pkt.DstPort == 2222 {
				transport = "udp"
			} else {
				transport = "tcp"
			}
		}
		if pkt.IsRequest {
			requests++
		} else {
			responses++
		}

		switch transport {
		case "udp":
			if _, err := udpConn.Write(pkt.FullPacket); err != nil {
				return fmt.Errorf("udp write: %w", err)
			}
			udpSent++
		default:
			if _, err := tcpConn.Write(pkt.FullPacket); err != nil {
				return fmt.Errorf("tcp write: %w", err)
			}
			tcpSent++
		}
		sent++
	}

	fmt.Fprintf(os.Stdout, "Replayed %d packet(s) via app mode\n", sent)
	if flags.report {
		missing := 0
		if requests > responses {
			missing = requests - responses
		}
		printReplaySummary("app", &replaySummary{
			mode:            "app",
			total:           len(packets),
			enip:            len(packets),
			requests:        requests,
			responses:       responses,
			missingResponse: missing,
			sent:            sent,
			tcpSent:         tcpSent,
			udpSent:         udpSent,
			skippedResponse: skippedResponses,
		})
	}
	return nil
}

func runRawReplay(flags *pcapReplayFlags) error {
	if flags.iface == "" {
		return fmt.Errorf("iface is required for raw replay")
	}

	if err := primeARP(flags); err != nil {
		return err
	}

	rewriteState, err := buildReplayRewriteState(flags)
	if err != nil {
		return err
	}
	arpCancel, arpErr := startARPMonitor(flags, rewriteState)
	if arpCancel != nil {
		defer arpCancel()
	}

	handle, err := pcap.OpenLive(flags.iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open live interface: %w", err)
	}
	defer handle.Close()

	source, err := pcap.OpenOffline(flags.input)
	if err != nil {
		return fmt.Errorf("open pcap: %w", err)
	}
	defer source.Close()

	packetSource := gopacket.NewPacketSource(source, source.LinkType())

	var lastTs time.Time
	sent := 0
	total := 0
	enip := 0
	enipTCP := 0
	enipUDP := 0
	rewritten := 0
	rewriteCandidates := 0
	rewriteSkipped := 0
	rewriteErrors := 0
	for packet := range packetSource.Packets() {
		total++
		if flags.limit > 0 && sent >= flags.limit {
			break
		}
		if arpErr != nil {
			select {
			case err := <-arpErr:
				if err != nil {
					return err
				}
			default:
			}
		}
		if flags.realtime && packet.Metadata() != nil {
			ts := packet.Metadata().Timestamp
			if !lastTs.IsZero() {
				sleep := ts.Sub(lastTs)
				if sleep > 0 {
					time.Sleep(sleep)
				}
			}
			lastTs = ts
		} else if flags.intervalMs > 0 {
			time.Sleep(time.Duration(flags.intervalMs) * time.Millisecond)
		}

		if isENIPPacket(packet) {
			enip++
			if hasTCPPort(packet, 44818) {
				enipTCP++
			} else if hasUDPPort(packet, 2222) {
				enipUDP++
			}
		}

		data := packet.Data()
		if rewriteState != nil {
			if shouldRewrite(packet, flags.rewriteOnlyENIP) {
				rewriteCandidates++
				updated, err := rewriteState.Rewrite(packet)
				if err == nil {
					data = updated
					rewritten++
				} else {
					rewriteErrors++
				}
			} else {
				rewriteSkipped++
			}
		}

		if err := handle.WritePacketData(data); err != nil {
			return fmt.Errorf("write packet: %w", err)
		}
		sent++
	}

	fmt.Fprintf(os.Stdout, "Replayed %d packet(s) via raw mode on %s\n", sent, flags.iface)
	if flags.report {
		printReplaySummary("raw", &replaySummary{
			mode:              "raw",
			total:             total,
			sent:              sent,
			enip:              enip,
			enipTCP:           enipTCP,
			enipUDP:           enipUDP,
			rewriteCandidates: rewriteCandidates,
			rewriteSkipped:    rewriteSkipped,
			rewritten:         rewritten,
			rewriteErrors:     rewriteErrors,
		})
	}
	return nil
}

func runTcpreplay(flags *pcapReplayFlags) error {
	if flags.iface == "" {
		return fmt.Errorf("iface is required for tcpreplay mode")
	}

	if err := primeARP(flags); err != nil {
		return err
	}

	if flags.arpRefreshMs > 0 {
		fmt.Fprintln(os.Stdout, "Warning: arp-refresh-ms is not supported in tcpreplay mode; ignoring.")
	}

	tcpreplayPath, err := resolveExternalPath(flags.tcpreplayPath, "TCPREPLAY", "tcpreplay")
	if err != nil {
		return err
	}

	pcapPath := flags.input
	if len(flags.tcprewriteArgs) > 0 || hasRewriteFlags(flags) {
		tcprewritePath, err := resolveExternalPath(flags.tcprewritePath, "TCPREWRITE", "tcprewrite")
		if err != nil {
			return err
		}
		tmp, err := os.CreateTemp("", "cipdip_tcprewrite_*.pcap")
		if err != nil {
			return fmt.Errorf("create temp pcap: %w", err)
		}
		tmp.Close()
		defer os.Remove(tmp.Name())

		args := []string{"-i", flags.input, "-o", tmp.Name()}
		args = append(args, buildTcprewriteArgs(flags)...)
		args = append(args, flags.tcprewriteArgs...)
		if err := runExternal(tcprewritePath, args); err != nil {
			return err
		}
		pcapPath = tmp.Name()
	}

	args := []string{"-i", flags.iface}
	args = append(args, flags.tcpreplayArgs...)
	args = append(args, pcapPath)
	if flags.report {
		if summary, err := pcappkg.SummarizePcapForReplay(flags.input); err == nil {
			printReplaySummary("tcpreplay", replaySummaryFromPCAP(summary))
		}
	}
	return runExternal(tcpreplayPath, args)
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

func hasRewriteFlags(flags *pcapReplayFlags) bool {
	return flags.rewriteSrcIP != "" || flags.rewriteDstIP != "" || flags.rewriteSrcPort > 0 || flags.rewriteDstPort > 0 || flags.rewriteSrcMAC != "" || flags.rewriteDstMAC != ""
}

func buildTcprewriteArgs(flags *pcapReplayFlags) []string {
	args := make([]string, 0, 4)
	if flags.rewriteSrcIP != "" {
		args = append(args, fmt.Sprintf("--srcipmap=0.0.0.0/0:%s", flags.rewriteSrcIP))
	}
	if flags.rewriteDstIP != "" {
		args = append(args, fmt.Sprintf("--dstipmap=0.0.0.0/0:%s", flags.rewriteDstIP))
	}
	if flags.rewriteSrcPort > 0 {
		args = append(args, fmt.Sprintf("--portmap=0:%d", flags.rewriteSrcPort))
	}
	if flags.rewriteDstPort > 0 {
		args = append(args, fmt.Sprintf("--portmap=0:%d", flags.rewriteDstPort))
	}
	return args
}

func warnIfMissingHandshake(flags *pcapReplayFlags) error {
	mode := strings.ToLower(flags.mode)
	if mode == "app" {
		return nil
	}
	ok, err := pcappkg.HasTCPHandshake(flags.input)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(os.Stdout, "Warning: PCAP does not include a full TCP handshake for 44818; stateful firewalls may drop replay.")
	}
	ok, _, err = pcappkg.HasPerFlowTCPHandshake(flags.input)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(os.Stdout, "Warning: PCAP missing per-flow SYN/SYN-ACK/ACK for 44818; stateful firewalls may drop replay.")
	}
	return nil
}

func primeARP(flags *pcapReplayFlags) error {
	if flags.arpTarget == "" && flags.rewriteDstIP != "" {
		flags.arpTarget = flags.rewriteDstIP
	}
	if flags.arpTarget == "" {
		return nil
	}
	if flags.iface == "" {
		return fmt.Errorf("arp-target requires --iface for raw/tcpreplay")
	}
	targetIP, err := resolveTargetIP(flags.arpTarget)
	if err != nil {
		return err
	}

	iface, err := net.InterfaceByName(flags.iface)
	if err != nil {
		return fmt.Errorf("lookup interface: %w", err)
	}
	if len(iface.HardwareAddr) == 0 {
		return fmt.Errorf("interface %s has no MAC address", flags.iface)
	}

	srcIP, err := firstIPv4Addr(iface)
	if err != nil {
		return err
	}
	if !ipInInterfaceSubnet(iface, targetIP) && flags.arpTarget == flags.rewriteDstIP {
		fmt.Fprintf(os.Stdout, "Warning: arp-target %s is not in the local subnet; use a gateway IP or set --rewrite-dst-mac\n", flags.arpTarget)
	}

	var resolved net.HardwareAddr
	for i := 0; i < maxInt(1, flags.arpRetries); i++ {
		resolved, err = resolveARP(flags.iface, srcIP, targetIP, flags.arpTimeoutMs)
		if err == nil && len(resolved) > 0 {
			break
		}
	}

	if len(resolved) == 0 {
		if flags.arpRequired {
			return fmt.Errorf("ARP resolution failed for %s", flags.arpTarget)
		}
		fmt.Fprintf(os.Stdout, "Warning: ARP resolution failed for %s; continuing replay\n", flags.arpTarget)
		return nil
	}

	if flags.arpAutoRewrite {
		if flags.rewriteDstMAC == "" {
			flags.rewriteDstMAC = resolved.String()
		}
		if flags.rewriteSrcMAC == "" {
			flags.rewriteSrcMAC = iface.HardwareAddr.String()
		}
	}

	return nil
}

func resolveARP(ifaceName string, srcIP, targetIP net.IP, timeoutMs int) (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("lookup interface: %w", err)
	}
	handle, err := pcap.OpenLive(ifaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open interface for arp: %w", err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, fmt.Errorf("set arp filter: %w", err)
	}

	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(targetIP.To4()),
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buffer, opts, eth, arp); err != nil {
		return nil, fmt.Errorf("serialize arp: %w", err)
	}
	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		return nil, fmt.Errorf("send arp: %w", err)
	}

	timeout := time.After(time.Duration(maxInt(1, timeoutMs)) * time.Millisecond)
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case pkt := <-source.Packets():
			if pkt == nil {
				continue
			}
			if layer := pkt.Layer(layers.LayerTypeARP); layer != nil {
				reply := layer.(*layers.ARP)
				if reply.Operation != layers.ARPReply {
					continue
				}
				if !net.IP(reply.SourceProtAddress).Equal(targetIP.To4()) {
					continue
				}
				return net.HardwareAddr(reply.SourceHwAddress), nil
			}
		case <-timeout:
			return nil, nil
		}
	}
}

func firstIPv4Addr(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("get interface addresses: %w", err)
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				return ip4, nil
			}
		}
	}
	return nil, fmt.Errorf("no IPv4 address on interface %s", iface.Name)
}

func resolveTargetIP(target string) (net.IP, error) {
	if target == "" {
		return nil, fmt.Errorf("empty arp-target")
	}
	if ip := net.ParseIP(target); ip != nil {
		return ip, nil
	}
	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, fmt.Errorf("resolve arp-target: %w", err)
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address found for arp-target: %s", target)
}

func ipInInterfaceSubnet(iface *net.Interface, targetIP net.IP) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				return ipNet.Contains(targetIP)
			}
		}
	}
	return false
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

type replayRewriteState struct {
	srcIP     net.IP
	dstIP     net.IP
	srcPort   int
	dstPort   int
	onlyENIP  bool
	opts      gopacket.SerializeOptions
	srcMAC    net.HardwareAddr
	dstMAC    net.HardwareAddr
	mu        *sync.RWMutex
	lastARPIP net.IP
}

func buildReplayRewriteState(flags *pcapReplayFlags) (*replayRewriteState, error) {
	if !hasRewriteFlags(flags) && !flags.arpAutoRewrite {
		return nil, nil
	}
	srcIP := net.ParseIP(flags.rewriteSrcIP)
	dstIP := net.ParseIP(flags.rewriteDstIP)
	srcMAC, err := parseMAC(flags.rewriteSrcMAC)
	if err != nil {
		return nil, err
	}
	dstMAC, err := parseMAC(flags.rewriteDstMAC)
	if err != nil {
		return nil, err
	}

	return &replayRewriteState{
		srcIP:    srcIP,
		dstIP:    dstIP,
		srcPort:  flags.rewriteSrcPort,
		dstPort:  flags.rewriteDstPort,
		onlyENIP: flags.rewriteOnlyENIP,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		srcMAC: srcMAC,
		dstMAC: dstMAC,
		mu:     &sync.RWMutex{},
	}, nil
}

func (state *replayRewriteState) UpdateDstMAC(mac net.HardwareAddr) {
	if state == nil || len(mac) == 0 {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	state.dstMAC = mac
}

func (state *replayRewriteState) Rewrite(packet gopacket.Packet) ([]byte, error) {
	if state == nil {
		return packet.Data(), nil
	}
	state.mu.RLock()
	srcMAC := state.srcMAC
	dstMAC := state.dstMAC
	state.mu.RUnlock()
	return rewritePacket(packet, state.srcIP, state.dstIP, srcMAC, dstMAC, state.srcPort, state.dstPort, state.opts, nil)
}

func startARPMonitor(flags *pcapReplayFlags, rewriteState *replayRewriteState) (func(), chan error) {
	if flags.arpTarget == "" || flags.arpRefreshMs <= 0 {
		return nil, nil
	}
	if flags.iface == "" {
		return nil, nil
	}
	targetIP, err := resolveTargetIP(flags.arpTarget)
	if err != nil {
		return nil, nil
	}
	iface, err := net.InterfaceByName(flags.iface)
	if err != nil {
		return nil, nil
	}
	srcIP, err := firstIPv4Addr(iface)
	if err != nil {
		return nil, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		ticker := time.NewTicker(time.Duration(flags.arpRefreshMs) * time.Millisecond)
		defer ticker.Stop()
		var lastMAC net.HardwareAddr
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				resolved, err := resolveARP(flags.iface, srcIP, targetIP, flags.arpTimeoutMs)
				if err != nil || len(resolved) == 0 {
					continue
				}
				if len(lastMAC) == 0 {
					lastMAC = resolved
					if flags.arpAutoRewrite {
						rewriteState.UpdateDstMAC(resolved)
					}
					continue
				}
				if !bytes.Equal(lastMAC, resolved) {
					fmt.Fprintf(os.Stdout, "Warning: ARP MAC changed for %s (%s -> %s)\n", flags.arpTarget, lastMAC, resolved)
					lastMAC = resolved
					if flags.arpAutoRewrite {
						rewriteState.UpdateDstMAC(resolved)
					}
					if flags.arpDriftFail {
						errCh <- fmt.Errorf("ARP MAC drift detected for %s", flags.arpTarget)
						cancel()
						return
					}
				}
			}
		}
	}()

	return cancel, errCh
}

type replaySummary struct {
	mode              string
	total             int
	enip              int
	enipTCP           int
	enipUDP           int
	requests          int
	responses         int
	missingResponse   int
	handshakeAny      bool
	handshakeFlows    bool
	flowsTotal        int
	flowsComplete     int
	sent              int
	tcpSent           int
	udpSent           int
	skippedResponse   int
	rewriteCandidates int
	rewriteSkipped    int
	rewritten         int
	rewriteErrors     int
}

func printReplaySummary(mode string, summary *replaySummary) {
	if summary == nil {
		return
	}
	fmt.Fprintf(os.Stdout, "Replay summary (%s): total=%d enip=%d enip_tcp=%d enip_udp=%d requests=%d responses=%d missing_responses=%d handshake_any=%t handshake_per_flow=%t flows=%d flows_complete=%d sent=%d tcp_sent=%d udp_sent=%d skipped_responses=%d rewrite_candidates=%d rewrite_skipped=%d rewritten=%d rewrite_errors=%d\n",
		mode, summary.total, summary.enip, summary.enipTCP, summary.enipUDP, summary.requests, summary.responses, summary.missingResponse, summary.handshakeAny, summary.handshakeFlows, summary.flowsTotal, summary.flowsComplete, summary.sent, summary.tcpSent, summary.udpSent, summary.skippedResponse, summary.rewriteCandidates, summary.rewriteSkipped, summary.rewritten, summary.rewriteErrors)
}

func runPcapPreflight(flags *pcapReplayFlags) error {
	mode := strings.ToLower(flags.mode)
	switch mode {
	case "app":
		if flags.serverIP == "" {
			return fmt.Errorf("server-ip is required for app replay preflight")
		}
	case "raw", "tcpreplay":
		if flags.iface == "" {
			return fmt.Errorf("iface is required for %s replay preflight", mode)
		}
	default:
		return fmt.Errorf("unknown replay mode '%s'; use app, raw, or tcpreplay", mode)
	}

	if flags.report {
		if summary, err := pcappkg.SummarizePcapForReplay(flags.input); err == nil {
			printReplaySummary("preflight", replaySummaryFromPCAP(summary))
		} else {
			return err
		}
	}

	if mode == "raw" || mode == "tcpreplay" {
		if flags.arpRefreshMs > 0 && mode == "tcpreplay" {
			fmt.Fprintln(os.Stdout, "Warning: arp-refresh-ms is not supported in tcpreplay mode; ignoring.")
		}
		if err := primeARP(flags); err != nil {
			return err
		}
	}

	return nil
}

func replaySummaryFromPCAP(summary *pcappkg.ReplaySummary) *replaySummary {
	if summary == nil {
		return nil
	}
	return &replaySummary{
		total:           summary.Total,
		enip:            summary.Enip,
		enipTCP:         summary.EnipTCP,
		enipUDP:         summary.EnipUDP,
		requests:        summary.Requests,
		responses:       summary.Responses,
		missingResponse: summary.MissingResponse,
		handshakeAny:    summary.HandshakeAny,
		handshakeFlows:  summary.HandshakeFlows,
		flowsTotal:      summary.FlowsTotal,
		flowsComplete:   summary.FlowsComplete,
	}
}

func isENIPPacket(packet gopacket.Packet) bool {
	if hasTCPPort(packet, 44818) || hasUDPPort(packet, 2222) {
		return true
	}
	return false
}

func hasTCPPort(packet gopacket.Packet, port uint16) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp != nil && (uint16(tcp.SrcPort) == port || uint16(tcp.DstPort) == port) {
			return true
		}
	}
	return false
}

func hasUDPPort(packet gopacket.Packet, port uint16) bool {
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if udp != nil && (uint16(udp.SrcPort) == port || uint16(udp.DstPort) == port) {
			return true
		}
	}
	return false
}

func rewritePCAPTemp(flags *pcapReplayFlags) (string, error) {
	tmp, err := os.CreateTemp("", "cipdip_rewrite_*.pcap")
	if err != nil {
		return "", fmt.Errorf("create temp pcap: %w", err)
	}
	tmp.Close()

	cmd := &pcapRewriteFlags{
		input:          flags.input,
		output:         tmp.Name(),
		srcIP:          flags.rewriteSrcIP,
		dstIP:          flags.rewriteDstIP,
		srcPort:        flags.rewriteSrcPort,
		dstPort:        flags.rewriteDstPort,
		srcMAC:         flags.rewriteSrcMAC,
		dstMAC:         flags.rewriteDstMAC,
		onlyENIP:       flags.rewriteOnlyENIP,
		recomputeCksum: true,
	}
	if err := runPcapRewrite(cmd); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

func resolveExternalPath(explicit, envKey, name string) (string, error) {
	if explicit == "" {
		explicit = os.Getenv(envKey)
	}
	if explicit != "" {
		if filepath.Base(explicit) == explicit {
			path, err := exec.LookPath(explicit)
			if err != nil {
				return "", fmt.Errorf("%s not found in PATH", name)
			}
			return path, nil
		}
		return explicit, nil
	}

	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not found in PATH; set %s or --%s", name, envKey, name)
	}
	return path, nil
}

func runExternal(path string, args []string) error {
	cmd := exec.Command(path, args...)
	var stderr bytes.Buffer
	cmd.Stdout = os.Stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %s", filepath.Base(path), strings.TrimSpace(stderr.String()))
	}
	return nil
}
