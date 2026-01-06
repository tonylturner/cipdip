package app

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
	pcappkg "github.com/tturner/cipdip/internal/pcap"
)

type PCAPReplayOptions struct {
	Input           string
	Preset          string
	PresetDir       string
	PresetAll       bool
	Mode            string
	ServerIP        string
	ServerPort      int
	UDPPort         int
	ClientIP        string
	RewriteSrcIP    string
	RewriteDstIP    string
	RewriteSrcPort  int
	RewriteDstPort  int
	RewriteSrcMAC   string
	RewriteDstMAC   string
	RewriteOnlyENIP bool
	ARPTarget       string
	ARPTimeoutMs    int
	ARPRetries      int
	ARPRequired     bool
	ARPAutoRewrite  bool
	ARPRefreshMs    int
	ARPDriftFail    bool
	IntervalMs      int
	Realtime        bool
	IncludeResponse bool
	Limit           int
	Iface           string
	TcpreplayPath   string
	TcprewritePath  string
	TcpreplayArgs   []string
	TcprewriteArgs  []string
	Report          bool
	PreflightOnly   bool
}

func RunPCAPReplay(opts PCAPReplayOptions) error {
	if opts.Preset != "" {
		files, err := pcappkg.ResolveReplayPreset(opts.Preset, opts.PresetDir, opts.PresetAll)
		if err != nil {
			return err
		}
		for _, file := range files {
			copyOpts := opts
			copyOpts.Input = file
			if err := runReplayForFile(&copyOpts); err != nil {
				return err
			}
		}
		return nil
	}
	return runReplayForFile(&opts)
}

func runReplayForFile(opts *PCAPReplayOptions) error {
	if err := warnIfMissingHandshake(opts); err != nil {
		return err
	}
	if opts.PreflightOnly {
		return runPcapPreflight(opts)
	}
	switch strings.ToLower(opts.Mode) {
	case "app":
		return runAppReplay(opts)
	case "raw":
		return runRawReplay(opts)
	case "tcpreplay":
		return runTcpreplay(opts)
	default:
		return fmt.Errorf("unknown replay mode '%s'; use app, raw, or tcpreplay", opts.Mode)
	}
}

func runAppReplay(opts *PCAPReplayOptions) error {
	if opts.ServerIP == "" {
		return fmt.Errorf("server-ip is required for app replay")
	}

	packets, err := pcappkg.ExtractENIPFromPCAP(opts.Input)
	if err != nil {
		return err
	}

	var tcpConn net.Conn
	var udpConn *net.UDPConn

	dialer := &net.Dialer{}
	if opts.ClientIP != "" {
		localIP := net.ParseIP(opts.ClientIP)
		if localIP == nil {
			return fmt.Errorf("invalid client-ip: %s", opts.ClientIP)
		}
		dialer.LocalAddr = &net.TCPAddr{IP: localIP}
	}
	tcpConn, err = dialer.DialContext(context.Background(), "tcp", fmt.Sprintf("%s:%d", opts.ServerIP, opts.ServerPort))
	if err != nil {
		return fmt.Errorf("tcp connect: %w", err)
	}
	defer tcpConn.Close()

	if opts.ClientIP != "" {
		localIP := net.ParseIP(opts.ClientIP)
		if localIP == nil {
			return fmt.Errorf("invalid client-ip: %s", opts.ClientIP)
		}
		udpConn, err = net.DialUDP("udp", &net.UDPAddr{IP: localIP}, &net.UDPAddr{IP: net.ParseIP(opts.ServerIP), Port: opts.UDPPort})
	} else {
		udpConn, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(opts.ServerIP), Port: opts.UDPPort})
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
		if !opts.IncludeResponse && !pkt.IsRequest {
			skippedResponses++
			continue
		}
		if opts.Limit > 0 && sent >= opts.Limit {
			break
		}

		if opts.Realtime && !pkt.Timestamp.IsZero() {
			if !lastTs.IsZero() {
				sleep := pkt.Timestamp.Sub(lastTs)
				if sleep > 0 {
					time.Sleep(sleep)
				}
			}
			lastTs = pkt.Timestamp
		} else if opts.IntervalMs > 0 {
			time.Sleep(time.Duration(opts.IntervalMs) * time.Millisecond)
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
	if opts.Report {
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

func runRawReplay(opts *PCAPReplayOptions) error {
	if opts.Iface == "" {
		return fmt.Errorf("iface is required for raw replay")
	}

	if err := primeARP(opts); err != nil {
		return err
	}

	rewriteState, err := buildReplayRewriteState(opts)
	if err != nil {
		return err
	}
	arpCancel, arpErr := startARPMonitor(opts, rewriteState)
	if arpCancel != nil {
		defer arpCancel()
	}

	handle, err := pcap.OpenLive(opts.Iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open live interface: %w", err)
	}
	defer handle.Close()

	source, err := pcap.OpenOffline(opts.Input)
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
		if opts.Limit > 0 && sent >= opts.Limit {
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
		if opts.Realtime && packet.Metadata() != nil {
			ts := packet.Metadata().Timestamp
			if !lastTs.IsZero() {
				sleep := ts.Sub(lastTs)
				if sleep > 0 {
					time.Sleep(sleep)
				}
			}
			lastTs = ts
		} else if opts.IntervalMs > 0 {
			time.Sleep(time.Duration(opts.IntervalMs) * time.Millisecond)
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
			if pcappkg.ShouldRewrite(packet, opts.RewriteOnlyENIP) {
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

	fmt.Fprintf(os.Stdout, "Replayed %d packet(s) via raw mode on %s\n", sent, opts.Iface)
	if opts.Report {
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

func hasRewriteFlags(opts *PCAPReplayOptions) bool {
	return opts.RewriteSrcIP != "" || opts.RewriteDstIP != "" || opts.RewriteSrcPort > 0 || opts.RewriteDstPort > 0 || opts.RewriteSrcMAC != "" || opts.RewriteDstMAC != ""
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

func primeARP(opts *PCAPReplayOptions) error {
	if opts.ARPTarget == "" && opts.RewriteDstIP != "" {
		opts.ARPTarget = opts.RewriteDstIP
	}
	if opts.ARPTarget == "" {
		return nil
	}
	if opts.Iface == "" {
		return fmt.Errorf("arp-target requires --iface for raw/tcpreplay")
	}
	targetIP, err := resolveTargetIP(opts.ARPTarget)
	if err != nil {
		return err
	}

	iface, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return fmt.Errorf("lookup interface: %w", err)
	}
	if len(iface.HardwareAddr) == 0 {
		return fmt.Errorf("interface %s has no MAC address", opts.Iface)
	}

	srcIP, err := firstIPv4Addr(iface)
	if err != nil {
		return err
	}
	if !ipInInterfaceSubnet(iface, targetIP) && opts.ARPTarget == opts.RewriteDstIP {
		fmt.Fprintf(os.Stdout, "Warning: arp-target %s is not in the local subnet; use a gateway IP or set --rewrite-dst-mac\n", opts.ARPTarget)
	}

	var resolved net.HardwareAddr
	for i := 0; i < maxInt(1, opts.ARPRetries); i++ {
		resolved, err = resolveARP(opts.Iface, srcIP, targetIP, opts.ARPTimeoutMs)
		if err == nil && len(resolved) > 0 {
			break
		}
	}

	if len(resolved) == 0 {
		if opts.ARPRequired {
			return fmt.Errorf("ARP resolution failed for %s", opts.ARPTarget)
		}
		fmt.Fprintf(os.Stdout, "Warning: ARP resolution failed for %s; continuing replay\n", opts.ARPTarget)
		return nil
	}

	if opts.ARPAutoRewrite {
		if opts.RewriteDstMAC == "" {
			opts.RewriteDstMAC = resolved.String()
		}
		if opts.RewriteSrcMAC == "" {
			opts.RewriteSrcMAC = iface.HardwareAddr.String()
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

func buildReplayRewriteState(opts *PCAPReplayOptions) (*replayRewriteState, error) {
	if !hasRewriteFlags(opts) && !opts.ARPAutoRewrite {
		return nil, nil
	}
	srcIP := net.ParseIP(opts.RewriteSrcIP)
	dstIP := net.ParseIP(opts.RewriteDstIP)
	srcMAC, err := pcappkg.ParseMAC(opts.RewriteSrcMAC)
	if err != nil {
		return nil, err
	}
	dstMAC, err := pcappkg.ParseMAC(opts.RewriteDstMAC)
	if err != nil {
		return nil, err
	}

	return &replayRewriteState{
		srcIP:    srcIP,
		dstIP:    dstIP,
		srcPort:  opts.RewriteSrcPort,
		dstPort:  opts.RewriteDstPort,
		onlyENIP: opts.RewriteOnlyENIP,
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
	return pcappkg.RewritePacket(packet, pcappkg.RewriteOptions{
		SrcIP:              state.srcIP,
		DstIP:              state.dstIP,
		SrcPort:            state.srcPort,
		DstPort:            state.dstPort,
		SrcMAC:             srcMAC,
		DstMAC:             dstMAC,
		RecomputeChecksums: state.opts.ComputeChecksums,
	})
}

func startARPMonitor(opts *PCAPReplayOptions, rewriteState *replayRewriteState) (func(), chan error) {
	if opts.ARPTarget == "" || opts.ARPRefreshMs <= 0 {
		return nil, nil
	}
	if opts.Iface == "" {
		return nil, nil
	}
	targetIP, err := resolveTargetIP(opts.ARPTarget)
	if err != nil {
		return nil, nil
	}
	iface, err := net.InterfaceByName(opts.Iface)
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
		ticker := time.NewTicker(time.Duration(opts.ARPRefreshMs) * time.Millisecond)
		defer ticker.Stop()
		var lastMAC net.HardwareAddr
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				resolved, err := resolveARP(opts.Iface, srcIP, targetIP, opts.ARPTimeoutMs)
				if err != nil || len(resolved) == 0 {
					continue
				}
				if len(lastMAC) == 0 {
					lastMAC = resolved
					if opts.ARPAutoRewrite {
						rewriteState.UpdateDstMAC(resolved)
					}
					continue
				}
				if !bytes.Equal(lastMAC, resolved) {
					fmt.Fprintf(os.Stdout, "Warning: ARP MAC changed for %s (%s -> %s)\n", opts.ARPTarget, lastMAC, resolved)
					lastMAC = resolved
					if opts.ARPAutoRewrite {
						rewriteState.UpdateDstMAC(resolved)
					}
					if opts.ARPDriftFail {
						errCh <- fmt.Errorf("ARP MAC drift detected for %s", opts.ARPTarget)
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

func ResolveExternalPath(explicit, envKey, name string) (string, error) {
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
