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
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/cipclient"
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
	intervalMs      int
	realtime        bool
	includeResponse bool
	limit           int
	iface           string
	tcpreplayPath   string
	tcprewritePath  string
	tcpreplayArgs   []string
	tcprewriteArgs  []string
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
	cmd.Flags().IntVar(&flags.intervalMs, "interval-ms", 5, "Fixed interval between packets (ms) when not using --realtime")
	cmd.Flags().BoolVar(&flags.realtime, "realtime", false, "Replay using PCAP timestamps when available")
	cmd.Flags().BoolVar(&flags.includeResponse, "include-responses", false, "Include response packets (default: requests only)")
	cmd.Flags().IntVar(&flags.limit, "limit", 0, "Optional max number of packets to replay")
	cmd.Flags().StringVar(&flags.iface, "iface", "", "Network interface for raw/tcpreplay modes")
	cmd.Flags().StringVar(&flags.tcpreplayPath, "tcpreplay", "", "Optional path to tcpreplay binary")
	cmd.Flags().StringVar(&flags.tcprewritePath, "tcprewrite", "", "Optional path to tcprewrite binary")
	cmd.Flags().StringArrayVar(&flags.tcpreplayArgs, "tcpreplay-arg", nil, "Pass-through arg to tcpreplay (repeatable)")
	cmd.Flags().StringArrayVar(&flags.tcprewriteArgs, "tcprewrite-arg", nil, "Pass-through arg to tcprewrite (repeatable)")

	return cmd
}

func runPcapReplay(flags *pcapReplayFlags) error {
	if flags.preset != "" {
		files, err := resolvePresetFiles(flags)
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

	packets, err := cipclient.ExtractENIPFromPCAP(flags.input)
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
	for _, pkt := range packets {
		if !flags.includeResponse && !pkt.IsRequest {
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

		switch transport {
		case "udp":
			if _, err := udpConn.Write(pkt.FullPacket); err != nil {
				return fmt.Errorf("udp write: %w", err)
			}
		default:
			if _, err := tcpConn.Write(pkt.FullPacket); err != nil {
				return fmt.Errorf("tcp write: %w", err)
			}
		}
		sent++
	}

	fmt.Fprintf(os.Stdout, "Replayed %d packet(s) via app mode\n", sent)
	return nil
}

func runRawReplay(flags *pcapReplayFlags) error {
	if flags.iface == "" {
		return fmt.Errorf("iface is required for raw replay")
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
	for packet := range packetSource.Packets() {
		if flags.limit > 0 && sent >= flags.limit {
			break
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
		if err := handle.WritePacketData(packet.Data()); err != nil {
			return fmt.Errorf("write packet: %w", err)
		}
		sent++
	}

	fmt.Fprintf(os.Stdout, "Replayed %d packet(s) via raw mode on %s\n", sent, flags.iface)
	return nil
}

func runTcpreplay(flags *pcapReplayFlags) error {
	if flags.iface == "" {
		return fmt.Errorf("iface is required for tcpreplay mode")
	}
	tcpreplayPath, err := resolveExternalPath(flags.tcpreplayPath, "TCPREPLAY", "tcpreplay")
	if err != nil {
		return err
	}

	pcapPath := flags.input
	if len(flags.tcprewriteArgs) > 0 {
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
		args = append(args, flags.tcprewriteArgs...)
		if err := runExternal(tcprewritePath, args); err != nil {
			return err
		}
		pcapPath = tmp.Name()
	}

	args := []string{"-i", flags.iface}
	args = append(args, flags.tcpreplayArgs...)
	args = append(args, pcapPath)
	return runExternal(tcpreplayPath, args)
}

var pcapPresets = map[string][]string{
	"cl5000eip:firmware-change":                   {"CL5000EIP-Firmware-Change.pcap"},
	"cl5000eip:firmware-change-failure":           {"CL5000EIP-Firmware-Change-Failure.pcap"},
	"cl5000eip:software-download":                 {"CL5000EIP-Software-Download.pcap"},
	"cl5000eip:software-download-failure":         {"CL5000EIP-Software-Download-Failure.pcap"},
	"cl5000eip:software-upload":                   {"CL5000EIP-Software-Upload.pcap"},
	"cl5000eip:software-upload-failure":           {"CL5000EIP-Software-Upload-Failure.pcap"},
	"cl5000eip:reboot-or-restart":                 {"CL5000EIP-Reboot-or-Restart.pcap"},
	"cl5000eip:change-date-attempt":               {"CL5000EIP-Change-Date-Attempt.pcap"},
	"cl5000eip:change-time-attempt":               {"CL5000EIP-Change-Time-Attempt.pcap"},
	"cl5000eip:change-port-configuration-attempt": {"CL5000EIP-Change-Port-Configuration-Attempt.pcap"},
	"cl5000eip:control-protocol-change-attempt":   {"CL5000EIP-Control-Protocol-Change-Attempt.pcap"},
	"cl5000eip:ip-address-change-attempt":         {"CL5000EIP-IP-Address-Change-Attempt.pcap"},
	"cl5000eip:lock-plc-attempt":                  {"CL5000EIP-Lock-PLC-Attempt.pcap"},
	"cl5000eip:unlock-plc-attempt":                {"CL5000EIP-Unlock-PLC-Attempt.pcap"},
	"cl5000eip:remote-mode-change-attempt":        {"CL5000EIP-Remote-Mode-Change-Attempt.pcap"},
	"cl5000eip:view-device-status":                {"CL5000EIP-View-Device-Status.pcap"},
}

func printPcapPresets() {
	fmt.Fprintln(os.Stdout, "Available presets:")
	fmt.Fprintln(os.Stdout, "  cl5000eip")
	for preset := range pcapPresets {
		fmt.Fprintf(os.Stdout, "  %s\n", preset)
	}
}

func resolvePresetFiles(flags *pcapReplayFlags) ([]string, error) {
	preset := strings.ToLower(strings.TrimSpace(flags.preset))
	if preset == "" {
		return nil, fmt.Errorf("preset is empty")
	}

	files, err := collectPcapFiles(flags.presetDir)
	if err != nil {
		return nil, err
	}

	if preset == "cl5000eip" || preset == "cl5000eip:all" {
		matches := filterPresetMatches(files, []string{"CL5000EIP-"}, true)
		if len(matches) == 0 {
			return nil, fmt.Errorf("no CL5000EIP pcaps found under %s", flags.presetDir)
		}
		return matches, nil
	}

	patterns, ok := pcapPresets[preset]
	if !ok {
		return nil, fmt.Errorf("unknown preset '%s'; use --list-presets", preset)
	}

	matches := filterPresetMatches(files, patterns, flags.presetAll)
	if len(matches) == 0 {
		return nil, fmt.Errorf("preset '%s' not found under %s", preset, flags.presetDir)
	}
	return matches, nil
}

func filterPresetMatches(files []string, patterns []string, allowMultiple bool) []string {
	matches := make([]string, 0, len(patterns))
	for _, file := range files {
		base := filepath.Base(file)
		for _, pattern := range patterns {
			if strings.HasPrefix(pattern, "CL5000EIP-") && strings.HasPrefix(base, pattern) {
				matches = append(matches, file)
				break
			}
			if strings.EqualFold(base, pattern) {
				matches = append(matches, file)
				break
			}
		}
		if len(matches) > 0 && !allowMultiple {
			return matches[:1]
		}
	}
	return matches
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
