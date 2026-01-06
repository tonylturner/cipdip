package app

import (
	"fmt"
	"strings"

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
