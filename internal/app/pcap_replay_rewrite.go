package app

import (
	"net"
	"sync"

	"github.com/google/gopacket"
	pcappkg "github.com/tonylturner/cipdip/internal/pcap"
)

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

func hasRewriteFlags(opts *PCAPReplayOptions) bool {
	return opts.RewriteSrcIP != "" || opts.RewriteDstIP != "" || opts.RewriteSrcPort > 0 || opts.RewriteDstPort > 0 || opts.RewriteSrcMAC != "" || opts.RewriteDstMAC != ""
}
