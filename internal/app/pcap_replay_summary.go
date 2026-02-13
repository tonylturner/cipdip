package app

import (
	"fmt"
	"os"

	pcappkg "github.com/tonylturner/cipdip/internal/pcap"
)

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
