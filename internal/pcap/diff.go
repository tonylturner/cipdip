package pcap

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
)

// DiffResult contains the comparison results between two PCAPs.
type DiffResult struct {
	BaselinePath string
	ComparePath  string

	// Service code differences
	AddedServices   []ServiceInfo
	RemovedServices []ServiceInfo
	CommonServices  []ServiceInfo

	// All services in each PCAP (for summary)
	BaselineServices []ServiceInfo
	CompareServices  []ServiceInfo

	// Object class differences
	AddedClasses   []uint16
	RemovedClasses []uint16
	CommonClasses  []uint16

	// Timing analysis
	BaselineTiming *TimingStats
	CompareTiming  *TimingStats

	// I/O RPI analysis
	BaselineRPI *RPIStats
	CompareRPI  *RPIStats

	// Summary counts
	BaselinePacketCount int
	ComparePacketCount  int
	BaselineCIPCount    int
	CompareCIPCount     int
}

// ServiceInfo contains information about a CIP service.
type ServiceInfo struct {
	ServiceCode uint8
	ServiceName string
	Class       uint16
	Count       int
	IsResponse  bool
}

// TimingStats contains latency statistics.
type TimingStats struct {
	PacketCount     int
	MinLatencyMs    float64
	MaxLatencyMs    float64
	AvgLatencyMs    float64
	P50LatencyMs    float64
	P90LatencyMs    float64
	P95LatencyMs    float64
	P99LatencyMs    float64
	Latencies       []float64
	RequestResponse []RequestResponsePair
}

// RequestResponsePair pairs a request with its response for latency calculation.
type RequestResponsePair struct {
	RequestTime  time.Time
	ResponseTime time.Time
	Service      uint8
	Class        uint16
	LatencyMs    float64
}

// RPIStats contains RPI (Requested Packet Interval) jitter statistics.
type RPIStats struct {
	PacketCount     int
	Intervals       []float64
	MinIntervalMs   float64
	MaxIntervalMs   float64
	AvgIntervalMs   float64
	StdDevMs        float64
	JitterMs        float64
	P50IntervalMs   float64
	P90IntervalMs   float64
	P95IntervalMs   float64
	P99IntervalMs   float64
	ExpectedRPIMs   float64
	RPIViolations   int
	ViolationPct    float64
}

// DiffOptions configures the diff operation.
type DiffOptions struct {
	IncludeTiming    bool
	IncludeRPI       bool
	ExpectedRPIMs    float64
	RPITolerancePct  float64
	MaxLatencySamples int
}

// DefaultDiffOptions returns default diff options.
func DefaultDiffOptions() DiffOptions {
	return DiffOptions{
		IncludeTiming:    true,
		IncludeRPI:       true,
		ExpectedRPIMs:    20.0, // 20ms default RPI
		RPITolerancePct:  10.0, // 10% tolerance
		MaxLatencySamples: 10000,
	}
}

// DiffPCAPs compares two PCAP files and returns the differences.
func DiffPCAPs(baselinePath, comparePath string, opts DiffOptions) (*DiffResult, error) {
	baselineData, err := extractPCAPData(baselinePath, opts)
	if err != nil {
		return nil, fmt.Errorf("extract baseline: %w", err)
	}

	compareData, err := extractPCAPData(comparePath, opts)
	if err != nil {
		return nil, fmt.Errorf("extract compare: %w", err)
	}

	result := &DiffResult{
		BaselinePath:        baselinePath,
		ComparePath:         comparePath,
		BaselinePacketCount: baselineData.packetCount,
		ComparePacketCount:  compareData.packetCount,
		BaselineCIPCount:    baselineData.cipCount,
		CompareCIPCount:     compareData.cipCount,
	}

	// Compare services
	result.AddedServices, result.RemovedServices, result.CommonServices = diffServices(
		baselineData.services, compareData.services)

	// Collect all services for summary
	result.BaselineServices = serviceMapToSlice(baselineData.services)
	result.CompareServices = serviceMapToSlice(compareData.services)

	// Compare classes
	result.AddedClasses, result.RemovedClasses, result.CommonClasses = diffClasses(
		baselineData.classes, compareData.classes)

	// Timing analysis
	if opts.IncludeTiming {
		result.BaselineTiming = computeTimingStats(baselineData.requestResponsePairs)
		result.CompareTiming = computeTimingStats(compareData.requestResponsePairs)
	}

	// RPI analysis
	if opts.IncludeRPI {
		result.BaselineRPI = computeRPIStats(baselineData.ioTimestamps, opts.ExpectedRPIMs, opts.RPITolerancePct)
		result.CompareRPI = computeRPIStats(compareData.ioTimestamps, opts.ExpectedRPIMs, opts.RPITolerancePct)
	}

	return result, nil
}

// pcapData holds extracted data from a PCAP.
type pcapData struct {
	packetCount          int
	cipCount             int
	services             map[string]ServiceInfo
	classes              map[uint16]int
	requestResponsePairs []RequestResponsePair
	ioTimestamps         []time.Time
}

// extractPCAPData extracts relevant data from a PCAP file.
func extractPCAPData(pcapFile string, opts DiffOptions) (*pcapData, error) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	defer handle.Close()

	data := &pcapData{
		services:             make(map[string]ServiceInfo),
		classes:              make(map[uint16]int),
		requestResponsePairs: make([]RequestResponsePair, 0),
		ioTimestamps:         make([]time.Time, 0),
	}

	// Track pending requests for latency calculation
	pendingRequests := make(map[string]pendingRequest)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	streams := make(map[string][]byte)

	for packet := range packetSource.Packets() {
		data.packetCount++
		timestamp := packet.Metadata().Timestamp

		// Extract network layer for IP addresses
		netLayer := packet.NetworkLayer()
		var srcIP, dstIP string
		if netLayer != nil {
			src, dst := netLayer.NetworkFlow().Endpoints()
			srcIP = src.String()
			dstIP = dst.String()
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		udpLayer := packet.Layer(layers.LayerTypeUDP)

		if tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			if !isENIPPort(uint16(tcp.SrcPort), uint16(tcp.DstPort)) {
				continue
			}
			if len(tcp.Payload) == 0 {
				continue
			}
			key := streamKey(netLayer, tcp)
			streams[key] = append(streams[key], tcp.Payload...)
			isRequest := tcp.DstPort == 44818 || tcp.DstPort == 2222
			meta := &ENIPMetadata{
				Timestamp: timestamp,
				SrcIP:     srcIP,
				DstIP:     dstIP,
				SrcPort:   uint16(tcp.SrcPort),
				DstPort:   uint16(tcp.DstPort),
				Transport: "tcp",
			}
			parsed, remaining := extractENIPFrames(streams[key], isRequest, meta)
			streams[key] = remaining
			processENIPPackets(parsed, data, timestamp, pendingRequests, opts)
		} else if udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			if !isENIPPort(uint16(udp.SrcPort), uint16(udp.DstPort)) {
				continue
			}
			if len(udp.Payload) == 0 {
				continue
			}
			isRequest := udp.DstPort == 44818 || udp.DstPort == 2222
			meta := &ENIPMetadata{
				Timestamp: timestamp,
				SrcIP:     srcIP,
				DstIP:     dstIP,
				SrcPort:   uint16(udp.SrcPort),
				DstPort:   uint16(udp.DstPort),
				Transport: "udp",
			}
			parsed, _ := extractENIPFrames(udp.Payload, isRequest, meta)
			processENIPPackets(parsed, data, timestamp, pendingRequests, opts)
			// Track I/O timestamps for RPI analysis
			if opts.IncludeRPI && len(parsed) > 0 {
				data.ioTimestamps = append(data.ioTimestamps, timestamp)
			}
		}
	}

	return data, nil
}

// processENIPPackets processes extracted ENIP packets and updates stats.
func processENIPPackets(packets []ENIPPacket, data *pcapData, _ time.Time,
	pending map[string]pendingRequest, opts DiffOptions) {
	for _, pkt := range packets {
		// Only process SendRRData and SendUnitData
		if pkt.Command != 0x6F && pkt.Command != 0x70 {
			continue
		}

		cipData, _, dataType := extractCIPFromENIP(pkt)
		if len(cipData) == 0 {
			continue
		}

		// Skip connected I/O data for service analysis
		if dataType == "connected" {
			continue
		}

		data.cipCount++

		// Parse CIP message using the protocol package
		msgInfo, err := protocol.ParseCIPMessage(cipData)
		if err != nil {
			continue
		}

		// Record service
		serviceKey := fmt.Sprintf("%02X_%04X_%v", msgInfo.BaseService, msgInfo.PathInfo.Path.Class, msgInfo.IsResponse)
		if existing, ok := data.services[serviceKey]; ok {
			existing.Count++
			data.services[serviceKey] = existing
		} else {
			data.services[serviceKey] = ServiceInfo{
				ServiceCode: msgInfo.BaseService,
				ServiceName: spec.ServiceName(protocol.CIPServiceCode(msgInfo.BaseService)),
				Class:       msgInfo.PathInfo.Path.Class,
				Count:       1,
				IsResponse:  msgInfo.IsResponse,
			}
		}

		// Record class
		if msgInfo.PathInfo.Path.Class > 0 {
			data.classes[msgInfo.PathInfo.Path.Class]++
		}

		// Track request/response pairs for latency using packet's own timestamp
		// Include stream info (src/dst IP) to match requests with responses properly
		// Note: CIP responses typically don't include path, so we match on service code only
		if opts.IncludeTiming && len(data.requestResponsePairs) < opts.MaxLatencySamples {
			// Use stream (IPs) + service as key - responses don't repeat the class
			if !msgInfo.IsResponse {
				reqKey := fmt.Sprintf("%s_%s_%02X", pkt.SrcIP, pkt.DstIP, msgInfo.BaseService)
				pending[reqKey] = pendingRequest{
					timestamp: pkt.Timestamp,
					service:   msgInfo.BaseService,
					class:     msgInfo.PathInfo.Path.Class,
				}
			} else {
				// Response comes from server→client, so swap IPs to get client→server key
				reqKey := fmt.Sprintf("%s_%s_%02X", pkt.DstIP, pkt.SrcIP, msgInfo.BaseService)
				if req, ok := pending[reqKey]; ok {
					latency := pkt.Timestamp.Sub(req.timestamp).Seconds() * 1000
					if latency > 0 && latency < 10000 { // Sanity check: < 10 seconds
						data.requestResponsePairs = append(data.requestResponsePairs, RequestResponsePair{
							RequestTime:  req.timestamp,
							ResponseTime: pkt.Timestamp,
							Service:      req.service,
							Class:        req.class,
							LatencyMs:    latency,
						})
					}
					delete(pending, reqKey)
				}
			}
		}
	}
}

// serviceMapToSlice converts a service map to a sorted slice.
func serviceMapToSlice(services map[string]ServiceInfo) []ServiceInfo {
	result := make([]ServiceInfo, 0, len(services))
	for _, info := range services {
		result = append(result, info)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ServiceCode != result[j].ServiceCode {
			return result[i].ServiceCode < result[j].ServiceCode
		}
		return result[i].Class < result[j].Class
	})
	return result
}

// pendingRequest tracks a request awaiting response.
type pendingRequest struct {
	timestamp time.Time
	service   uint8
	class     uint16
}

// diffServices compares services between baseline and compare.
func diffServices(baseline, compare map[string]ServiceInfo) (added, removed, common []ServiceInfo) {
	for key, info := range compare {
		if _, ok := baseline[key]; !ok {
			added = append(added, info)
		} else {
			common = append(common, info)
		}
	}
	for key, info := range baseline {
		if _, ok := compare[key]; !ok {
			removed = append(removed, info)
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].ServiceCode < added[j].ServiceCode })
	sort.Slice(removed, func(i, j int) bool { return removed[i].ServiceCode < removed[j].ServiceCode })
	sort.Slice(common, func(i, j int) bool { return common[i].ServiceCode < common[j].ServiceCode })
	return
}

// diffClasses compares object classes between baseline and compare.
func diffClasses(baseline, compare map[uint16]int) (added, removed, common []uint16) {
	for class := range compare {
		if _, ok := baseline[class]; !ok {
			added = append(added, class)
		} else {
			common = append(common, class)
		}
	}
	for class := range baseline {
		if _, ok := compare[class]; !ok {
			removed = append(removed, class)
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i] < added[j] })
	sort.Slice(removed, func(i, j int) bool { return removed[i] < removed[j] })
	sort.Slice(common, func(i, j int) bool { return common[i] < common[j] })
	return
}

// computeTimingStats computes latency statistics from request/response pairs.
func computeTimingStats(pairs []RequestResponsePair) *TimingStats {
	if len(pairs) == 0 {
		return &TimingStats{}
	}

	stats := &TimingStats{
		PacketCount:     len(pairs),
		RequestResponse: pairs,
		Latencies:       make([]float64, len(pairs)),
	}

	var sum float64
	for i, pair := range pairs {
		stats.Latencies[i] = pair.LatencyMs
		sum += pair.LatencyMs
		if i == 0 || pair.LatencyMs < stats.MinLatencyMs {
			stats.MinLatencyMs = pair.LatencyMs
		}
		if pair.LatencyMs > stats.MaxLatencyMs {
			stats.MaxLatencyMs = pair.LatencyMs
		}
	}

	stats.AvgLatencyMs = sum / float64(len(pairs))

	// Compute percentiles
	sorted := make([]float64, len(stats.Latencies))
	copy(sorted, stats.Latencies)
	sort.Float64s(sorted)

	stats.P50LatencyMs = percentileValue(sorted, 0.50)
	stats.P90LatencyMs = percentileValue(sorted, 0.90)
	stats.P95LatencyMs = percentileValue(sorted, 0.95)
	stats.P99LatencyMs = percentileValue(sorted, 0.99)

	return stats
}

// computeRPIStats computes RPI jitter statistics from I/O timestamps.
func computeRPIStats(timestamps []time.Time, expectedRPIMs, tolerancePct float64) *RPIStats {
	if len(timestamps) < 2 {
		return &RPIStats{ExpectedRPIMs: expectedRPIMs}
	}

	stats := &RPIStats{
		PacketCount:   len(timestamps),
		ExpectedRPIMs: expectedRPIMs,
		Intervals:     make([]float64, 0, len(timestamps)-1),
	}

	var sum float64
	for i := 1; i < len(timestamps); i++ {
		interval := timestamps[i].Sub(timestamps[i-1]).Seconds() * 1000
		if interval > 0 && interval < 10000 { // Sanity check
			stats.Intervals = append(stats.Intervals, interval)
			sum += interval

			if len(stats.Intervals) == 1 || interval < stats.MinIntervalMs {
				stats.MinIntervalMs = interval
			}
			if interval > stats.MaxIntervalMs {
				stats.MaxIntervalMs = interval
			}

			// Check RPI violations
			tolerance := expectedRPIMs * tolerancePct / 100.0
			if math.Abs(interval-expectedRPIMs) > tolerance {
				stats.RPIViolations++
			}
		}
	}

	if len(stats.Intervals) == 0 {
		return stats
	}

	stats.AvgIntervalMs = sum / float64(len(stats.Intervals))
	stats.ViolationPct = float64(stats.RPIViolations) / float64(len(stats.Intervals)) * 100

	// Compute standard deviation and jitter
	var sumSquares float64
	for _, interval := range stats.Intervals {
		diff := interval - stats.AvgIntervalMs
		sumSquares += diff * diff
	}
	stats.StdDevMs = math.Sqrt(sumSquares / float64(len(stats.Intervals)))
	stats.JitterMs = stats.MaxIntervalMs - stats.MinIntervalMs

	// Compute percentiles
	sorted := make([]float64, len(stats.Intervals))
	copy(sorted, stats.Intervals)
	sort.Float64s(sorted)

	stats.P50IntervalMs = percentileValue(sorted, 0.50)
	stats.P90IntervalMs = percentileValue(sorted, 0.90)
	stats.P95IntervalMs = percentileValue(sorted, 0.95)
	stats.P99IntervalMs = percentileValue(sorted, 0.99)

	return stats
}

// percentileValue returns the value at the given percentile.
func percentileValue(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// FormatDiffReport formats a DiffResult as a human-readable report.
func FormatDiffReport(result *DiffResult) string {
	var b strings.Builder

	b.WriteString("PCAP Diff Report\n")
	b.WriteString(strings.Repeat("=", 60) + "\n\n")

	b.WriteString(fmt.Sprintf("Baseline: %s\n", result.BaselinePath))
	b.WriteString(fmt.Sprintf("Compare:  %s\n\n", result.ComparePath))

	b.WriteString("Packet Counts:\n")
	b.WriteString(fmt.Sprintf("  Baseline: %d packets, %d CIP messages\n",
		result.BaselinePacketCount, result.BaselineCIPCount))
	b.WriteString(fmt.Sprintf("  Compare:  %d packets, %d CIP messages\n\n",
		result.ComparePacketCount, result.CompareCIPCount))

	// Service summary for each PCAP
	b.WriteString("Baseline Services:\n")
	b.WriteString(strings.Repeat("-", 60) + "\n")
	if len(result.BaselineServices) == 0 {
		b.WriteString("  (none)\n")
	} else {
		for _, s := range result.BaselineServices {
			reqResp := "req"
			if s.IsResponse {
				reqResp = "rsp"
			}
			b.WriteString(fmt.Sprintf("  0x%02X %-25s Class:0x%04X %s Count:%d\n",
				s.ServiceCode, s.ServiceName, s.Class, reqResp, s.Count))
		}
	}

	b.WriteString("\nCompare Services:\n")
	b.WriteString(strings.Repeat("-", 60) + "\n")
	if len(result.CompareServices) == 0 {
		b.WriteString("  (none)\n")
	} else {
		for _, s := range result.CompareServices {
			reqResp := "req"
			if s.IsResponse {
				reqResp = "rsp"
			}
			b.WriteString(fmt.Sprintf("  0x%02X %-25s Class:0x%04X %s Count:%d\n",
				s.ServiceCode, s.ServiceName, s.Class, reqResp, s.Count))
		}
	}

	// Service differences
	b.WriteString("\nService Code Differences:\n")
	b.WriteString(strings.Repeat("-", 60) + "\n")

	if len(result.AddedServices) > 0 {
		b.WriteString("\n  ADDED (in compare, not in baseline):\n")
		for _, s := range result.AddedServices {
			b.WriteString(fmt.Sprintf("    + 0x%02X %-25s Class:0x%04X Count:%d\n",
				s.ServiceCode, s.ServiceName, s.Class, s.Count))
		}
	}

	if len(result.RemovedServices) > 0 {
		b.WriteString("\n  REMOVED (in baseline, not in compare):\n")
		for _, s := range result.RemovedServices {
			b.WriteString(fmt.Sprintf("    - 0x%02X %-25s Class:0x%04X Count:%d\n",
				s.ServiceCode, s.ServiceName, s.Class, s.Count))
		}
	}

	if len(result.AddedServices) == 0 && len(result.RemovedServices) == 0 {
		b.WriteString("  No service differences found.\n")
	}

	b.WriteString(fmt.Sprintf("\n  Common services: %d\n", len(result.CommonServices)))

	// Class differences
	b.WriteString("\nObject Class Differences:\n")
	b.WriteString(strings.Repeat("-", 60) + "\n")

	if len(result.AddedClasses) > 0 {
		b.WriteString("  ADDED: ")
		for i, c := range result.AddedClasses {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(fmt.Sprintf("0x%04X", c))
		}
		b.WriteString("\n")
	}

	if len(result.RemovedClasses) > 0 {
		b.WriteString("  REMOVED: ")
		for i, c := range result.RemovedClasses {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(fmt.Sprintf("0x%04X", c))
		}
		b.WriteString("\n")
	}

	if len(result.AddedClasses) == 0 && len(result.RemovedClasses) == 0 {
		b.WriteString("  No class differences found.\n")
	}

	// Timing stats
	if result.BaselineTiming != nil && result.CompareTiming != nil {
		b.WriteString("\nLatency Analysis:\n")
		b.WriteString(strings.Repeat("-", 60) + "\n")
		b.WriteString("                    Baseline        Compare         Delta\n")
		b.WriteString(fmt.Sprintf("  Samples:          %-15d %-15d\n",
			result.BaselineTiming.PacketCount, result.CompareTiming.PacketCount))
		b.WriteString(fmt.Sprintf("  Min (ms):         %-15.3f %-15.3f %+.3f\n",
			result.BaselineTiming.MinLatencyMs, result.CompareTiming.MinLatencyMs,
			result.CompareTiming.MinLatencyMs-result.BaselineTiming.MinLatencyMs))
		b.WriteString(fmt.Sprintf("  Max (ms):         %-15.3f %-15.3f %+.3f\n",
			result.BaselineTiming.MaxLatencyMs, result.CompareTiming.MaxLatencyMs,
			result.CompareTiming.MaxLatencyMs-result.BaselineTiming.MaxLatencyMs))
		b.WriteString(fmt.Sprintf("  Avg (ms):         %-15.3f %-15.3f %+.3f\n",
			result.BaselineTiming.AvgLatencyMs, result.CompareTiming.AvgLatencyMs,
			result.CompareTiming.AvgLatencyMs-result.BaselineTiming.AvgLatencyMs))
		b.WriteString(fmt.Sprintf("  P50 (ms):         %-15.3f %-15.3f %+.3f\n",
			result.BaselineTiming.P50LatencyMs, result.CompareTiming.P50LatencyMs,
			result.CompareTiming.P50LatencyMs-result.BaselineTiming.P50LatencyMs))
		b.WriteString(fmt.Sprintf("  P95 (ms):         %-15.3f %-15.3f %+.3f\n",
			result.BaselineTiming.P95LatencyMs, result.CompareTiming.P95LatencyMs,
			result.CompareTiming.P95LatencyMs-result.BaselineTiming.P95LatencyMs))
		b.WriteString(fmt.Sprintf("  P99 (ms):         %-15.3f %-15.3f %+.3f\n",
			result.BaselineTiming.P99LatencyMs, result.CompareTiming.P99LatencyMs,
			result.CompareTiming.P99LatencyMs-result.BaselineTiming.P99LatencyMs))
	}

	// RPI stats
	if result.BaselineRPI != nil && result.CompareRPI != nil &&
		(len(result.BaselineRPI.Intervals) > 0 || len(result.CompareRPI.Intervals) > 0) {
		b.WriteString("\nRPI/Jitter Analysis:\n")
		b.WriteString(strings.Repeat("-", 60) + "\n")
		b.WriteString(fmt.Sprintf("  Expected RPI: %.1f ms\n", result.BaselineRPI.ExpectedRPIMs))
		b.WriteString("                    Baseline        Compare         Delta\n")
		b.WriteString(fmt.Sprintf("  I/O Packets:      %-15d %-15d\n",
			result.BaselineRPI.PacketCount, result.CompareRPI.PacketCount))
		b.WriteString(fmt.Sprintf("  Avg Interval:     %-15.3f %-15.3f %+.3f\n",
			result.BaselineRPI.AvgIntervalMs, result.CompareRPI.AvgIntervalMs,
			result.CompareRPI.AvgIntervalMs-result.BaselineRPI.AvgIntervalMs))
		b.WriteString(fmt.Sprintf("  Jitter (max-min): %-15.3f %-15.3f %+.3f\n",
			result.BaselineRPI.JitterMs, result.CompareRPI.JitterMs,
			result.CompareRPI.JitterMs-result.BaselineRPI.JitterMs))
		b.WriteString(fmt.Sprintf("  Std Dev:          %-15.3f %-15.3f %+.3f\n",
			result.BaselineRPI.StdDevMs, result.CompareRPI.StdDevMs,
			result.CompareRPI.StdDevMs-result.BaselineRPI.StdDevMs))
		b.WriteString(fmt.Sprintf("  RPI Violations:   %-15d %-15d\n",
			result.BaselineRPI.RPIViolations, result.CompareRPI.RPIViolations))
		b.WriteString(fmt.Sprintf("  Violation %%:      %-15.1f %-15.1f\n",
			result.BaselineRPI.ViolationPct, result.CompareRPI.ViolationPct))
	}

	return b.String()
}
