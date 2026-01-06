package app

import (
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	pcappkg "github.com/tturner/cipdip/internal/pcap"
)

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
