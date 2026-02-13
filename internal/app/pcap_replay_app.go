package app

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	pcappkg "github.com/tonylturner/cipdip/internal/pcap"
)

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
