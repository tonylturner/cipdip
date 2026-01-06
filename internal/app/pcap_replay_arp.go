package app

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

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
