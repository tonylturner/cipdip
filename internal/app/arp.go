package app

import (
	"fmt"
	"net"
	"os"
)

type ARPOptions struct {
	Iface     string
	TargetIP  string
	TimeoutMs int
	Retries   int
}

func RunARP(opts ARPOptions) error {
	targetIP := net.ParseIP(opts.TargetIP)
	if targetIP == nil {
		return fmt.Errorf("invalid target-ip: %s", opts.TargetIP)
	}
	iface, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return fmt.Errorf("lookup interface: %w", err)
	}
	srcIP, err := firstIPv4Addr(iface)
	if err != nil {
		return err
	}

	var mac string
	for i := 0; i < maxInt(1, opts.Retries); i++ {
		var resolved []byte
		resolved, err = resolveARP(opts.Iface, srcIP, targetIP, opts.TimeoutMs)
		if err != nil {
			continue
		}
		if len(resolved) > 0 {
			mac = net.HardwareAddr(resolved).String()
			break
		}
	}
	if mac == "" {
		return fmt.Errorf("ARP resolution failed for %s", opts.TargetIP)
	}
	fmt.Fprintf(os.Stdout, "Resolved %s -> %s\n", opts.TargetIP, mac)
	return nil
}
