package main

import (
	"fmt"
	"net"
	"os"

	"github.com/spf13/cobra"
)

type arpFlags struct {
	iface     string
	targetIP  string
	timeoutMs int
	retries   int
}

func newArpCmd() *cobra.Command {
	flags := &arpFlags{}

	cmd := &cobra.Command{
		Use:   "arp",
		Short: "Resolve MAC address via ARP",
		Long: `Send ARP requests to resolve a target MAC address.
Useful for validating L2 reachability before raw/tcpreplay replays.`,
		Example: `  cipdip arp --iface eth0 --target-ip 10.0.0.10`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if handleHelpArg(cmd, args) {
				return nil
			}
			if flags.iface == "" {
				return missingFlagError(cmd, "--iface")
			}
			if flags.targetIP == "" {
				return missingFlagError(cmd, "--target-ip")
			}
			return runArp(flags)
		},
	}

	cmd.Flags().StringVar(&flags.iface, "iface", "", "Interface name (required)")
	cmd.Flags().StringVar(&flags.targetIP, "target-ip", "", "Target IP to resolve (required)")
	cmd.Flags().IntVar(&flags.timeoutMs, "timeout-ms", 1000, "ARP wait timeout in milliseconds")
	cmd.Flags().IntVar(&flags.retries, "retries", 2, "ARP retries")

	return cmd
}

func runArp(flags *arpFlags) error {
	targetIP := net.ParseIP(flags.targetIP)
	if targetIP == nil {
		return fmt.Errorf("invalid target-ip: %s", flags.targetIP)
	}
	iface, err := net.InterfaceByName(flags.iface)
	if err != nil {
		return fmt.Errorf("lookup interface: %w", err)
	}
	srcIP, err := firstIPv4Addr(iface)
	if err != nil {
		return err
	}

	var mac string
	for i := 0; i < maxInt(1, flags.retries); i++ {
		var resolved []byte
		resolved, err = resolveARP(flags.iface, srcIP, targetIP, flags.timeoutMs)
		if err != nil {
			continue
		}
		if len(resolved) > 0 {
			mac = net.HardwareAddr(resolved).String()
			break
		}
	}
	if mac == "" {
		return fmt.Errorf("ARP resolution failed for %s", flags.targetIP)
	}
	fmt.Fprintf(os.Stdout, "Resolved %s -> %s\n", flags.targetIP, mac)
	return nil
}
