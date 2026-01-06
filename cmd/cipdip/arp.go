package main

import (
	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/app"
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
	return app.RunARP(app.ARPOptions{
		Iface:     flags.iface,
		TargetIP:  flags.targetIP,
		TimeoutMs: flags.timeoutMs,
		Retries:   flags.retries,
	})
}
