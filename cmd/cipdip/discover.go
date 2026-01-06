package main

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/app"
)

type discoverFlags struct {
	interfaceName string
	timeout       time.Duration
	output        string
}

func newDiscoverCmd() *cobra.Command {
	flags := &discoverFlags{}

	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover CIP devices using ListIdentity",
		Long: `Discover EtherNet/IP devices on the network by sending ListIdentity requests.

This command broadcasts ListIdentity requests via UDP port 44818 and collects responses
from all CIP devices on the network. It's useful for finding devices before running
client scenarios.

The command will:
  - Send UDP broadcast ListIdentity requests
  - Wait for responses (default 5 seconds)
  - Display discovered device information:
    * IP address
    * Vendor ID
    * Product ID
    * Product name
    * Serial number
    * Device state

Use --interface to specify which network interface to use for broadcasting. If not
specified, broadcasts on all available interfaces.

Use --timeout to adjust how long to wait for responses. Longer timeouts may discover
more devices but take longer to complete.`,
		Example: `  # Discover devices on all interfaces (default 5s timeout)
  cipdip discover

  # Discover on specific interface with custom timeout
  cipdip discover --interface eth0 --timeout 10s

  # Output results as JSON
  cipdip discover --output json

  # Quick discovery (2 seconds)
  cipdip discover --timeout 2s`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiscover(flags)
		},
	}

	cmd.Flags().StringVar(&flags.interfaceName, "interface", "", "Network interface for broadcast (default: all interfaces)")
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 5*time.Second, "Discovery timeout duration (default 5s)")
	cmd.Flags().StringVar(&flags.output, "output", "text", "Output format: text|json (default \"text\")")

	return cmd
}

func runDiscover(flags *discoverFlags) error {
	return app.RunDiscover(app.DiscoverOptions{
		InterfaceName: flags.interfaceName,
		Timeout:       flags.timeout,
		Output:        flags.output,
	})
}
