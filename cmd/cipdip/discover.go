package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/cipclient"
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
		Long: `Send ListIdentity requests via UDP broadcast to discover CIP devices on the network.
Returns device information including IP, product name, and vendor ID.`,
		Example: `  cipdip discover
  cipdip discover --interface eth0 --timeout 5s
  cipdip discover --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiscover(flags)
		},
	}

	// Optional flags
	cmd.Flags().StringVar(&flags.interfaceName, "interface", "", "Network interface for broadcast (default: all interfaces)")
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 5*time.Second, "Discovery timeout duration (default 5s)")
	cmd.Flags().StringVar(&flags.output, "output", "text", "Output format: text|json (default \"text\")")

	return cmd
}

func runDiscover(flags *discoverFlags) error {
	// Validate output format
	if flags.output != "text" && flags.output != "json" {
		return fmt.Errorf("invalid output format '%s'; must be 'text' or 'json'", flags.output)
	}

	// Create context
	ctx, cancel := context.WithTimeout(context.Background(), flags.timeout)
	defer cancel()

	// Discover devices
	devices, err := cipclient.DiscoverDevices(ctx, flags.interfaceName, flags.timeout)
	if err != nil {
		return fmt.Errorf("discover devices: %w", err)
	}

	// Output results
	if flags.output == "json" {
		// JSON output
		jsonData, err := json.MarshalIndent(devices, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
		fmt.Fprintf(os.Stdout, "%s\n", jsonData)
	} else {
		// Text output
		if len(devices) == 0 {
			fmt.Fprintf(os.Stdout, "No devices discovered\n")
			return nil
		}

		fmt.Fprintf(os.Stdout, "Discovered %d device(s):\n\n", len(devices))
		for i, device := range devices {
			fmt.Fprintf(os.Stdout, "Device %d:\n", i+1)
			fmt.Fprintf(os.Stdout, "  IP:           %s\n", device.IP)
			fmt.Fprintf(os.Stdout, "  Vendor ID:    0x%04X\n", device.VendorID)
			fmt.Fprintf(os.Stdout, "  Product ID:   0x%04X\n", device.ProductID)
			fmt.Fprintf(os.Stdout, "  Product Name: %s\n", device.ProductName)
			fmt.Fprintf(os.Stdout, "  Serial:       0x%08X\n", device.SerialNumber)
			fmt.Fprintf(os.Stdout, "  State:        0x%02X\n", device.State)
			if i < len(devices)-1 {
				fmt.Fprintf(os.Stdout, "\n")
			}
		}
	}

	return nil
}
