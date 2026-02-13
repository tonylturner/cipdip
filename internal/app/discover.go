package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
)

type DiscoverOptions struct {
	InterfaceName string
	Timeout       time.Duration
	Output        string
}

func RunDiscover(opts DiscoverOptions) error {
	if opts.Output != "text" && opts.Output != "json" {
		return fmt.Errorf("invalid output format '%s'; must be 'text' or 'json'", opts.Output)
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	devices, err := cipclient.DiscoverDevices(ctx, opts.InterfaceName, opts.Timeout)
	if err != nil {
		return fmt.Errorf("discover devices: %w", err)
	}

	if opts.Output == "json" {
		jsonData, err := json.MarshalIndent(devices, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
		fmt.Fprintf(os.Stdout, "%s\n", jsonData)
		return nil
	}

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

	return nil
}
