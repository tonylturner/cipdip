package main

// Test connectivity command

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/cipclient"
)

type testFlags struct {
	ip   string
	port int
}

func newTestCmd() *cobra.Command {
	flags := &testFlags{}

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test connectivity to a CIP device",
		Long: `Test basic connectivity to a CIP device by attempting to establish an EtherNet/IP session.

This command performs a quick connectivity test by:
  1. Connecting to the device on TCP port 44818 (or --port)
  2. Sending a RegisterSession request
  3. Verifying the device responds successfully
  4. Closing the connection

This is useful for:
  - Verifying network connectivity before running scenarios
  - Testing if a device is powered on and responding
  - Validating firewall rules allow EtherNet/IP traffic
  - Quick health check of CIP devices

If the test fails, troubleshooting tips are displayed to help diagnose the issue.`,
		Example: `  # Test connectivity to device
  cipdip test --ip 10.0.0.50

  # Test with custom port
  cipdip test --ip 10.0.0.50 --port 44818

  # Test before running a scenario
  cipdip test --ip 10.0.0.50 && cipdip client --ip 10.0.0.50 --scenario baseline`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTest(flags)
		},
	}

	cmd.Flags().StringVar(&flags.ip, "ip", "", "Target CIP adapter IP address (required)")
	cmd.MarkFlagRequired("ip")
	cmd.Flags().IntVar(&flags.port, "port", 44818, "CIP TCP port (default 44818)")

	return cmd
}

func runTest(flags *testFlags) error {
	fmt.Fprintf(os.Stdout, "Testing connectivity to %s:%d...\n", flags.ip, flags.port)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := cipclient.NewClient()

	// Attempt connection
	err := client.Connect(ctx, flags.ip, flags.port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Connection failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nTroubleshooting tips:\n")
		fmt.Fprintf(os.Stderr, "  - Verify the device IP address is correct\n")
		fmt.Fprintf(os.Stderr, "  - Check network connectivity (ping %s)\n", flags.ip)
		fmt.Fprintf(os.Stderr, "  - Verify the device is powered on and connected\n")
		fmt.Fprintf(os.Stderr, "  - Check firewall rules (port %d should be open)\n", flags.port)
		fmt.Fprintf(os.Stderr, "  - Try: cipdip discover --timeout 5s\n")
		return fmt.Errorf("connectivity test failed")
	}

	// Success
	fmt.Fprintf(os.Stdout, "✓ Connection successful\n")
	fmt.Fprintf(os.Stdout, "  Session registered successfully\n")

	// Clean disconnect
	_ = client.Disconnect(ctx)

	return nil
}
