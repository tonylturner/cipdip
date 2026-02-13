package main

import (
	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/app"
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
			if handleHelpArg(cmd, args) {
				return nil
			}
			if flags.ip == "" {
				return missingFlagError(cmd, "--ip")
			}
			return runTest(flags)
		},
	}

	cmd.Flags().StringVar(&flags.ip, "ip", "", "Target CIP adapter IP address (required)")
	cmd.Flags().IntVar(&flags.port, "port", 44818, "CIP TCP port (default 44818)")

	return cmd
}

func runTest(flags *testFlags) error {
	return app.RunConnectivityTest(app.TestOptions{
		IP:   flags.ip,
		Port: flags.port,
	})
}
