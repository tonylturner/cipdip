package app

import (
	"context"
	"fmt"
	"os"
	"time"

	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
)

type TestOptions struct {
	IP   string
	Port int
}

func RunConnectivityTest(opts TestOptions) error {
	fmt.Fprintf(os.Stdout, "Testing connectivity to %s:%d...\n", opts.IP, opts.Port)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := cipclient.NewClient()

	err := client.Connect(ctx, opts.IP, opts.Port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Connection failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nTroubleshooting tips:\n")
		fmt.Fprintf(os.Stderr, "  - Verify the device IP address is correct\n")
		fmt.Fprintf(os.Stderr, "  - Check network connectivity (ping %s)\n", opts.IP)
		fmt.Fprintf(os.Stderr, "  - Verify the device is powered on and connected\n")
		fmt.Fprintf(os.Stderr, "  - Check firewall rules (port %d should be open)\n", opts.Port)
		fmt.Fprintf(os.Stderr, "  - Try: cipdip discover --timeout 5s\n")
		return fmt.Errorf("connectivity test failed")
	}

	fmt.Fprintf(os.Stdout, "Connection successful\n")
	fmt.Fprintf(os.Stdout, "  Session registered successfully\n")

	_ = client.Disconnect(ctx)

	return nil
}
