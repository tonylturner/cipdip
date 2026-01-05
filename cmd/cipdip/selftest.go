package main

import (
	"context"
	"fmt"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
	"github.com/tturner/cipdip/internal/server"
)

type selfTestFlags struct {
	personality string
	latencyMs   int
	jitterMs    int
}

func newSelfTestCmd() *cobra.Command {
	flags := &selfTestFlags{
		personality: "adapter",
		latencyMs:   2,
		jitterMs:    1,
	}

	cmd := &cobra.Command{
		Use:   "selftest",
		Short: "Run a loopback client+server validation",
		Long: `Start an in-process CIP server on localhost and run a small client
validation sequence to confirm request/response handling.`,
		Example: `  # Run loopback validation
  cipdip selftest

  # Use logix_like personality
  cipdip selftest --personality logix_like`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSelfTest(flags)
		},
	}

	cmd.Flags().StringVar(&flags.personality, "personality", "adapter", "Server personality: adapter or logix_like")
	cmd.Flags().IntVar(&flags.latencyMs, "latency-ms", 2, "Base latency (ms) applied to server responses")
	cmd.Flags().IntVar(&flags.jitterMs, "jitter-ms", 1, "Latency jitter (ms) applied to server responses")

	return cmd
}

func runSelfTest(flags *selfTestFlags) error {
	cfg := &config.ServerConfig{
		Server: config.ServerConfigSection{
			Name:                "Loopback",
			Personality:         flags.personality,
			ListenIP:            "127.0.0.1",
			TCPPort:             0,
			EnableUDPIO:         false,
			ConnectionTimeoutMs: 2000,
		},
		Protocol: config.ProtocolConfig{Mode: "strict_odva"},
		Faults: config.ServerFaultConfig{
			Enable: true,
			Latency: config.ServerFaultLatencyConfig{
				BaseDelayMs:  flags.latencyMs,
				JitterMs:     flags.jitterMs,
				SpikeEveryN:  0,
				SpikeDelayMs: 0,
			},
		},
	}

	switch flags.personality {
	case "adapter":
		cfg.AdapterAssemblies = []config.AdapterAssemblyConfig{
			{
				Name:          "TestAssembly",
				Class:         spec.CIPClassAssembly,
				Instance:      0x65,
				Attribute:     0x03,
				SizeBytes:     4,
				Writable:      true,
				UpdatePattern: "static",
			},
		}
	case "logix_like":
		cfg.LogixTags = []config.LogixTagConfig{
			{
				Name:          "TestTag",
				Type:          "DINT",
				ArrayLength:   1,
				UpdatePattern: "static",
			},
		}
	default:
		return fmt.Errorf("unsupported personality %q", flags.personality)
	}

	logger, err := logging.NewLogger(logging.LogLevelError, "")
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}
	defer logger.Close()

	srv, err := server.NewServer(cfg, logger)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}
	if err := srv.Start(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	defer srv.Stop()

	addr := srv.TCPAddr()
	if addr == nil {
		return fmt.Errorf("server did not expose TCP address")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := cipclient.NewClient()
	if err := client.Connect(ctx, "127.0.0.1", addr.Port); err != nil {
		return fmt.Errorf("connect client: %w", err)
	}
	defer client.Disconnect(ctx)

	validator := cipclient.NewPacketValidator(true)
	if flags.personality == "adapter" {
		path := protocol.CIPPath{
			Class:     spec.CIPClassAssembly,
			Instance:  0x65,
			Attribute: 0x03,
		}
		readResp, err := client.ReadAttribute(ctx, path)
		if err != nil {
			return fmt.Errorf("read attribute: %w", err)
		}
		if err := validator.ValidateCIPResponse(readResp, spec.CIPServiceGetAttributeSingle); err != nil {
			return fmt.Errorf("validate read response: %w", err)
		}

		writeResp, err := client.WriteAttribute(ctx, path, []byte{0x01, 0x02, 0x03, 0x04})
		if err != nil {
			return fmt.Errorf("write attribute: %w", err)
		}
		if err := validator.ValidateCIPResponse(writeResp, spec.CIPServiceSetAttributeSingle); err != nil {
			return fmt.Errorf("validate write response: %w", err)
		}
	}

	embeddedReq := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     spec.CIPClassIdentityObject,
			Instance:  0x01,
			Attribute: 0x01,
		},
	}
	ucmmResp, embeddedResp, err := client.InvokeUnconnectedSend(ctx, embeddedReq, cipclient.UnconnectedSendOptions{})
	if err != nil {
		return fmt.Errorf("invoke unconnected send: %w", err)
	}
	if err := validator.ValidateCIPResponse(ucmmResp, spec.CIPServiceUnconnectedSend); err != nil {
		return fmt.Errorf("validate unconnected send response: %w", err)
	}
	if err := validator.ValidateCIPResponse(embeddedResp, spec.CIPServiceGetAttributeSingle); err != nil {
		return fmt.Errorf("validate embedded response: %w", err)
	}

	conn, err := client.ForwardOpen(ctx, cipclient.ConnectionParams{
		Name:                  "Loopback",
		Priority:              "scheduled",
		OToTRPIMs:             20,
		TToORPIMs:             20,
		OToTSizeBytes:         8,
		TToOSizeBytes:         8,
		TransportClassTrigger: 3,
		Class:                 spec.CIPClassAssembly,
		Instance:              0x65,
	})
	if err != nil {
		return fmt.Errorf("forward open: %w", err)
	}
	if conn == nil || conn.ID == 0 {
		return fmt.Errorf("forward open returned invalid connection")
	}
	if err := client.ForwardClose(ctx, conn); err != nil {
		return fmt.Errorf("forward close: %w", err)
	}

	fmt.Fprintln(os.Stdout, "Loopback selftest complete")
	return nil
}
