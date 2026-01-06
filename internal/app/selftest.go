package app

import (
	"context"
	"fmt"
	"os"
	"time"

	cipclient "github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
	"github.com/tturner/cipdip/internal/server"
)

type SelfTestOptions struct {
	Personality string
	LatencyMs   int
	JitterMs    int
}

func RunSelfTest(opts SelfTestOptions) error {
	cfg := &config.ServerConfig{
		Server: config.ServerConfigSection{
			Name:                "Loopback",
			Personality:         opts.Personality,
			ListenIP:            "127.0.0.1",
			TCPPort:             0,
			EnableUDPIO:         false,
			ConnectionTimeoutMs: 2000,
		},
		Protocol: config.ProtocolConfig{Mode: "strict_odva"},
		Faults: config.ServerFaultConfig{
			Enable: true,
			Latency: config.ServerFaultLatencyConfig{
				BaseDelayMs:  opts.LatencyMs,
				JitterMs:     opts.JitterMs,
				SpikeEveryN:  0,
				SpikeDelayMs: 0,
			},
		},
	}

	switch opts.Personality {
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
		return fmt.Errorf("unsupported personality %q", opts.Personality)
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
	if opts.Personality == "adapter" {
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
