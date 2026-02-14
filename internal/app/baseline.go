package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tonylturner/cipdip/internal/capture"
	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/config"
	"github.com/tonylturner/cipdip/internal/logging"
	"github.com/tonylturner/cipdip/internal/metrics"
	"github.com/tonylturner/cipdip/internal/scenario"
	"github.com/tonylturner/cipdip/internal/server"
)

type BaselineOptions struct {
	OutputDir string
	Duration  int
}

func RunBaseline(opts BaselineOptions) error {
	fmt.Fprintf(os.Stdout, "CIPDIP Baseline Test Suite\n")
	fmt.Fprintf(os.Stdout, "==========================\n\n")
	fmt.Fprintf(os.Stdout, "This will run all scenarios against all server personalities.\n")
	fmt.Fprintf(os.Stdout, "Duration per scenario: %d seconds\n", opts.Duration)
	fmt.Fprintf(os.Stdout, "Output directory: %s\n\n", opts.OutputDir)

	if err := os.MkdirAll(opts.OutputDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	clientCfg, err := config.LoadClientConfig("cipdip_client.yaml", false)
	if err != nil {
		return fmt.Errorf("load client config: %w", err)
	}

	serverCfg, err := config.LoadServerConfig("cipdip_server.yaml")
	if err != nil {
		return fmt.Errorf("load server config: %w", err)
	}

	logger, err := logging.NewLogger(logging.LogLevelError, "")
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}

	scenarios := []string{"baseline", "mixed", "stress", "churn", "io"}
	personalities := []string{"adapter", "logix_like"}

	combinedPcapPath := filepath.Join(opts.OutputDir, "baseline_all.pcap")
	fmt.Fprintf(os.Stdout, "Starting combined capture: %s\n", combinedPcapPath)
	combinedCapture, err := capture.StartCaptureLoopback(combinedPcapPath)
	if err != nil {
		return fmt.Errorf("start combined capture: %w", err)
	}
	defer func() { _ = combinedCapture.Stop() }()

	for _, personality := range personalities {
		fmt.Fprintf(os.Stdout, "\n=== Testing %s personality ===\n\n", personality)

		serverCfg.Server.Personality = personality
		serverCfg.Server.EnableUDPIO = true

		srv, err := server.NewServer(serverCfg, logger)
		if err != nil {
			return fmt.Errorf("create server: %w", err)
		}

		if err := srv.Start(); err != nil {
			return fmt.Errorf("start server: %w", err)
		}

		time.Sleep(500 * time.Millisecond)

		serverPort := serverCfg.Server.TCPPort
		if serverPort == 0 {
			serverPort = 44818
		}

		for _, scenarioName := range scenarios {
			fmt.Fprintf(os.Stdout, "Running scenario: %s (personality: %s)\n", scenarioName, personality)

			if scenarioName == "io" && len(clientCfg.IOConnections) == 0 {
				fmt.Fprintf(os.Stdout, "  Skipping io scenario (no I/O connections configured)\n")
				continue
			}

			scenarioPcapPath := filepath.Join(opts.OutputDir, fmt.Sprintf("baseline_%s_%s.pcap", scenarioName, personality))
			scenarioCapture, err := capture.StartCaptureLoopback(scenarioPcapPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to start scenario capture: %v\n", err)
			}

			client := cipclient.NewClient()

			scenarioImpl, err := scenario.GetScenario(scenarioName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to get scenario %s: %v\n", scenarioName, err)
				if scenarioCapture != nil {
					_ = scenarioCapture.Stop()
				}
				continue
			}

			metricsSink := metrics.NewSink()
			params := scenario.ScenarioParams{
				IP:          "127.0.0.1",
				Port:        serverPort,
				Interval:    getDefaultInterval(scenarioName),
				Duration:    time.Duration(opts.Duration) * time.Second,
				MetricsSink: metricsSink,
				Logger:      logger,
				TargetType:  metrics.TargetTypeEmulatorAdapter,
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.Duration+5)*time.Second)
			err = scenarioImpl.Run(ctx, client, clientCfg, params)
			cancel()

			if scenarioCapture != nil {
				_ = scenarioCapture.Stop()
				packetCount := scenarioCapture.GetPacketCount()
				fmt.Fprintf(os.Stdout, "  Captured %d packets: %s\n", packetCount, scenarioPcapPath)
			}

			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: scenario %s failed: %v\n", scenarioName, err)
			} else {
				fmt.Fprintf(os.Stdout, "  バ Completed successfully\n")
			}

			_ = client.Disconnect(ctx)
			time.Sleep(200 * time.Millisecond)
		}

		if err := srv.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: server stop error: %v\n", err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	_ = combinedCapture.Stop()
	combinedPacketCount := combinedCapture.GetPacketCount()
	fmt.Fprintf(os.Stdout, "\n=== Baseline Suite Complete ===\n")
	fmt.Fprintf(os.Stdout, "Combined capture: %d packets saved to %s\n", combinedPacketCount, combinedPcapPath)
	fmt.Fprintf(os.Stdout, "Individual captures saved to: %s\n", opts.OutputDir)

	return nil
}

func getDefaultInterval(scenarioName string) time.Duration {
	switch scenarioName {
	case "baseline":
		return 250 * time.Millisecond
	case "mixed":
		return 100 * time.Millisecond
	case "stress":
		return 20 * time.Millisecond
	case "churn":
		return 100 * time.Millisecond
	case "io":
		return 10 * time.Millisecond
	default:
		return 100 * time.Millisecond
	}
}
