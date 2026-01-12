package app

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/tturner/cipdip/internal/capture"
	cipclient "github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
	"github.com/tturner/cipdip/internal/profile"
	"github.com/tturner/cipdip/internal/server"
)

type ServerOptions struct {
	ListenIP         string
	ListenPort       int
	Personality      string
	ConfigPath       string
	EnableUDPIO      bool
	PCAPFile         string
	CaptureInterface string
	CIPProfile       string
	Mode             string
	Target           string
	LogFormat        string
	LogLevel         string
	LogEvery         int
	TUIStats         bool
	Profile          string // Process profile name (loads data model from profile)
}

func RunServer(opts ServerOptions) error {
	var pcapCapture *capture.Capture
	if opts.PCAPFile != "" {
		var err error
		var ifaceName string
		if opts.CaptureInterface != "" {
			// Use explicitly specified interface
			fmt.Fprintf(os.Stdout, "Starting packet capture on %s: %s\n", opts.CaptureInterface, opts.PCAPFile)
			pcapCapture, err = capture.StartCapture(opts.CaptureInterface, opts.PCAPFile)
			ifaceName = opts.CaptureInterface
		} else {
			// Auto-detect interface for listen IP
			pcapCapture, ifaceName, err = capture.StartCaptureForServer(opts.PCAPFile, opts.ListenIP)
			if err == nil {
				fmt.Fprintf(os.Stdout, "Starting packet capture on %s (auto-detected): %s\n", ifaceName, opts.PCAPFile)
			}
		}
		if err != nil {
			return fmt.Errorf("start packet capture on %s: %w", ifaceName, err)
		}
		defer pcapCapture.Stop()
	}

	var cfg *config.ServerConfig

	fmt.Fprintf(os.Stdout, "CIPDIP Server starting...\n")

	// Load config from profile or config file
	if opts.Profile != "" {
		// Load profile and convert to server config
		p, err := profile.LoadProfileByName(opts.Profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to load profile: %v\n", err)
			return fmt.Errorf("load profile: %w", err)
		}
		cfg = p.ToServerConfig()
		// Override personality from profile
		opts.Personality = p.Metadata.Personality
		fmt.Fprintf(os.Stdout, "  Profile: %s\n", p.Metadata.Name)
		fmt.Fprintf(os.Stdout, "  Personality: %s\n", p.Metadata.Personality)
		fmt.Fprintf(os.Stdout, "  Tags/Assemblies: %d\n", len(p.DataModel.Tags)+len(p.DataModel.Assemblies))
	} else {
		if opts.Personality != "adapter" && opts.Personality != "logix_like" {
			return fmt.Errorf("invalid personality '%s'; must be 'adapter' or 'logix_like'", opts.Personality)
		}

		var err error
		cfg, err = config.LoadServerConfig(opts.ConfigPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to load server config: %v\n", err)
			return fmt.Errorf("load server config: %w", err)
		}
		if opts.Target != "" {
			if err := server.ApplyServerTarget(cfg, opts.Target); err != nil {
				return err
			}
		}
	}

	if opts.Mode != "" {
		if err := ApplyServerMode(cfg, opts.Mode); err != nil {
			return err
		}
	}
	if opts.CIPProfile != "" {
		profiles := cipclient.NormalizeCIPProfiles(parseProfileFlag(opts.CIPProfile))
		cfg.CIPProfiles = mergeProfiles(cfg.CIPProfiles, profiles)
	}

	profile := cipclient.ResolveProtocolProfile(
		cfg.Protocol.Mode,
		cfg.Protocol.Variant,
		cfg.Protocol.Overrides.ENIPEndianness,
		cfg.Protocol.Overrides.CIPEndianness,
		cfg.Protocol.Overrides.CIPPathSize,
		cfg.Protocol.Overrides.CIPResponseReserved,
		cfg.Protocol.Overrides.UseCPF,
		cfg.Protocol.Overrides.IOSequenceMode,
	)
	cipclient.SetProtocolProfile(profile)

	if opts.ListenIP != "" {
		cfg.Server.ListenIP = opts.ListenIP
	}
	if opts.ListenPort != 0 {
		cfg.Server.TCPPort = opts.ListenPort
	}
	if opts.Personality != "" {
		cfg.Server.Personality = opts.Personality
	}
	if opts.EnableUDPIO {
		cfg.Server.EnableUDPIO = true
	}
	if opts.LogFormat != "" {
		cfg.Logging.Format = opts.LogFormat
	}
	if opts.LogLevel != "" {
		cfg.Logging.Level = opts.LogLevel
	}
	if opts.LogEvery > 0 {
		cfg.Logging.LogEveryN = opts.LogEvery
	}

	logger, err := logging.NewLoggerWithOptions(logging.LogLevelInfo, cfg.Logging.LogFile, cfg.Logging.Format, cfg.Logging.LogEveryN)
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}
	logger.SetLevel(parseLogLevel(cfg.Logging.Level))

	srv, err := server.NewServer(cfg, logger)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	if opts.TUIStats {
		srv.EnableTUIStats()
	}

	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to start server: %v\n", err)
		return fmt.Errorf("start server: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Server started successfully\n")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan

	fmt.Fprintf(os.Stdout, "\nShutting down server...\n")

	if err := srv.Stop(); err != nil {
		return fmt.Errorf("stop server: %w", err)
	}

	if pcapCapture != nil {
		pcapCapture.Stop()
		packetCount := pcapCapture.GetPacketCount()
		absPath, _ := filepath.Abs(opts.PCAPFile)
		fmt.Fprintf(os.Stdout, "Packets captured: %d\n", packetCount)
		fmt.Fprintf(os.Stdout, "PCAP written to: %s\n", absPath)
	}

	return nil
}

func ApplyServerMode(cfg *config.ServerConfig, mode string) error {
	switch mode {
	case "baseline":
		cfg.Faults.Enable = false
		cfg.Logging.Level = "info"
		cfg.Logging.LogEveryN = 1
	case "realistic":
		cfg.Faults.Enable = false
		cfg.Logging.Level = "info"
		cfg.Logging.LogEveryN = 1
	case "dpi-torture":
		cfg.Faults.Enable = true
		cfg.Faults.Latency.BaseDelayMs = 5
		cfg.Faults.Latency.JitterMs = 10
		cfg.Faults.Latency.SpikeEveryN = 10
		cfg.Faults.Latency.SpikeDelayMs = 25
		cfg.Faults.Reliability.DropResponseEveryN = 25
		cfg.Faults.Reliability.CloseConnectionEveryN = 50
		cfg.Faults.TCP.ChunkWrites = true
		cfg.Faults.TCP.ChunkMin = 2
		cfg.Faults.TCP.ChunkMax = 4
	case "perf":
		cfg.Faults.Enable = false
		cfg.Logging.Level = "error"
		cfg.Logging.LogEveryN = 100
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
	return nil
}

func parseLogLevel(value string) logging.LogLevel {
	switch value {
	case "error":
		return logging.LogLevelError
	case "verbose":
		return logging.LogLevelVerbose
	case "debug":
		return logging.LogLevelDebug
	default:
		return logging.LogLevelInfo
	}
}
