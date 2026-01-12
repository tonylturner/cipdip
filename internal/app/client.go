package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tturner/cipdip/internal/artifact"
	"github.com/tturner/cipdip/internal/capture"
	cipclient "github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/cip/spec"
	"github.com/tturner/cipdip/internal/config"
	cipdipErrors "github.com/tturner/cipdip/internal/errors"
	"github.com/tturner/cipdip/internal/logging"
	"github.com/tturner/cipdip/internal/metrics"
	processprofile "github.com/tturner/cipdip/internal/profile"
	"github.com/tturner/cipdip/internal/scenario"
)

type ClientOptions struct {
	IP               string
	Port             int
	Scenario         string
	IntervalMs       int
	DurationSec      int
	ConfigPath       string
	LogFile          string
	MetricsFile      string
	Verbose          bool
	Debug            bool
	PCAPFile         string
	CaptureInterface string
	QuickStart       bool
	CIPProfile       string
	TargetTags       string
	FirewallVendor   string
	TUIStats         bool
	Profile          string
	Role             string
	OutputDir        string
}

func RunClient(opts ClientOptions) error {
	// Validate scenario (unless using profile mode)
	if opts.Profile == "" {
		validScenarios := map[string]bool{
			"baseline":            true,
			"mixed":               true,
			"stress":              true,
			"churn":               true,
			"io":                  true,
			"edge_valid":          true,
			"edge_vendor":         true,
			"rockwell":            true,
			"vendor_variants":     true,
			"mixed_state":         true,
			"unconnected_send":    true,
			"firewall_hirschmann": true,
			"firewall_moxa":       true,
			"firewall_dynics":     true,
			"firewall_pack":       true,
		}
		if !validScenarios[opts.Scenario] {
			return fmt.Errorf("invalid scenario '%s'; must be one of: baseline, mixed, stress, churn, io, edge_valid, edge_vendor, rockwell, vendor_variants, mixed_state, unconnected_send, firewall_hirschmann, firewall_moxa, firewall_dynics, firewall_pack", opts.Scenario)
		}

		if opts.IntervalMs == 0 {
			switch opts.Scenario {
			case "baseline":
				opts.IntervalMs = 250
			case "mixed":
				opts.IntervalMs = 100
			case "stress":
				opts.IntervalMs = 20
			case "churn":
				opts.IntervalMs = 100
			case "io":
				opts.IntervalMs = 10
			case "edge_valid":
				opts.IntervalMs = 100
			case "edge_vendor":
				opts.IntervalMs = 100
			case "rockwell":
				opts.IntervalMs = 100
			case "vendor_variants":
				opts.IntervalMs = 100
			case "mixed_state":
				opts.IntervalMs = 50
			case "unconnected_send":
				opts.IntervalMs = 100
			case "firewall_hirschmann", "firewall_moxa", "firewall_dynics", "firewall_pack":
				opts.IntervalMs = 100
			}
		}
	}

	logLevel := logging.LogLevelInfo
	if opts.Debug {
		logLevel = logging.LogLevelDebug
	} else if opts.Verbose {
		logLevel = logging.LogLevelVerbose
	}

	logger, err := logging.NewLogger(logLevel, opts.LogFile)
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}
	defer logger.Close()

	autoCreate := opts.QuickStart
	cfg, err := config.LoadClientConfig(opts.ConfigPath, autoCreate)
	if err != nil {
		var pathErr *os.PathError
		if !autoCreate && errors.As(err, &pathErr) && os.IsNotExist(pathErr.Err) {
			fmt.Fprintf(os.Stderr, "ERROR: Config file not found: %s\n", opts.ConfigPath)
			fmt.Fprintf(os.Stderr, "Hint: Use --quick-start to auto-generate a default config file\n")
			fmt.Fprintf(os.Stderr, "      Or copy configs/cipdip_client.yaml.example to %s and customize it\n", opts.ConfigPath)
			return fmt.Errorf("load config: %w", err)
		}
		userErr := cipdipErrors.WrapConfigError(err, opts.ConfigPath)
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", userErr)
		return fmt.Errorf("load config: %w", err)
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

	applyCIPProfileTargets(cfg)
	if opts.TargetTags != "" {
		tags := parseTags(opts.TargetTags)
		cfg.ReadTargets = filterTargetsByTags(cfg.ReadTargets, tags)
		cfg.WriteTargets = filterTargetsByTags(cfg.WriteTargets, tags)
		cfg.CustomTargets = filterTargetsByTags(cfg.CustomTargets, tags)
		cfg.EdgeTargets = filterEdgeTargetsByTags(cfg.EdgeTargets, tags)
		cfg.IOConnections = filterIOByTags(cfg.IOConnections, tags)
	}

	if autoCreate {
		if info, err := os.Stat(opts.ConfigPath); err == nil {
			if time.Since(info.ModTime()) < 2*time.Second {
				fmt.Fprintf(os.Stdout, "Created default config file: %s\n", opts.ConfigPath)
				fmt.Fprintf(os.Stdout, "You can customize this file for your target device.\n\n")
			}
		}
	}

	// Set up artifact output manager if output directory specified
	var outputMgr *artifact.OutputManager
	if opts.OutputDir != "" {
		var err error
		outputMgr, err = artifact.NewOutputManager(opts.OutputDir)
		if err != nil {
			return fmt.Errorf("create output manager: %w", err)
		}

		// Use output manager paths for artifacts
		if opts.PCAPFile == "" {
			opts.PCAPFile = outputMgr.PCAPPath()
			outputMgr.SetPCAPFile(filepath.Base(opts.PCAPFile))
		}
		if opts.MetricsFile == "" {
			opts.MetricsFile = outputMgr.MetricsPath()
			outputMgr.SetMetricsFile(filepath.Base(opts.MetricsFile))
		}

		outputMgr.SetTarget(opts.IP, opts.Port)
		fmt.Fprintf(os.Stdout, "Output directory: %s\n", opts.OutputDir)
	}

	metricsSink := metrics.NewSink()
	var metricsWriter *metrics.Writer
	if opts.MetricsFile != "" {
		metricsWriter, err = metrics.NewWriter(opts.MetricsFile, "")
		if err != nil {
			return fmt.Errorf("create metrics writer: %w", err)
		}
		defer metricsWriter.Close()
	}

	var pcapCapture *capture.Capture
	if opts.PCAPFile != "" {
		var ifaceName string
		if opts.CaptureInterface != "" {
			// Use explicitly specified interface
			fmt.Fprintf(os.Stdout, "Starting packet capture on %s: %s\n", opts.CaptureInterface, opts.PCAPFile)
			pcapCapture, err = capture.StartCapture(opts.CaptureInterface, opts.PCAPFile)
			ifaceName = opts.CaptureInterface
		} else {
			// Auto-detect interface for target IP
			pcapCapture, ifaceName, err = capture.StartCaptureForClient(opts.PCAPFile, opts.IP)
			if err == nil {
				fmt.Fprintf(os.Stdout, "Starting packet capture on %s (auto-detected): %s\n", ifaceName, opts.PCAPFile)
			}
		}
		if err != nil {
			return fmt.Errorf("start packet capture on %s: %w", ifaceName, err)
		}
		defer pcapCapture.Stop()
	}

	fmt.Fprintf(os.Stdout, "CIPDIP Client starting...\n")
	if opts.Profile != "" {
		fmt.Fprintf(os.Stdout, "  Profile: %s (role: %s)\n", opts.Profile, opts.Role)
	} else {
		fmt.Fprintf(os.Stdout, "  Scenario: %s\n", opts.Scenario)
	}
	fmt.Fprintf(os.Stdout, "  Target: %s:%d\n", opts.IP, opts.Port)
	if opts.Profile == "" {
		fmt.Fprintf(os.Stdout, "  Interval: %d ms\n", opts.IntervalMs)
	}
	fmt.Fprintf(os.Stdout, "  Duration: %d seconds\n", opts.DurationSec)
	if opts.PCAPFile != "" {
		fmt.Fprintf(os.Stdout, "  PCAP: %s\n", opts.PCAPFile)
	}
	fmt.Fprintf(os.Stdout, "  Press Ctrl+C to stop\n\n")
	os.Stdout.Sync()

	startupScenario := opts.Scenario
	if opts.Profile != "" {
		startupScenario = fmt.Sprintf("profile:%s/%s", opts.Profile, opts.Role)
	}
	logger.LogStartup(startupScenario, opts.IP, opts.Port, opts.IntervalMs, opts.DurationSec, opts.ConfigPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info("Received interrupt signal, shutting down gracefully...")
		cancel()
	}()

	client := cipclient.NewClient()

	var scenarioImpl scenario.Scenario
	var scenarioName string

	if opts.Profile != "" {
		// Load profile and create ProfileScenario
		p, err := processprofile.LoadProfileByName(opts.Profile)
		if err != nil {
			return fmt.Errorf("load profile '%s': %w", opts.Profile, err)
		}

		// Validate role exists
		role := p.GetRole(opts.Role)
		if role == nil {
			availableRoles := make([]string, 0, len(p.Roles))
			for name := range p.Roles {
				availableRoles = append(availableRoles, name)
			}
			return fmt.Errorf("role '%s' not found in profile '%s'; available roles: %v", opts.Role, opts.Profile, availableRoles)
		}

		scenarioImpl = &scenario.ProfileScenario{
			Profile: p,
			Role:    opts.Role,
		}
		scenarioName = fmt.Sprintf("profile:%s/%s", opts.Profile, opts.Role)

		// Configure output manager for profile run
		if outputMgr != nil {
			outputMgr.SetProfile(opts.Profile, opts.Role, p.Metadata.Personality)
			outputMgr.SetConfig(int(role.PollInterval.MustParse().Milliseconds()), role.BatchSize)
		}
	} else {
		var err error
		scenarioImpl, err = scenario.GetScenario(opts.Scenario)
		if err != nil {
			return fmt.Errorf("get scenario: %w", err)
		}
		scenarioName = opts.Scenario

		// Configure output manager for scenario run
		if outputMgr != nil {
			outputMgr.SetScenario(opts.Scenario)
			outputMgr.SetConfig(opts.IntervalMs, 1)
		}
	}

	params := scenario.ScenarioParams{
		IP:          opts.IP,
		Port:        opts.Port,
		Interval:    time.Duration(opts.IntervalMs) * time.Millisecond,
		Duration:    time.Duration(opts.DurationSec) * time.Second,
		MetricsSink: metricsSink,
		Logger:      logger,
		TargetType:  determineTargetType(cfg, opts.IP),
	}

	// Start TUI stats output if enabled
	var statsQuit chan struct{}
	if opts.TUIStats {
		statsQuit = make(chan struct{})
		go clientStatsLoop(ctx, metricsSink, statsQuit)
	}

	startTime := time.Now()
	err = scenarioImpl.Run(ctx, client, cfg, params)

	// Stop stats output
	if statsQuit != nil {
		close(statsQuit)
	}
	elapsed := time.Since(startTime)

	if label := buildScenarioLabel(scenarioName, opts.FirewallVendor, parseTags(opts.TargetTags)); label != "" {
		metricsSink.RelabelScenario(label)
	}

	summary := metricsSink.GetSummary()

	if metricsWriter != nil {
		for _, m := range metricsSink.GetMetrics() {
			if err := metricsWriter.WriteMetric(m); err != nil {
				logger.Error("Failed to write metric: %v", err)
			}
		}
		if err := metricsWriter.WriteSummary(summary, metricsSink.GetMetrics()); err != nil {
			logger.Error("Failed to write summary metrics: %v", err)
		}
	}

	if opts.Verbose || opts.Debug {
		fmt.Fprintf(os.Stdout, "\n%s", metrics.FormatSummary(summary))
	} else {
		fmt.Fprintf(os.Stdout, "Completed scenario '%s' in %.1fs (%d operations, %d errors)\n",
			scenarioName, elapsed.Seconds(), summary.TotalOperations, summary.FailedOps)
	}

	// Finalize artifact output
	if outputMgr != nil {
		exitCode := 0
		if err != nil {
			exitCode = 1
		}
		if finalizeErr := outputMgr.Finalize(summary, metricsSink.GetMetrics(), exitCode, err); finalizeErr != nil {
			logger.Error("Failed to finalize artifacts: %v", finalizeErr)
		} else {
			fmt.Fprintf(os.Stdout, "Artifacts written to: %s\n", opts.OutputDir)
		}
	}

	if err != nil {
		return fmt.Errorf("scenario failed: %w", err)
	}

	return nil
}

func parseTags(input string) []string {
	if input == "" {
		return nil
	}
	parts := strings.Split(input, ",")
	tags := make([]string, 0, len(parts))
	for _, part := range parts {
		tag := strings.TrimSpace(part)
		if tag == "" {
			continue
		}
		tags = append(tags, strings.ToLower(tag))
	}
	return tags
}

func buildScenarioLabel(base, firewall string, tags []string) string {
	if firewall == "" && len(tags) == 0 {
		return ""
	}
	parts := []string{base}
	if firewall != "" {
		parts = append(parts, fmt.Sprintf("fw=%s", strings.ToLower(strings.TrimSpace(firewall))))
	}
	if len(tags) > 0 {
		parts = append(parts, fmt.Sprintf("tags=%s", strings.Join(tags, "+")))
	}
	return strings.Join(parts, "|")
}

func filterTargetsByTags(targets []config.CIPTarget, tags []string) []config.CIPTarget {
	if len(tags) == 0 {
		return targets
	}
	filtered := make([]config.CIPTarget, 0, len(targets))
	for _, target := range targets {
		if hasAllTags(target.Tags, tags) {
			filtered = append(filtered, target)
		}
	}
	return filtered
}

func filterEdgeTargetsByTags(targets []config.EdgeTarget, tags []string) []config.EdgeTarget {
	if len(tags) == 0 {
		return targets
	}
	filtered := make([]config.EdgeTarget, 0, len(targets))
	for _, target := range targets {
		if hasAllTags(target.Tags, tags) {
			filtered = append(filtered, target)
		}
	}
	return filtered
}

func filterIOByTags(conns []config.IOConnectionConfig, tags []string) []config.IOConnectionConfig {
	if len(tags) == 0 {
		return conns
	}
	filtered := make([]config.IOConnectionConfig, 0, len(conns))
	for _, conn := range conns {
		if hasAllTags(conn.Tags, tags) {
			filtered = append(filtered, conn)
		}
	}
	return filtered
}

func hasAllTags(targetTags []string, required []string) bool {
	if len(required) == 0 {
		return true
	}
	if len(targetTags) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(targetTags))
	for _, tag := range targetTags {
		set[strings.ToLower(tag)] = struct{}{}
	}
	for _, tag := range required {
		if _, ok := set[tag]; !ok {
			return false
		}
	}
	return true
}

func determineTargetType(cfg *config.Config, ip string) metrics.TargetType {
	if ip == "127.0.0.1" || ip == "localhost" || ip == "::1" {
		return metrics.TargetTypeClick
	}
	return metrics.TargetTypeClick
}

func applyCIPProfileTargets(cfg *config.Config) {
	if len(cfg.CIPProfiles) == 0 {
		return
	}
	profiles := cipclient.NormalizeCIPProfiles(cfg.CIPProfiles)
	classList := cipclient.ResolveCIPProfileClasses(profiles, cfg.CIPProfileClasses)
	if len(classList) == 0 {
		return
	}

	seen := make(map[string]struct{})
	for _, target := range cfg.CustomTargets {
		key := fmt.Sprintf("%02X:%04X:%04X:%04X", target.ServiceCode, target.Class, target.Instance, target.Attribute)
		seen[key] = struct{}{}
	}

	addTarget := func(target config.CIPTarget) {
		key := fmt.Sprintf("%02X:%04X:%04X:%04X", target.ServiceCode, target.Class, target.Instance, target.Attribute)
		if _, ok := seen[key]; ok {
			return
		}
		cfg.CustomTargets = append(cfg.CustomTargets, target)
		seen[key] = struct{}{}
	}

	overrides := map[uint16][]config.CIPTarget{
		spec.CIPClassFileObject: {
			{
				Name:        "File_Class_Max_Instance",
				Service:     config.ServiceCustom,
				ServiceCode: uint8(spec.CIPServiceGetAttributeSingle),
				Class:       spec.CIPClassFileObject,
				Instance:    0x0000,
				Attribute:   0x0002,
			},
		},
		spec.CIPClassEventLog: {
			{
				Name:        "Event_Log_Time_Format",
				Service:     config.ServiceCustom,
				ServiceCode: uint8(spec.CIPServiceGetAttributeSingle),
				Class:       spec.CIPClassEventLog,
				Instance:    0x0000,
				Attribute:   0x0020,
			},
		},
		spec.CIPClassTimeSync: {
			{
				Name:        "Time_Sync_PTP_Enable",
				Service:     config.ServiceCustom,
				ServiceCode: uint8(spec.CIPServiceGetAttributeSingle),
				Class:       spec.CIPClassTimeSync,
				Instance:    0x0001,
				Attribute:   0x0001,
			},
		},
		spec.CIPClassModbus: {
			{
				Name:              "Modbus_Read_Holding_Registers",
				Service:           config.ServiceCustom,
				ServiceCode:       uint8(spec.CIPServiceReadModifyWrite),
				Class:             spec.CIPClassModbus,
				Instance:          0x0001,
				Attribute:         0x0000,
				RequestPayloadHex: "00000100",
			},
		},
		spec.CIPClassMotionAxis: {
			{
				Name:        "Motion_Get_Axis_Attributes_List",
				Service:     config.ServiceCustom,
				ServiceCode: uint8(spec.CIPServiceExecutePCCC),
				Class:       spec.CIPClassMotionAxis,
				Instance:    0x0001,
				Attribute:   0x0000,
			},
		},
		spec.CIPClassSafetySupervisor: {
			{
				Name:        "Safety_Supervisor_Device_Status",
				Service:     config.ServiceCustom,
				ServiceCode: uint8(spec.CIPServiceGetAttributeSingle),
				Class:       spec.CIPClassSafetySupervisor,
				Instance:    0x0001,
				Attribute:   0x000B,
			},
		},
		spec.CIPClassSafetyValidator: {
			{
				Name:        "Safety_Validator_State",
				Service:     config.ServiceCustom,
				ServiceCode: uint8(spec.CIPServiceGetAttributeSingle),
				Class:       spec.CIPClassSafetyValidator,
				Instance:    0x0001,
				Attribute:   0x0001,
			},
		},
	}

	for _, classID := range classList {
		if targets, ok := overrides[classID]; ok {
			for _, target := range targets {
				addTarget(target)
			}
			continue
		}
		addTarget(config.CIPTarget{
			Name:        fmt.Sprintf("Profile_Class_0x%04X", classID),
			Service:     config.ServiceCustom,
			ServiceCode: uint8(spec.CIPServiceGetAttributeAll),
			Class:       classID,
			Instance:    0x0001,
			Attribute:   0x0000,
		})
	}

	for _, profile := range profiles {
		if profile != "energy" {
			continue
		}
		addTarget(config.CIPTarget{
			Name:        "Energy_Start_Metering",
			Service:     config.ServiceCustom,
			ServiceCode: uint8(spec.CIPServiceExecutePCCC),
			Class:       spec.CIPClassEnergyBase,
			Instance:    0x0001,
			Attribute:   0x0000,
		})
		addTarget(config.CIPTarget{
			Name:        "Energy_Stop_Metering",
			Service:     config.ServiceCustom,
			ServiceCode: uint8(spec.CIPServiceReadTag),
			Class:       spec.CIPClassEnergyBase,
			Instance:    0x0001,
			Attribute:   0x0000,
		})
	}
}

func parseProfileFlag(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func mergeProfiles(existing, extra []string) []string {
	merged := append([]string{}, existing...)
	merged = append(merged, extra...)
	return cipclient.NormalizeCIPProfiles(merged)
}

// clientStatsLoop outputs JSON stats periodically when TUI stats are enabled.
func clientStatsLoop(ctx context.Context, sink *metrics.Sink, quit chan struct{}) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-quit:
			return
		case <-ticker.C:
			outputClientStats(sink)
		}
	}
}

// outputClientStats writes current stats as JSON to stdout.
func outputClientStats(sink *metrics.Sink) {
	summary := sink.GetSummary()
	data, err := json.Marshal(map[string]interface{}{
		"type": "stats",
		"stats": map[string]interface{}{
			"total_requests":      summary.TotalOperations,
			"successful_requests": summary.SuccessfulOps,
			"failed_requests":     summary.FailedOps,
			"timeouts":            summary.TimeoutCount,
		},
	})
	if err != nil {
		return
	}
	// Print newline first to ensure stats are on their own line
	// (progress bars use \r without \n)
	fmt.Fprintf(os.Stdout, "\n%s\n", data)
	os.Stdout.Sync()
}
