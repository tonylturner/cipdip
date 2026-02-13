package config

// Configuration loading and validation for CIPDIP

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tonylturner/cipdip/internal/errors"
)

// ServiceType represents the type of CIP service
type ServiceType string

const (
	ServiceGetAttributeSingle ServiceType = "get_attribute_single"
	ServiceSetAttributeSingle ServiceType = "set_attribute_single"
	ServiceCustom             ServiceType = "custom"
)

// AdapterConfig represents adapter configuration
type AdapterConfig struct {
	Name string `yaml:"name"`
	Port int    `yaml:"port"`
}

// ProtocolOverrides provides optional overrides for protocol behavior.
type ProtocolOverrides struct {
	ENIPEndianness      string `yaml:"enip_endianness,omitempty"`       // "little" or "big"
	CIPEndianness       string `yaml:"cip_endianness,omitempty"`        // "little" or "big"
	CIPPathSize         *bool  `yaml:"cip_path_size,omitempty"`         // include path size byte
	CIPResponseReserved *bool  `yaml:"cip_response_reserved,omitempty"` // include reserved/status-size fields
	UseCPF              *bool  `yaml:"use_cpf,omitempty"`               // encode CPF items for SendRRData/SendUnitData
	IOSequenceMode      string `yaml:"io_sequence_mode,omitempty"`      // "increment", "random", "omit"
}

// ProtocolConfig controls strict ODVA compliance and vendor-variant behavior.
type ProtocolConfig struct {
	Mode      string            `yaml:"mode"`                // "strict_odva", "vendor_variant", "legacy_compat"
	Variant   string            `yaml:"variant,omitempty"`   // optional vendor preset when mode=vendor_variant
	Overrides ProtocolOverrides `yaml:"overrides,omitempty"` // optional per-field overrides
}

// CIPTarget represents a CIP target (read, write, or custom)
type CIPTarget struct {
	Name              string         `yaml:"name"`
	Service           ServiceType    `yaml:"service"`
	ServiceCode       uint8          `yaml:"service_code,omitempty"` // used for custom services
	Class             uint16         `yaml:"class"`
	Instance          uint16         `yaml:"instance"`
	Attribute         uint16         `yaml:"attribute"`
	Pattern           string         `yaml:"pattern,omitempty"` // "increment", "toggle", "constant"
	InitialValue      int64          `yaml:"initial_value,omitempty"`
	RequestPayloadHex string         `yaml:"request_payload_hex,omitempty"` // raw hex string for request body
	PayloadType       string         `yaml:"payload_type,omitempty"`
	PayloadParams     map[string]any `yaml:"payload_params,omitempty"`
	Tags              []string       `yaml:"tags,omitempty"`
}

// IOConnectionConfig represents configuration for a connected I/O connection
type IOConnectionConfig struct {
	Name                  string   `yaml:"name"`
	Transport             string   `yaml:"transport"` // "udp" (default), "tcp", or "multicast"
	OToTRPIMs             int      `yaml:"o_to_t_rpi_ms"`
	TToORPIMs             int      `yaml:"t_to_o_rpi_ms"`
	OToTSizeBytes         int      `yaml:"o_to_t_size_bytes"`
	TToOSizeBytes         int      `yaml:"t_to_o_size_bytes"`
	Priority              string   `yaml:"priority"`
	TransportClassTrigger int      `yaml:"transport_class_trigger"`
	Class                 uint16   `yaml:"class"`
	Instance              uint16   `yaml:"instance"`
	ConnectionPathHex     string   `yaml:"connection_path_hex,omitempty"`
	MulticastGroup        string   `yaml:"multicast_group,omitempty"` // multicast group address (e.g. "239.192.1.0")
	MulticastTTL          int      `yaml:"multicast_ttl,omitempty"`   // multicast TTL (default 32)
	Tags                  []string `yaml:"tags,omitempty"`
}

// EdgeTarget represents a protocol-valid edge case target.
type EdgeTarget struct {
	Name              string         `yaml:"name"`
	Service           ServiceType    `yaml:"service"`
	ServiceCode       uint8          `yaml:"service_code,omitempty"`
	Class             uint16         `yaml:"class"`
	Instance          uint16         `yaml:"instance"`
	Attribute         uint16         `yaml:"attribute"`
	RequestPayloadHex string         `yaml:"request_payload_hex,omitempty"`
	PayloadType       string         `yaml:"payload_type,omitempty"`
	PayloadParams     map[string]any `yaml:"payload_params,omitempty"`
	ExpectedOutcome   string         `yaml:"expected_outcome,omitempty"` // "success", "error", "timeout", or "any"
	ForceStatus       *uint8         `yaml:"force_status,omitempty"`     // optional metrics override in unconnected_send
	Tags              []string       `yaml:"tags,omitempty"`
}

// Config represents the client configuration
type Config struct {
	Adapter           AdapterConfig        `yaml:"adapter"`
	Protocol          ProtocolConfig       `yaml:"protocol"`
	ProtocolVariants  []ProtocolConfig     `yaml:"protocol_variants"`
	CIPProfiles       []string             `yaml:"cip_profiles"`
	CIPProfileClasses map[string][]uint16  `yaml:"cip_profile_classes,omitempty"`
	ReadTargets       []CIPTarget          `yaml:"read_targets"`
	WriteTargets      []CIPTarget          `yaml:"write_targets"`
	CustomTargets     []CIPTarget          `yaml:"custom_targets"`
	EdgeTargets       []EdgeTarget         `yaml:"edge_targets"`
	IOConnections     []IOConnectionConfig `yaml:"io_connections"`
	ScenarioJitterMs  int                  `yaml:"scenario_jitter_ms"`
	IOJitterMs        int                  `yaml:"io_jitter_ms"`
	IOBurstEveryMs    int                  `yaml:"io_burst_every_ms"`
	IOBurstDurationMs int                  `yaml:"io_burst_duration_ms"`
	IOBurstIntervalMs int                  `yaml:"io_burst_interval_ms"`
}

// ServerConfigSection represents the server section in server config
type ServerConfigSection struct {
	Name                string `yaml:"name"`
	Personality         string `yaml:"personality"` // "adapter" or "logix_like"
	ListenIP            string `yaml:"listen_ip"`
	TCPPort             int    `yaml:"tcp_port"`
	UDPIOPort           int    `yaml:"udp_io_port"`
	EnableUDPIO         bool   `yaml:"enable_udp_io"`
	MulticastGroup      string `yaml:"multicast_group,omitempty"`     // multicast group for I/O reception
	MulticastInterface  string `yaml:"multicast_interface,omitempty"` // network interface for multicast
	ConnectionTimeoutMs int    `yaml:"connection_timeout_ms"`
	RNGSeed             int64  `yaml:"rng_seed"`
	IdentityVendorID    uint16 `yaml:"identity_vendor_id,omitempty"`
	IdentityDeviceType  uint16 `yaml:"identity_device_type,omitempty"`
	IdentityProductCode uint16 `yaml:"identity_product_code,omitempty"`
	IdentityRevMajor    uint8  `yaml:"identity_rev_major,omitempty"`
	IdentityRevMinor    uint8  `yaml:"identity_rev_minor,omitempty"`
	IdentityStatus      uint16 `yaml:"identity_status,omitempty"`
	IdentitySerial      uint32 `yaml:"identity_serial,omitempty"`
	IdentityProductName string `yaml:"identity_product_name,omitempty"`
}

// ServerENIPSupportConfig controls which ENIP commands the server accepts.
type ServerENIPSupportConfig struct {
	ListIdentity    *bool `yaml:"list_identity,omitempty"`
	ListServices    *bool `yaml:"list_services,omitempty"`
	ListInterfaces  *bool `yaml:"list_interfaces,omitempty"`
	RegisterSession *bool `yaml:"register_session,omitempty"`
	SendRRData      *bool `yaml:"send_rr_data,omitempty"`
	SendUnitData    *bool `yaml:"send_unit_data,omitempty"`
}

// ServerENIPSessionConfig controls ENIP session policy.
type ServerENIPSessionConfig struct {
	RequireRegisterSession *bool `yaml:"require_register_session,omitempty"`
	MaxSessions            int   `yaml:"max_sessions,omitempty"`
	MaxSessionsPerIP       int   `yaml:"max_sessions_per_ip,omitempty"`
	IdleTimeoutMs          int   `yaml:"idle_timeout_ms,omitempty"`
}

// ServerENIPCPFConfig controls CPF parsing policy.
type ServerENIPCPFConfig struct {
	Strict            *bool `yaml:"strict,omitempty"`
	AllowItemReorder  *bool `yaml:"allow_item_reorder,omitempty"`
	AllowExtraItems   *bool `yaml:"allow_extra_items,omitempty"`
	AllowMissingItems *bool `yaml:"allow_missing_items,omitempty"`
}

// ServerENIPConfig groups ENIP-specific server controls.
type ServerENIPConfig struct {
	Support ServerENIPSupportConfig `yaml:"support,omitempty"`
	Session ServerENIPSessionConfig `yaml:"session,omitempty"`
	CPF     ServerENIPCPFConfig     `yaml:"cpf,omitempty"`
}

// ServerFaultLatencyConfig controls response latency injection.
type ServerFaultLatencyConfig struct {
	BaseDelayMs  int `yaml:"base_delay_ms,omitempty"`
	JitterMs     int `yaml:"jitter_ms,omitempty"`
	SpikeEveryN  int `yaml:"spike_every_n,omitempty"`
	SpikeDelayMs int `yaml:"spike_delay_ms,omitempty"`
}

// ServerFaultReliabilityConfig controls drop/close/stall behavior.
type ServerFaultReliabilityConfig struct {
	DropResponseEveryN    int     `yaml:"drop_response_every_n,omitempty"`
	DropResponsePct       float64 `yaml:"drop_response_pct,omitempty"`
	CloseConnectionEveryN int     `yaml:"close_connection_every_n,omitempty"`
	StallResponseEveryN   int     `yaml:"stall_response_every_n,omitempty"`
}

// ServerFaultTCPConfig controls TCP-level behavior.
type ServerFaultTCPConfig struct {
	ChunkWrites       bool `yaml:"chunk_writes,omitempty"`
	ChunkMin          int  `yaml:"chunk_min,omitempty"`
	ChunkMax          int  `yaml:"chunk_max,omitempty"`
	InterChunkDelayMs int  `yaml:"inter_chunk_delay_ms,omitempty"`
	CoalesceResponses bool `yaml:"coalesce_responses,omitempty"`
}

// ServerFaultConfig controls fault injection for the server.
type ServerFaultConfig struct {
	Enable      bool                         `yaml:"enable,omitempty"`
	Latency     ServerFaultLatencyConfig     `yaml:"latency,omitempty"`
	Reliability ServerFaultReliabilityConfig `yaml:"reliability,omitempty"`
	TCP         ServerFaultTCPConfig         `yaml:"tcp,omitempty"`
}

// ServerLoggingConfig controls server log formatting and verbosity.
type ServerLoggingConfig struct {
	Format         string `yaml:"format,omitempty"` // "text" or "json"
	Level          string `yaml:"level,omitempty"`  // "error","info","verbose","debug"
	LogEveryN      int    `yaml:"log_every_n,omitempty"`
	IncludeHexDump bool   `yaml:"include_hex_dump,omitempty"`
	LogFile        string `yaml:"log_file,omitempty"`
}

// ServerMetricsConfig controls server metrics endpoint exposure.
type ServerMetricsConfig struct {
	Enable   bool   `yaml:"enable,omitempty"`
	ListenIP string `yaml:"listen_ip,omitempty"`
	Port     int    `yaml:"port,omitempty"`
}

// ServerCIPRule matches a CIP service/path combination for allow/deny policy.
type ServerCIPRule struct {
	Service   uint8  `yaml:"service"`
	Class     uint16 `yaml:"class,omitempty"`
	Instance  uint16 `yaml:"instance,omitempty"`
	Attribute uint16 `yaml:"attribute,omitempty"`
}

// ServerCIPStatusOverride overrides the status for a matching service/path.
type ServerCIPStatusOverride struct {
	Service   uint8  `yaml:"service"`
	Class     uint16 `yaml:"class,omitempty"`
	Instance  uint16 `yaml:"instance,omitempty"`
	Attribute uint16 `yaml:"attribute,omitempty"`
	Status    uint8  `yaml:"status"`
}

// ServerCIPPolicyConfig controls CIP routing behavior on the server.
type ServerCIPPolicyConfig struct {
	StrictPaths              *bool                     `yaml:"strict_paths,omitempty"`
	DefaultUnsupportedStatus uint8                     `yaml:"default_unsupported_status,omitempty"`
	DefaultErrorExtStatus    uint16                    `yaml:"default_error_ext_status,omitempty"`
	CatalogValidation        bool                      `yaml:"catalog_validation,omitempty"` // Enable catalog-based service validation
	Allow                    []ServerCIPRule           `yaml:"allow,omitempty"`
	Deny                     []ServerCIPRule           `yaml:"deny,omitempty"`
	DenyStatusOverrides      []ServerCIPStatusOverride `yaml:"deny_status_overrides,omitempty"`
}

// AdapterAssemblyConfig represents an adapter assembly configuration
type AdapterAssemblyConfig struct {
	Name          string `yaml:"name"`
	Class         uint16 `yaml:"class"`
	Instance      uint16 `yaml:"instance"`
	Attribute     uint16 `yaml:"attribute"`
	SizeBytes     int    `yaml:"size_bytes"`
	Writable      bool   `yaml:"writable"`
	UpdatePattern string `yaml:"update_pattern"` // "counter", "static", "random", "reflect_inputs"
}

// LogixTagConfig represents a Logix tag configuration
type LogixTagConfig struct {
	Name          string `yaml:"name"`
	Type          string `yaml:"type"` // "BOOL", "SINT", "INT", "DINT", "REAL", etc.
	ArrayLength   int    `yaml:"array_length"`
	UpdatePattern string `yaml:"update_pattern"` // "counter", "static", "random", "sine", "sawtooth"
}

// PCCCDataTableConfig defines a PCCC data table for the pccc personality.
type PCCCDataTableConfig struct {
	FileType   string `yaml:"file_type"`   // "N", "B", "T", "C", "R", "F", "ST", "O", "I", "S", "A", "L"
	FileNumber uint8  `yaml:"file_number"` // Data file number
	Elements   int    `yaml:"elements"`    // Number of elements
}

// ServerConfig represents the server configuration
type ServerConfig struct {
	Server            ServerConfigSection     `yaml:"server"`
	Protocol          ProtocolConfig          `yaml:"protocol"`
	CIPProfiles       []string                `yaml:"cip_profiles"`
	CIPProfileClasses map[string][]uint16     `yaml:"cip_profile_classes,omitempty"`
	ENIP              ServerENIPConfig        `yaml:"enip,omitempty"`
	CIP               ServerCIPPolicyConfig   `yaml:"cip,omitempty"`
	Faults            ServerFaultConfig       `yaml:"faults,omitempty"`
	Logging           ServerLoggingConfig     `yaml:"logging,omitempty"`
	Metrics           ServerMetricsConfig     `yaml:"metrics,omitempty"`
	AdapterAssemblies []AdapterAssemblyConfig `yaml:"adapter_assemblies"`
	LogixTags         []LogixTagConfig        `yaml:"logix_tags"`
	TagNamespace      string                  `yaml:"tag_namespace"`
	PCCCDataTables    []PCCCDataTableConfig   `yaml:"pccc_data_tables,omitempty"`
	ModbusConfig      ModbusServerConfig      `yaml:"modbus,omitempty"`
}

// ModbusServerConfig configures the Modbus emulation (both CIP-tunneled and standalone TCP).
type ModbusServerConfig struct {
	Enabled              bool   `yaml:"enabled"`
	TCPPort              int    `yaml:"tcp_port,omitempty"`                // Standalone Modbus TCP port (default 502)
	UnitID               uint8  `yaml:"unit_id,omitempty"`                // Default slave address (default 1)
	CoilCount            int    `yaml:"coil_count,omitempty"`             // Number of coils (default 9999)
	DiscreteInputCount   int    `yaml:"discrete_input_count,omitempty"`   // Number of discrete inputs
	InputRegisterCount   int    `yaml:"input_register_count,omitempty"`   // Number of input registers
	HoldingRegisterCount int    `yaml:"holding_register_count,omitempty"` // Number of holding registers
	CIPTunnel            bool   `yaml:"cip_tunnel,omitempty"`             // Register class 0x44 handler (default true when enabled)
}

// CreateDefaultClientConfig creates a default client configuration
func CreateDefaultClientConfig() *Config {
	return &Config{
		Adapter: AdapterConfig{
			Name: "Default Device",
			Port: 44818,
		},
		Protocol: ProtocolConfig{
			Mode: "strict_odva",
		},
		ReadTargets: []CIPTarget{
			{
				Name:      "InputBlock1",
				Service:   ServiceGetAttributeSingle,
				Class:     0x04,
				Instance:  0x65,
				Attribute: 0x03,
			},
			{
				Name:      "InputBlock2",
				Service:   ServiceGetAttributeSingle,
				Class:     0x04,
				Instance:  0x66,
				Attribute: 0x03,
			},
		},
		WriteTargets: []CIPTarget{
			{
				Name:         "OutputBlock1",
				Service:      ServiceSetAttributeSingle,
				Class:        0x04,
				Instance:     0x67,
				Attribute:    0x03,
				Pattern:      "increment",
				InitialValue: 0,
			},
		},
	}
}

// CreateDefaultServerConfig creates a default server configuration.
func CreateDefaultServerConfig() *ServerConfig {
	cfg := &ServerConfig{
		Server: ServerConfigSection{
			Name:                "CIPDIP Emulator",
			Personality:         "adapter",
			ListenIP:            "0.0.0.0",
			TCPPort:             44818,
			UDPIOPort:           2222,
			EnableUDPIO:         false,
			ConnectionTimeoutMs: 10000,
		},
		Protocol: ProtocolConfig{
			Mode: "strict_odva",
		},
		AdapterAssemblies: []AdapterAssemblyConfig{
			{
				Name:          "InputAssembly1",
				Class:         0x04,
				Instance:      0x65,
				Attribute:     0x03,
				SizeBytes:     16,
				Writable:      false,
				UpdatePattern: "counter",
			},
			{
				Name:          "OutputAssembly1",
				Class:         0x04,
				Instance:      0x67,
				Attribute:     0x03,
				SizeBytes:     16,
				Writable:      true,
				UpdatePattern: "reflect_inputs",
			},
		},
		LogixTags: []LogixTagConfig{
			{
				Name:          "scada",
				Type:          "DINT",
				ArrayLength:   1000,
				UpdatePattern: "counter",
			},
		},
		TagNamespace: "Program:MainProgram",
	}

	applyServerENIPDefaults(cfg)
	applyServerCIPDefaults(cfg)
	applyServerLoggingDefaults(cfg)
	applyServerMetricsDefaults(cfg)

	return cfg
}

// WriteDefaultClientConfig writes a default client configuration to a file
func WriteDefaultClientConfig(path string) error {
	cfg := CreateDefaultClientConfig()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal default config: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}
	return nil
}

// LoadClientConfig loads a client configuration from a YAML file
// If the file doesn't exist and autoCreate is true, it will create a default config file
func LoadClientConfig(path string, autoCreate bool) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if autoCreate {
				// Create default config
				if err := WriteDefaultClientConfig(path); err != nil {
					return nil, fmt.Errorf("create default config: %w", err)
				}
				// Read the newly created file
				data, err = os.ReadFile(path)
				if err != nil {
					return nil, errors.WrapConfigError(
						fmt.Errorf("read created config file: %w", err),
						path,
					)
				}
			} else {
				// Return user-friendly error
				return nil, errors.WrapConfigError(
					fmt.Errorf("config file not found: %s", path),
					path,
				)
			}
		} else {
			return nil, errors.WrapConfigError(
				fmt.Errorf("read config file: %w", err),
				path,
			)
		}
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	// Apply defaults
	if cfg.Adapter.Port == 0 {
		cfg.Adapter.Port = 44818
	}
	if cfg.Protocol.Mode == "" {
		cfg.Protocol.Mode = "strict_odva"
	}

	// Apply defaults for IO connections
	for i := range cfg.IOConnections {
		if cfg.IOConnections[i].Transport == "" {
			cfg.IOConnections[i].Transport = "udp"
		}
	}

	// Validate
	if err := ValidateClientConfig(&cfg); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

// ValidateClientConfig validates a client configuration
func ValidateClientConfig(cfg *Config) error {
	if cfg.Protocol.Mode == "" {
		cfg.Protocol.Mode = "strict_odva"
	}
	if err := validateProtocolConfig(cfg.Protocol); err != nil {
		return err
	}
	if err := validateCIPProfiles(cfg.CIPProfiles); err != nil {
		return err
	}
	for i := range cfg.ProtocolVariants {
		if cfg.ProtocolVariants[i].Mode == "" {
			cfg.ProtocolVariants[i].Mode = "vendor_variant"
		}
		if err := validateProtocolConfig(cfg.ProtocolVariants[i]); err != nil {
			return fmt.Errorf("protocol_variants[%d]: %w", i, err)
		}
	}

	// Check that at least one target type is populated
	if len(cfg.ReadTargets) == 0 && len(cfg.WriteTargets) == 0 && len(cfg.CustomTargets) == 0 && len(cfg.EdgeTargets) == 0 {
		return fmt.Errorf("at least one of read_targets, write_targets, custom_targets, or edge_targets must be populated")
	}

	// Validate read targets
	for i, target := range cfg.ReadTargets {
		if err := validateCIPTarget(target, "read_targets", i); err != nil {
			return err
		}
	}

	// Validate write targets
	for i, target := range cfg.WriteTargets {
		if err := validateCIPTarget(target, "write_targets", i); err != nil {
			return err
		}
	}

	// Validate custom targets
	for i, target := range cfg.CustomTargets {
		if err := validateCIPTarget(target, "custom_targets", i); err != nil {
			return err
		}
		if target.Service == ServiceCustom && target.ServiceCode == 0 {
			return fmt.Errorf("custom_targets[%d]: service_code is required when service is 'custom'", i)
		}
	}
	for i, target := range cfg.EdgeTargets {
		if err := validateEdgeTarget(target, i); err != nil {
			return err
		}
	}

	// Validate IO connections
	for i, conn := range cfg.IOConnections {
		if err := validateIOConnection(conn, i); err != nil {
			return err
		}
	}
	if cfg.ScenarioJitterMs < 0 {
		return fmt.Errorf("scenario_jitter_ms must be >= 0")
	}
	if cfg.IOJitterMs < 0 {
		return fmt.Errorf("io_jitter_ms must be >= 0")
	}
	if cfg.IOBurstEveryMs < 0 || cfg.IOBurstDurationMs < 0 || cfg.IOBurstIntervalMs < 0 {
		return fmt.Errorf("io_burst_* values must be >= 0")
	}
	if cfg.IOBurstEveryMs > 0 && cfg.IOBurstDurationMs == 0 {
		return fmt.Errorf("io_burst_duration_ms must be > 0 when io_burst_every_ms is set")
	}

	return nil
}

// validateCIPTarget validates a single CIP target
func validateCIPTarget(target CIPTarget, section string, index int) error {
	if target.Name == "" {
		return fmt.Errorf("%s[%d]: name is required", section, index)
	}

	if target.Service == "" {
		return fmt.Errorf("%s[%d]: service is required", section, index)
	}

	// Validate service type
	validServices := []ServiceType{
		ServiceGetAttributeSingle,
		ServiceSetAttributeSingle,
		ServiceCustom,
	}
	valid := false
	for _, vs := range validServices {
		if target.Service == vs {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("%s[%d]: invalid service type '%s'", section, index, target.Service)
	}

	return nil
}

// validateIOConnection validates a single IO connection configuration
func validateIOConnection(conn IOConnectionConfig, index int) error {
	if conn.Name == "" {
		return fmt.Errorf("io_connections[%d]: name is required", index)
	}

	// Validate transport
	if conn.Transport != "" && conn.Transport != "udp" && conn.Transport != "tcp" && conn.Transport != "multicast" {
		return fmt.Errorf("io_connections[%d]: transport must be 'udp', 'tcp', or 'multicast', got '%s'", index, conn.Transport)
	}

	// Validate RPIs
	if conn.OToTRPIMs <= 0 {
		return fmt.Errorf("io_connections[%d]: o_to_t_rpi_ms must be > 0", index)
	}
	if conn.TToORPIMs <= 0 {
		return fmt.Errorf("io_connections[%d]: t_to_o_rpi_ms must be > 0", index)
	}

	// Validate sizes
	if conn.OToTSizeBytes <= 0 {
		return fmt.Errorf("io_connections[%d]: o_to_t_size_bytes must be > 0", index)
	}
	if conn.TToOSizeBytes <= 0 {
		return fmt.Errorf("io_connections[%d]: t_to_o_size_bytes must be > 0", index)
	}

	// Validate transport class trigger
	if conn.TransportClassTrigger < 1 || conn.TransportClassTrigger > 3 {
		return fmt.Errorf("io_connections[%d]: transport_class_trigger must be 1, 2, or 3, got %d", index, conn.TransportClassTrigger)
	}

	// Class and Instance must be set
	if conn.Class == 0 && conn.Instance == 0 {
		return fmt.Errorf("io_connections[%d]: class and instance must be set", index)
	}

	return nil
}

// LoadServerConfig loads a server configuration from a YAML file
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config file not found: %s\n\n"+
				"To fix this:\n"+
				"  1. Copy the example config: cp configs/cipdip_server.yaml.example cipdip_server.yaml\n"+
				"  2. Edit cipdip_server.yaml with your server settings\n"+
				"  3. Or specify a custom config file with --server-config <path>\n\n"+
				"See docs/CONFIGURATION.md for detailed configuration instructions", path)
		}
		return nil, fmt.Errorf("read config file %s: %w", path, err)
	}

	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	// Apply defaults
	if cfg.Server.ListenIP == "" {
		cfg.Server.ListenIP = "0.0.0.0"
	}
	if cfg.Server.TCPPort == 0 {
		cfg.Server.TCPPort = 44818
	}
	if cfg.Server.UDPIOPort == 0 {
		cfg.Server.UDPIOPort = 2222
	}
	if cfg.Server.Personality == "" {
		cfg.Server.Personality = "adapter"
	}
	if cfg.Server.ConnectionTimeoutMs == 0 {
		cfg.Server.ConnectionTimeoutMs = 10000
	}
	if cfg.Protocol.Mode == "" {
		cfg.Protocol.Mode = "strict_odva"
	}
	if cfg.Server.IdentityProductName == "" {
		if cfg.Server.Name != "" {
			cfg.Server.IdentityProductName = cfg.Server.Name
		} else {
			cfg.Server.IdentityProductName = "CIPDIP"
		}
	}
	applyServerENIPDefaults(&cfg)
	applyServerCIPDefaults(&cfg)
	applyServerLoggingDefaults(&cfg)
	applyServerMetricsDefaults(&cfg)

	// Validate
	if err := ValidateServerConfig(&cfg); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

// ValidateServerConfig validates a server configuration
func ValidateServerConfig(cfg *ServerConfig) error {
	if err := validateProtocolConfig(cfg.Protocol); err != nil {
		return err
	}
	if err := validateCIPProfiles(cfg.CIPProfiles); err != nil {
		return err
	}
	if cfg.ENIP.Session.MaxSessions < 0 {
		return fmt.Errorf("enip.session.max_sessions must be >= 0")
	}
	if cfg.ENIP.Session.MaxSessionsPerIP < 0 {
		return fmt.Errorf("enip.session.max_sessions_per_ip must be >= 0")
	}
	if cfg.ENIP.Session.IdleTimeoutMs < 0 {
		return fmt.Errorf("enip.session.idle_timeout_ms must be >= 0")
	}
	if cfg.Faults.Latency.BaseDelayMs < 0 || cfg.Faults.Latency.JitterMs < 0 || cfg.Faults.Latency.SpikeDelayMs < 0 {
		return fmt.Errorf("faults.latency values must be >= 0")
	}
	if cfg.Faults.Reliability.DropResponseEveryN < 0 || cfg.Faults.Reliability.CloseConnectionEveryN < 0 || cfg.Faults.Reliability.StallResponseEveryN < 0 {
		return fmt.Errorf("faults.reliability values must be >= 0")
	}
	if cfg.Faults.Reliability.DropResponsePct < 0 || cfg.Faults.Reliability.DropResponsePct > 1 {
		return fmt.Errorf("faults.reliability.drop_response_pct must be between 0 and 1")
	}
	if cfg.Faults.TCP.ChunkMin < 0 || cfg.Faults.TCP.ChunkMax < 0 || cfg.Faults.TCP.InterChunkDelayMs < 0 {
		return fmt.Errorf("faults.tcp values must be >= 0")
	}
	if cfg.Logging.Level != "" {
		switch strings.ToLower(cfg.Logging.Level) {
		case "error", "info", "verbose", "debug":
		default:
			return fmt.Errorf("logging.level must be error, info, verbose, or debug")
		}
	}
	if cfg.Logging.Format != "" {
		switch strings.ToLower(cfg.Logging.Format) {
		case "text", "json":
		default:
			return fmt.Errorf("logging.format must be text or json")
		}
	}
	if cfg.Logging.LogEveryN < 0 {
		return fmt.Errorf("logging.log_every_n must be >= 0")
	}
	if cfg.Metrics.Port < 0 {
		return fmt.Errorf("metrics.port must be >= 0")
	}
	if cfg.CIP.DefaultUnsupportedStatus == 0 {
		// allow defaulting during load, but if explicitly set to 0 it's not useful
	}

	// Validate personality
	if cfg.Server.Personality != "adapter" && cfg.Server.Personality != "logix_like" {
		return fmt.Errorf("server.personality must be 'adapter' or 'logix_like', got '%s'", cfg.Server.Personality)
	}

	// Validate based on personality
	if cfg.Server.Personality == "adapter" {
		if len(cfg.AdapterAssemblies) == 0 {
			return fmt.Errorf("adapter_assemblies must have at least one entry when personality is 'adapter'")
		}

		// Validate adapter assemblies
		for i, assembly := range cfg.AdapterAssemblies {
			if err := validateAdapterAssembly(assembly, i); err != nil {
				return err
			}
		}
	} else if cfg.Server.Personality == "logix_like" {
		if len(cfg.LogixTags) == 0 {
			return fmt.Errorf("logix_tags must have at least one entry when personality is 'logix_like'")
		}

		// Validate logix tags
		for i, tag := range cfg.LogixTags {
			if err := validateLogixTag(tag, i); err != nil {
				return err
			}
		}
	}

	return nil
}

func applyServerENIPDefaults(cfg *ServerConfig) {
	cfg.ENIP.Support.ListIdentity = boolPtrDefault(cfg.ENIP.Support.ListIdentity, true)
	cfg.ENIP.Support.ListServices = boolPtrDefault(cfg.ENIP.Support.ListServices, true)
	cfg.ENIP.Support.ListInterfaces = boolPtrDefault(cfg.ENIP.Support.ListInterfaces, true)
	cfg.ENIP.Support.RegisterSession = boolPtrDefault(cfg.ENIP.Support.RegisterSession, true)
	cfg.ENIP.Support.SendRRData = boolPtrDefault(cfg.ENIP.Support.SendRRData, true)
	cfg.ENIP.Support.SendUnitData = boolPtrDefault(cfg.ENIP.Support.SendUnitData, true)

	cfg.ENIP.Session.RequireRegisterSession = boolPtrDefault(cfg.ENIP.Session.RequireRegisterSession, true)
	if cfg.ENIP.Session.MaxSessions == 0 {
		cfg.ENIP.Session.MaxSessions = 256
	}
	if cfg.ENIP.Session.MaxSessionsPerIP == 0 {
		cfg.ENIP.Session.MaxSessionsPerIP = 64
	}
	if cfg.ENIP.Session.IdleTimeoutMs == 0 {
		cfg.ENIP.Session.IdleTimeoutMs = 60000
	}

	cfg.ENIP.CPF.Strict = boolPtrDefault(cfg.ENIP.CPF.Strict, true)
	cfg.ENIP.CPF.AllowItemReorder = boolPtrDefault(cfg.ENIP.CPF.AllowItemReorder, true)
	cfg.ENIP.CPF.AllowExtraItems = boolPtrDefault(cfg.ENIP.CPF.AllowExtraItems, false)
	cfg.ENIP.CPF.AllowMissingItems = boolPtrDefault(cfg.ENIP.CPF.AllowMissingItems, false)
}

func boolPtrDefault(value *bool, def bool) *bool {
	if value != nil {
		return value
	}
	v := def
	return &v
}

func applyServerCIPDefaults(cfg *ServerConfig) {
	cfg.CIP.StrictPaths = boolPtrDefault(cfg.CIP.StrictPaths, true)
	if cfg.CIP.DefaultUnsupportedStatus == 0 {
		cfg.CIP.DefaultUnsupportedStatus = 0x08
	}
}

func applyServerLoggingDefaults(cfg *ServerConfig) {
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "text"
	}
	if cfg.Logging.LogEveryN == 0 {
		cfg.Logging.LogEveryN = 1
	}
}

func applyServerMetricsDefaults(cfg *ServerConfig) {
	if cfg.Metrics.ListenIP == "" {
		cfg.Metrics.ListenIP = "127.0.0.1"
	}
	if cfg.Metrics.Port == 0 {
		cfg.Metrics.Port = 9109
	}
}

func validateEdgeTarget(target EdgeTarget, index int) error {
	if target.Name == "" {
		return fmt.Errorf("edge_targets[%d]: name is required", index)
	}
	if target.Service == "" {
		return fmt.Errorf("edge_targets[%d]: service is required", index)
	}
	validServices := []ServiceType{
		ServiceGetAttributeSingle,
		ServiceSetAttributeSingle,
		ServiceCustom,
	}
	valid := false
	for _, vs := range validServices {
		if target.Service == vs {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("edge_targets[%d]: invalid service type '%s'", index, target.Service)
	}
	if target.Service == ServiceCustom && target.ServiceCode == 0 {
		return fmt.Errorf("edge_targets[%d]: service_code is required when service is 'custom'", index)
	}
	if target.ExpectedOutcome != "" {
		switch target.ExpectedOutcome {
		case "success", "error", "timeout", "any":
		default:
			return fmt.Errorf("edge_targets[%d]: expected_outcome must be 'success', 'error', 'timeout', or 'any'", index)
		}
	}
	return nil
}

func validateProtocolConfig(cfg ProtocolConfig) error {
	switch cfg.Mode {
	case "strict_odva", "vendor_variant", "legacy_compat":
	default:
		return fmt.Errorf("protocol.mode must be 'strict_odva', 'vendor_variant', or 'legacy_compat', got '%s'", cfg.Mode)
	}

	if cfg.Mode != "vendor_variant" && cfg.Variant != "" {
		return fmt.Errorf("protocol.variant requires mode 'vendor_variant'")
	}
	if cfg.Mode == "strict_odva" && cfg.Overrides.UseCPF != nil && !*cfg.Overrides.UseCPF {
		return fmt.Errorf("protocol.overrides.use_cpf must be true in strict_odva mode")
	}

	if cfg.Overrides.ENIPEndianness != "" && cfg.Overrides.ENIPEndianness != "little" && cfg.Overrides.ENIPEndianness != "big" {
		return fmt.Errorf("protocol.overrides.enip_endianness must be 'little' or 'big'")
	}
	if cfg.Overrides.CIPEndianness != "" && cfg.Overrides.CIPEndianness != "little" && cfg.Overrides.CIPEndianness != "big" {
		return fmt.Errorf("protocol.overrides.cip_endianness must be 'little' or 'big'")
	}
	if cfg.Overrides.IOSequenceMode != "" && cfg.Overrides.IOSequenceMode != "increment" && cfg.Overrides.IOSequenceMode != "random" && cfg.Overrides.IOSequenceMode != "omit" {
		return fmt.Errorf("protocol.overrides.io_sequence_mode must be 'increment', 'random', or 'omit'")
	}

	return nil
}

func validateCIPProfiles(profiles []string) error {
	for _, profile := range profiles {
		switch strings.ToLower(profile) {
		case "", "all", "energy", "safety", "motion":
		default:
			return fmt.Errorf("cip_profiles contains unsupported profile '%s'", profile)
		}
	}
	return nil
}

// validateAdapterAssembly validates an adapter assembly configuration
func validateAdapterAssembly(assembly AdapterAssemblyConfig, index int) error {
	if assembly.Name == "" {
		return fmt.Errorf("adapter_assemblies[%d]: name is required", index)
	}

	if assembly.SizeBytes <= 0 {
		return fmt.Errorf("adapter_assemblies[%d]: size_bytes must be > 0", index)
	}

	// Validate update pattern
	validPatterns := []string{"counter", "static", "random", "reflect_inputs"}
	valid := false
	for _, vp := range validPatterns {
		if assembly.UpdatePattern == vp {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("adapter_assemblies[%d]: update_pattern must be one of %v, got '%s'", index, validPatterns, assembly.UpdatePattern)
	}

	return nil
}

// validateLogixTag validates a Logix tag configuration
func validateLogixTag(tag LogixTagConfig, index int) error {
	if tag.Name == "" {
		return fmt.Errorf("logix_tags[%d]: name is required", index)
	}

	if tag.Type == "" {
		return fmt.Errorf("logix_tags[%d]: type is required", index)
	}

	// Validate tag type
	validTypes := []string{"BOOL", "SINT", "INT", "DINT", "REAL"}
	valid := false
	tagTypeUpper := strings.ToUpper(tag.Type)
	for _, vt := range validTypes {
		if tagTypeUpper == vt {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("logix_tags[%d]: type must be one of %v, got '%s'", index, validTypes, tag.Type)
	}

	if tag.ArrayLength < 1 {
		return fmt.Errorf("logix_tags[%d]: array_length must be >= 1", index)
	}

	// Validate update pattern
	validPatterns := []string{"counter", "static", "random", "sine", "sawtooth"}
	valid = false
	for _, vp := range validPatterns {
		if tag.UpdatePattern == vp {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("logix_tags[%d]: update_pattern must be one of %v, got '%s'", index, validPatterns, tag.UpdatePattern)
	}

	return nil
}
