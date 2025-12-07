package config

// Configuration loading and validation for CIPDIP

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
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

// CIPTarget represents a CIP target (read, write, or custom)
type CIPTarget struct {
	Name            string      `yaml:"name"`
	Service         ServiceType `yaml:"service"`
	ServiceCode     uint8       `yaml:"service_code,omitempty"` // used for custom services
	Class           uint16      `yaml:"class"`
	Instance        uint16      `yaml:"instance"`
	Attribute       uint8       `yaml:"attribute"`
	Pattern         string      `yaml:"pattern,omitempty"`         // "increment", "toggle", "constant"
	InitialValue    int64       `yaml:"initial_value,omitempty"`
	RequestPayloadHex string    `yaml:"request_payload_hex,omitempty"` // raw hex string for request body
}

// IOConnectionConfig represents configuration for a connected I/O connection
type IOConnectionConfig struct {
	Name                 string `yaml:"name"`
	Transport            string `yaml:"transport"`             // "udp" (default) or "tcp"
	OToTRPIMs            int    `yaml:"o_to_t_rpi_ms"`
	TToORPIMs            int    `yaml:"t_to_o_rpi_ms"`
	OToTSizeBytes        int    `yaml:"o_to_t_size_bytes"`
	TToOSizeBytes        int    `yaml:"t_to_o_size_bytes"`
	Priority             string `yaml:"priority"`
	TransportClassTrigger int   `yaml:"transport_class_trigger"`
	Class                uint16 `yaml:"class"`
	Instance             uint16 `yaml:"instance"`
	ConnectionPathHex    string `yaml:"connection_path_hex,omitempty"`
}

// Config represents the client configuration
type Config struct {
	Adapter       AdapterConfig       `yaml:"adapter"`
	ReadTargets   []CIPTarget         `yaml:"read_targets"`
	WriteTargets  []CIPTarget         `yaml:"write_targets"`
	CustomTargets []CIPTarget         `yaml:"custom_targets"`
	IOConnections []IOConnectionConfig `yaml:"io_connections"`
}

// ServerConfigSection represents the server section in server config
type ServerConfigSection struct {
	Name        string `yaml:"name"`
	Personality string `yaml:"personality"` // "adapter" or "logix_like"
	ListenIP    string `yaml:"listen_ip"`
	TCPPort     int    `yaml:"tcp_port"`
	UDPIOPort   int    `yaml:"udp_io_port"`
	EnableUDPIO bool   `yaml:"enable_udp_io"`
}

// AdapterAssemblyConfig represents an adapter assembly configuration
type AdapterAssemblyConfig struct {
	Name          string `yaml:"name"`
	Class         uint16 `yaml:"class"`
	Instance      uint16 `yaml:"instance"`
	Attribute     uint8  `yaml:"attribute"`
	SizeBytes     int    `yaml:"size_bytes"`
	Writable      bool   `yaml:"writable"`
	UpdatePattern string `yaml:"update_pattern"` // "counter", "static", "random", "reflect_inputs"
}

// LogixTagConfig represents a Logix tag configuration
type LogixTagConfig struct {
	Name          string `yaml:"name"`
	Type          string `yaml:"type"`          // "BOOL", "SINT", "INT", "DINT", "REAL", etc.
	ArrayLength   int    `yaml:"array_length"`
	UpdatePattern string `yaml:"update_pattern"` // "counter", "static", "random", "sine", "sawtooth"
}

// ServerConfig represents the server configuration
type ServerConfig struct {
	Server          ServerConfigSection    `yaml:"server"`
	AdapterAssemblies []AdapterAssemblyConfig `yaml:"adapter_assemblies"`
	LogixTags         []LogixTagConfig        `yaml:"logix_tags"`
	TagNamespace      string                  `yaml:"tag_namespace"`
}

// LoadClientConfig loads a client configuration from a YAML file
func LoadClientConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	// Apply defaults
	if cfg.Adapter.Port == 0 {
		cfg.Adapter.Port = 44818
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
	// Check that at least one target type is populated
	if len(cfg.ReadTargets) == 0 && len(cfg.WriteTargets) == 0 && len(cfg.CustomTargets) == 0 {
		return fmt.Errorf("at least one of read_targets, write_targets, or custom_targets must be populated")
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

	// Validate IO connections
	for i, conn := range cfg.IOConnections {
		if err := validateIOConnection(conn, i); err != nil {
			return err
		}
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
	if conn.Transport != "" && conn.Transport != "udp" && conn.Transport != "tcp" {
		return fmt.Errorf("io_connections[%d]: transport must be 'udp' or 'tcp', got '%s'", index, conn.Transport)
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
		return nil, fmt.Errorf("read config file: %w", err)
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

	// Validate
	if err := ValidateServerConfig(&cfg); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

// ValidateServerConfig validates a server configuration
func ValidateServerConfig(cfg *ServerConfig) error {
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
