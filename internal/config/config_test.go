package config

import (
	"os"
	"testing"
)

func TestValidateClientConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config with read targets",
			config: &Config{
				Adapter: AdapterConfig{
					Name: "Test Adapter",
					Port: 44818,
				},
				ReadTargets: []CIPTarget{
					{
						Name:      "TestTarget",
						Service:   ServiceGetAttributeSingle,
						Class:     0x04,
						Instance:  0x65,
						Attribute: 0x03,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty config",
			config: &Config{
				Adapter: AdapterConfig{},
			},
			wantErr: true,
		},
		{
			name: "custom service without service code",
			config: &Config{
				Adapter: AdapterConfig{
					Name: "Test",
				},
				CustomTargets: []CIPTarget{
					{
						Name:      "Custom",
						Service:   ServiceCustom,
						Class:     0x01,
						Instance:  0x01,
						Attribute: 0x00,
						// Missing ServiceCode
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid IO connection transport",
			config: &Config{
				Adapter: AdapterConfig{
					Name: "Test",
				},
				ReadTargets: []CIPTarget{
					{
						Name:      "Test",
						Service:   ServiceGetAttributeSingle,
						Class:     0x04,
						Instance:  0x65,
						Attribute: 0x03,
					},
				},
				IOConnections: []IOConnectionConfig{
					{
						Name:                  "IO1",
						Transport:             "invalid",
						OToTRPIMs:             20,
						TToORPIMs:             20,
						OToTSizeBytes:         8,
						TToOSizeBytes:         8,
						TransportClassTrigger: 3,
						Class:                 0x04,
						Instance:              0x65,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "strict_odva with cpf disabled",
			config: &Config{
				Adapter: AdapterConfig{
					Name: "Test",
				},
				Protocol: ProtocolConfig{
					Mode: "strict_odva",
					Overrides: ProtocolOverrides{
						UseCPF: boolPtr(false),
					},
				},
				ReadTargets: []CIPTarget{
					{
						Name:      "TestTarget",
						Service:   ServiceGetAttributeSingle,
						Class:     0x04,
						Instance:  0x65,
						Attribute: 0x03,
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClientConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateClientConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func TestLoadClientConfig(t *testing.T) {
	// Create a temporary config file
	tmpfile, err := os.CreateTemp("", "test_config_*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	configContent := `
adapter:
  name: "Test Adapter"
  port: 44818

read_targets:
  - name: "TestTarget"
    service: "get_attribute_single"
    class: 0x04
    instance: 0x65
    attribute: 0x03
`
	if _, err := tmpfile.WriteString(configContent); err != nil {
		t.Fatalf("write config: %v", err)
	}
	tmpfile.Close()

	// Load config
	cfg, err := LoadClientConfig(tmpfile.Name(), false)
	if err != nil {
		t.Fatalf("LoadClientConfig failed: %v", err)
	}

	if cfg.Adapter.Name != "Test Adapter" {
		t.Errorf("adapter name: got %q, want %q", cfg.Adapter.Name, "Test Adapter")
	}

	if cfg.Adapter.Port != 44818 {
		t.Errorf("adapter port: got %d, want 44818", cfg.Adapter.Port)
	}

	if len(cfg.ReadTargets) != 1 {
		t.Errorf("read targets: got %d, want 1", len(cfg.ReadTargets))
	}
}

func TestLoadClientConfigDefaults(t *testing.T) {
	// Create a temporary config file without port
	tmpfile, err := os.CreateTemp("", "test_config_*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	configContent := `
adapter:
  name: "Test Adapter"

read_targets:
  - name: "TestTarget"
    service: "get_attribute_single"
    class: 0x04
    instance: 0x65
    attribute: 0x03
`
	if _, err := tmpfile.WriteString(configContent); err != nil {
		t.Fatalf("write config: %v", err)
	}
	tmpfile.Close()

	// Load config
	cfg, err := LoadClientConfig(tmpfile.Name(), false)
	if err != nil {
		t.Fatalf("LoadClientConfig failed: %v", err)
	}

	// Port should default to 44818
	if cfg.Adapter.Port != 44818 {
		t.Errorf("adapter port: got %d, want 44818 (default)", cfg.Adapter.Port)
	}
}

func TestValidateClientConfigProtocolVariantsDefault(t *testing.T) {
	cfg := &Config{
		Adapter: AdapterConfig{
			Name: "Test",
		},
		ReadTargets: []CIPTarget{
			{
				Name:      "Target",
				Service:   ServiceGetAttributeSingle,
				Class:     0x04,
				Instance:  0x01,
				Attribute: 0x01,
			},
		},
		ProtocolVariants: []ProtocolConfig{
			{
				Variant: "rockwell_enbt",
			},
		},
	}

	if err := ValidateClientConfig(cfg); err != nil {
		t.Fatalf("ValidateClientConfig failed: %v", err)
	}
	if got := cfg.ProtocolVariants[0].Mode; got != "vendor_variant" {
		t.Fatalf("protocol_variants[0].mode: got %q, want %q", got, "vendor_variant")
	}
}

func TestValidateClientConfigCIPProfiles(t *testing.T) {
	cfg := &Config{
		Adapter: AdapterConfig{
			Name: "Test",
		},
		ReadTargets: []CIPTarget{
			{
				Name:      "Target",
				Service:   ServiceGetAttributeSingle,
				Class:     0x04,
				Instance:  0x01,
				Attribute: 0x01,
			},
		},
		CIPProfiles: []string{"energy", "safety"},
	}

	if err := ValidateClientConfig(cfg); err != nil {
		t.Fatalf("ValidateClientConfig failed: %v", err)
	}

	cfg.CIPProfiles = []string{"bad_profile"}
	if err := ValidateClientConfig(cfg); err == nil {
		t.Fatalf("ValidateClientConfig expected error for invalid cip_profiles")
	}
}

func TestValidateServerConfig(t *testing.T) {
	base := &ServerConfig{
		Server: ServerConfigSection{
			Name:        "Test",
			Personality: "adapter",
			TCPPort:     44818,
		},
		AdapterAssemblies: []AdapterAssemblyConfig{
			{
				Name:          "Input",
				Class:         0x04,
				Instance:      0x65,
				Attribute:     0x03,
				SizeBytes:     4,
				UpdatePattern: "counter",
			},
		},
	}

	if err := ValidateServerConfig(base); err != nil {
		t.Fatalf("ValidateServerConfig failed: %v", err)
	}

	adapterMissing := *base
	adapterMissing.AdapterAssemblies = nil
	if err := ValidateServerConfig(&adapterMissing); err == nil {
		t.Fatalf("ValidateServerConfig expected error for missing adapter_assemblies")
	}

	logix := *base
	logix.Server.Personality = "logix_like"
	logix.AdapterAssemblies = nil
	logix.LogixTags = []LogixTagConfig{
		{
			Name:          "TestTag",
			Type:          "DINT",
			ArrayLength:   1,
			UpdatePattern: "counter",
		},
	}
	if err := ValidateServerConfig(&logix); err != nil {
		t.Fatalf("ValidateServerConfig logix_like failed: %v", err)
	}

	logix.CIPProfiles = []string{"bad_profile"}
	if err := ValidateServerConfig(&logix); err == nil {
		t.Fatalf("ValidateServerConfig expected error for invalid cip_profiles")
	}
}
