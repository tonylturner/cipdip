package server

import (
	"fmt"
	"strings"

	"github.com/tonylturner/cipdip/internal/config"
)

// ServerTargetPreset defines default server behavior for a known vendor profile.
type ServerTargetPreset struct {
	Name         string
	Description  string
	Personality  string
	Identity     config.ServerConfigSection
	Assemblies   []config.AdapterAssemblyConfig
	Tags         []config.LogixTagConfig
	TagNamespace string
}

// AvailableServerTargets returns the supported server target presets.
func AvailableServerTargets() []ServerTargetPreset {
	return []ServerTargetPreset{
		{
			Name:        "rockwell_v32",
			Description: "Rockwell Logix-like controller (tag server)",
			Personality: "logix_like",
			Identity: config.ServerConfigSection{
				IdentityVendorID:    0x0001,
				IdentityProductName: "CIPDIP Rockwell v32",
			},
			Tags:         defaultLogixTags(),
			TagNamespace: "Program:MainProgram",
		},
		{
			Name:        "rockwell_enbt",
			Description: "Rockwell 1756-ENBT/A adapter identity (assembly server)",
			Personality: "adapter",
			Identity: config.ServerConfigSection{
				IdentityVendorID:    0x0001,
				IdentityProductName: "1756-ENBT/A",
			},
			Assemblies: defaultAdapterAssemblies(),
		},
		{
			Name:        "schneider_m580",
			Description: "Schneider Modicon M580-style adapter (generic assemblies)",
			Personality: "adapter",
			Identity: config.ServerConfigSection{
				IdentityProductName: "CIPDIP Schneider M580",
			},
			Assemblies: defaultAdapterAssemblies(),
		},
		{
			Name:        "siemens_s7_1200",
			Description: "Siemens S7-1200 MultiFieldbus adapter (generic assemblies)",
			Personality: "adapter",
			Identity: config.ServerConfigSection{
				IdentityProductName: "CIPDIP Siemens S7-1200",
			},
			Assemblies: defaultAdapterAssemblies(),
		},
		{
			Name:        "omron",
			Description: "Omron EtherNet/IP adapter (generic assemblies)",
			Personality: "adapter",
			Identity: config.ServerConfigSection{
				IdentityProductName: "CIPDIP Omron",
			},
			Assemblies: defaultAdapterAssemblies(),
		},
		{
			Name:        "keyence",
			Description: "Keyence EtherNet/IP adapter (generic assemblies)",
			Personality: "adapter",
			Identity: config.ServerConfigSection{
				IdentityProductName: "CIPDIP Keyence",
			},
			Assemblies: defaultAdapterAssemblies(),
		},
	}
}

// ApplyServerTarget applies a named target preset to a server config.
func ApplyServerTarget(cfg *config.ServerConfig, name string) error {
	if cfg == nil {
		return fmt.Errorf("server config is nil")
	}
	target, ok := findServerTarget(name)
	if !ok {
		return fmt.Errorf("unknown server target %q", name)
	}
	cfg.Server.Personality = target.Personality
	if target.Identity.IdentityVendorID != 0 {
		cfg.Server.IdentityVendorID = target.Identity.IdentityVendorID
	}
	if target.Identity.IdentityDeviceType != 0 {
		cfg.Server.IdentityDeviceType = target.Identity.IdentityDeviceType
	}
	if target.Identity.IdentityProductCode != 0 {
		cfg.Server.IdentityProductCode = target.Identity.IdentityProductCode
	}
	if target.Identity.IdentityRevMajor != 0 {
		cfg.Server.IdentityRevMajor = target.Identity.IdentityRevMajor
	}
	if target.Identity.IdentityRevMinor != 0 {
		cfg.Server.IdentityRevMinor = target.Identity.IdentityRevMinor
	}
	if target.Identity.IdentityStatus != 0 {
		cfg.Server.IdentityStatus = target.Identity.IdentityStatus
	}
	if target.Identity.IdentitySerial != 0 {
		cfg.Server.IdentitySerial = target.Identity.IdentitySerial
	}
	if target.Identity.IdentityProductName != "" {
		cfg.Server.IdentityProductName = target.Identity.IdentityProductName
	}

	switch target.Personality {
	case "adapter":
		cfg.AdapterAssemblies = append([]config.AdapterAssemblyConfig(nil), target.Assemblies...)
		cfg.LogixTags = nil
	case "logix_like":
		cfg.LogixTags = append([]config.LogixTagConfig(nil), target.Tags...)
		cfg.AdapterAssemblies = nil
	}
	if target.TagNamespace != "" {
		cfg.TagNamespace = target.TagNamespace
	}
	return nil
}

func findServerTarget(name string) (ServerTargetPreset, bool) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	for _, target := range AvailableServerTargets() {
		if target.Name == normalized {
			return target, true
		}
	}
	return ServerTargetPreset{}, false
}

func defaultAdapterAssemblies() []config.AdapterAssemblyConfig {
	return []config.AdapterAssemblyConfig{
		{
			Name:          "InputAssembly1",
			Class:         0x04,
			Instance:      0x65,
			Attribute:     0x03,
			SizeBytes:     16,
			UpdatePattern: "counter",
			Writable:      false,
		},
		{
			Name:          "OutputAssembly1",
			Class:         0x04,
			Instance:      0x67,
			Attribute:     0x03,
			SizeBytes:     16,
			UpdatePattern: "reflect_inputs",
			Writable:      true,
		},
	}
}

func defaultLogixTags() []config.LogixTagConfig {
	return []config.LogixTagConfig{
		{
			Name:          "scada",
			Type:          "DINT",
			ArrayLength:   1000,
			UpdatePattern: "counter",
		},
		{
			Name:          "realval",
			Type:          "REAL",
			ArrayLength:   1,
			UpdatePattern: "sine",
		},
	}
}
