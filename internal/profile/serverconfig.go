package profile

import (
	"github.com/tonylturner/cipdip/internal/config"
)

// ToServerConfig converts a profile to a ServerConfig.
// This configures the server to expose the profile's data model (tags or assemblies).
func (p *Profile) ToServerConfig() *config.ServerConfig {
	cfg := config.CreateDefaultServerConfig()

	// Set personality based on profile metadata
	cfg.Server.Personality = p.Metadata.Personality

	// Set UDP I/O based on profile metadata
	cfg.Server.EnableUDPIO = p.Metadata.EnableUDPIO

	if p.Metadata.Personality == "logix_like" {
		cfg.LogixTags = p.toLogixTags()
		cfg.AdapterAssemblies = nil
	} else {
		cfg.AdapterAssemblies = p.toAdapterAssemblies()
		cfg.LogixTags = nil
	}

	return cfg
}

// toLogixTags converts profile tags to LogixTagConfig slice.
func (p *Profile) toLogixTags() []config.LogixTagConfig {
	tags := make([]config.LogixTagConfig, 0, len(p.DataModel.Tags))
	for _, tag := range p.DataModel.Tags {
		tags = append(tags, config.LogixTagConfig{
			Name:          tag.Name,
			Type:          tag.Type,
			ArrayLength:   tag.ArrayLength,
			UpdatePattern: mapUpdateRule(tag.UpdateRule),
		})
	}
	return tags
}

// toAdapterAssemblies converts profile assemblies to AdapterAssemblyConfig slice.
func (p *Profile) toAdapterAssemblies() []config.AdapterAssemblyConfig {
	assemblies := make([]config.AdapterAssemblyConfig, 0, len(p.DataModel.Assemblies))
	for _, asm := range p.DataModel.Assemblies {
		assemblies = append(assemblies, config.AdapterAssemblyConfig{
			Name:          asm.Name,
			Class:         asm.Class,
			Instance:      asm.Instance,
			Attribute:     asm.Attribute,
			SizeBytes:     asm.SizeBytes,
			Writable:      asm.Writable,
			UpdatePattern: mapUpdateRule(asm.UpdateRule),
		})
	}
	return assemblies
}

// mapUpdateRule maps profile update rules to server update patterns.
func mapUpdateRule(rule string) string {
	switch rule {
	case "counter":
		return "counter"
	case "ramp":
		return "counter" // Similar behavior
	case "toggle":
		return "random" // Approximate with random
	case "sine":
		return "sine"
	case "static", "latch":
		return "static"
	default:
		return "static"
	}
}
