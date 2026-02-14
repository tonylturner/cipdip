package config

import (
	"strings"

	"github.com/tonylturner/cipdip/internal/cip/spec"
)

// ScenarioMeta holds per-scenario defaults for interval, duration, and personality.
type ScenarioMeta struct {
	IntervalMs     int
	MinDurationSec int
	Personality    string // server personality required; empty defaults to "adapter"
}

// ScenarioMetaMap returns default interval/duration/personality for known scenarios.
func ScenarioMetaMap() map[string]ScenarioMeta {
	return map[string]ScenarioMeta{
		"baseline":             {IntervalMs: 250},
		"stress":               {IntervalMs: 20},
		"churn":                {IntervalMs: 100},
		"io":                   {IntervalMs: 10},
		"vendor_variants":      {IntervalMs: 100},
		"dpi_explicit":         {IntervalMs: 100},
		"evasion_segment":      {IntervalMs: 200},
		"evasion_fuzz":         {IntervalMs: 500, MinDurationSec: 15},
		"evasion_anomaly":      {IntervalMs: 300},
		"evasion_timing":       {IntervalMs: 1000, MinDurationSec: 25},
		"edge_valid":           {IntervalMs: 200},
		"edge_vendor":          {IntervalMs: 200, Personality: "logix_like"},
		"pccc":                 {IntervalMs: 200},
		"modbus":               {IntervalMs: 200},
		"mixed":                {IntervalMs: 100},
		"mixed_state":          {IntervalMs: 50},
		"firewall_pack":        {IntervalMs: 100},
		"firewall_hirschmann":  {IntervalMs: 100},
		"firewall_moxa":        {IntervalMs: 100},
		"firewall_dynics":      {IntervalMs: 100},
		"rockwell":             {IntervalMs: 100},
		"unconnected_send":     {IntervalMs: 200},
		"modbus_pipeline":      {IntervalMs: 200},
	}
}

// DefaultReadTargets returns the standard read targets used by selftest.
func DefaultReadTargets() []CIPTarget {
	return []CIPTarget{
		{
			Name:      "Identity_VendorID",
			Service:   ServiceGetAttributeSingle,
			Class:     spec.CIPClassIdentityObject,
			Instance:  0x01,
			Attribute: 0x01,
			Tags:      []string{"tc-enip-001-explicit", "tc-dyn-001-learn", "hirschmann", "moxa", "dynics"},
		},
		{
			Name:      "Identity_ProductType",
			Service:   ServiceGetAttributeSingle,
			Class:     spec.CIPClassIdentityObject,
			Instance:  0x01,
			Attribute: 0x02,
			Tags:      []string{"tc-enip-001-explicit", "tc-dyn-001-learn", "hirschmann", "moxa", "dynics"},
		},
		{
			Name:      "Assembly_Input1",
			Service:   ServiceGetAttributeSingle,
			Class:     spec.CIPClassAssembly,
			Instance:  0x65,
			Attribute: 0x03,
			Tags:      []string{"tc-enip-001-explicit", "tc-dyn-001-learn", "hirschmann", "moxa", "dynics"},
		},
	}
}

// DefaultWriteTargets returns the standard write targets used by selftest.
func DefaultWriteTargets() []CIPTarget {
	return []CIPTarget{
		{
			Name:         "Assembly_Output1",
			Service:      ServiceSetAttributeSingle,
			Class:        spec.CIPClassAssembly,
			Instance:     0x67,
			Attribute:    0x03,
			Pattern:      "increment",
			InitialValue: 0,
			Tags:         []string{"tc-enip-001-explicit", "tc-dyn-001-learn", "hirschmann", "moxa", "dynics"},
		},
	}
}

// DefaultCustomTargets returns custom CIP targets for DPI and firewall scenarios.
func DefaultCustomTargets() []CIPTarget {
	return []CIPTarget{
		{
			Name:        "Identity_GetAll",
			Service:     ServiceCustom,
			ServiceCode: uint8(spec.CIPServiceGetAttributeAll),
			Class:       spec.CIPClassIdentityObject,
			Instance:    0x01,
			Attribute:   0x00,
			Tags:        []string{"tc-enip-001-explicit", "tc-hirsch-001-pccc", "tc-hirsch-002-wildcard", "tc-moxa-001-default-action", "tc-dyn-001-learn", "tc-dyn-001-novel", "hirschmann", "moxa", "dynics"},
		},
		{
			Name:        "MessageRouter_GetAll",
			Service:     ServiceCustom,
			ServiceCode: uint8(spec.CIPServiceGetAttributeAll),
			Class:       spec.CIPClassMessageRouter,
			Instance:    0x01,
			Attribute:   0x00,
			Tags:        []string{"tc-enip-002-violation", "tc-hirsch-001-pccc", "tc-hirsch-002-wildcard", "tc-moxa-001-default-action", "tc-dyn-001-learn", "tc-dyn-001-novel", "hirschmann", "moxa", "dynics"},
		},
	}
}

// DefaultEdgeTargets returns edge targets for edge_valid/edge_vendor/unconnected_send scenarios.
func DefaultEdgeTargets() []EdgeTarget {
	return []EdgeTarget{
		// Standard CIP edge targets (used by edge_valid)
		{
			Name:            "Edge_HighInstance",
			Service:         ServiceGetAttributeSingle,
			Class:           spec.CIPClassIdentityObject,
			Instance:        0x1000,
			Attribute:       0x01,
			ExpectedOutcome: "error",
			Tags:            []string{"tc-enip-002-violation", "tc-hirsch-001-pccc", "tc-hirsch-002-wildcard", "tc-moxa-001-default-action", "tc-dyn-001-learn", "tc-dyn-001-novel", "hirschmann", "moxa", "dynics"},
		},
		{
			Name:            "Edge_InvalidClass",
			Service:         ServiceGetAttributeSingle,
			Class:           0xFF,
			Instance:        0x01,
			Attribute:       0x01,
			ExpectedOutcome: "error",
			Tags:            []string{"tc-enip-004-allowlist", "tc-hirsch-002-wildcard", "tc-moxa-001-default-action", "tc-dyn-001-novel", "hirschmann", "moxa", "dynics"},
		},
		{
			Name:            "Edge_ReservedService",
			Service:         ServiceCustom,
			ServiceCode:     0x20,
			Class:           spec.CIPClassIdentityObject,
			Instance:        0x01,
			Attribute:       0x00,
			ExpectedOutcome: "error",
			Tags:            []string{"tc-enip-003-reset", "tc-hirsch-001-pccc", "tc-moxa-001-default-action", "tc-dyn-001-novel", "hirschmann", "moxa", "dynics"},
		},
		// Vendor-specific targets for edge_vendor scenario (matched by logix_like server).
		{
			Name:              "Vendor_ExecutePCCC",
			Service:           ServiceCustom,
			ServiceCode:       uint8(spec.CIPServiceExecutePCCC),
			Class:             spec.CIPClassPCCCObject,
			Instance:          0x01,
			Attribute:         0x00,
			RequestPayloadHex: "0607000100", // PCCC echo command
			ExpectedOutcome:   "any",
			Tags:              []string{"tc-enip-001-explicit", "hirschmann", "moxa", "dynics"},
		},
		// Tag-based targets — names match LogixTags on the logix_like server
		{
			Name:              "scada",
			Service:           ServiceCustom,
			ServiceCode:       uint8(spec.CIPServiceReadTag),
			Class:             spec.CIPClassSymbolObject,
			Instance:          0x01,
			Attribute:         0x00,
			RequestPayloadHex: "0100", // Read 1 element
			ExpectedOutcome:   "any",
			Tags:              []string{"tc-enip-001-explicit", "hirschmann", "moxa", "dynics"},
		},
		{
			Name:              "motor_speed",
			Service:           ServiceCustom,
			ServiceCode:       uint8(spec.CIPServiceWriteTag),
			Class:             spec.CIPClassSymbolObject,
			Instance:          0x01,
			Attribute:         0x00,
			RequestPayloadHex: "c3000100 0000", // Type=INT(0xC3), count=1, data=0x0000
			ExpectedOutcome:   "any",
			Tags:              []string{"tc-enip-001-explicit", "hirschmann", "moxa", "dynics"},
		},
		{
			Name:              "sensor_temp",
			Service:           ServiceCustom,
			ServiceCode:       uint8(spec.CIPServiceReadTagFragmented),
			Class:             spec.CIPClassSymbolObject,
			Instance:          0x01,
			Attribute:         0x00,
			RequestPayloadHex: "0100 00000000", // Read 1 element, offset 0
			ExpectedOutcome:   "any",
			Tags:              []string{"tc-enip-001-explicit", "hirschmann", "moxa", "dynics"},
		},
	}
}

// DefaultProtocolVariants returns protocol variants for the vendor_variants scenario.
func DefaultProtocolVariants() []ProtocolConfig {
	return []ProtocolConfig{
		{Mode: "strict_odva"},
		{Mode: "vendor_variant", Variant: "schneider_m580"},
		{Mode: "vendor_variant", Variant: "siemens_s7_1200"},
		{Mode: "vendor_variant", Variant: "rockwell_v32"},
	}
}

// DefaultIOConnection returns a default I/O connection config.
func DefaultIOConnection() IOConnectionConfig {
	return IOConnectionConfig{
		Name:                  "TestIO",
		Transport:             "tcp",
		OToTRPIMs:             100,
		TToORPIMs:             100,
		OToTSizeBytes:         8,
		TToOSizeBytes:         8,
		Priority:              "scheduled",
		TransportClassTrigger: 3,
		Class:                 spec.CIPClassAssembly,
		Instance:              0x65,
		Tags:                  []string{"tc-enip-001-implicit", "hirschmann", "moxa", "dynics"},
	}
}

// DefaultPCCCDataTables returns PCCC data table configs for the server.
func DefaultPCCCDataTables() []PCCCDataTableConfig {
	return []PCCCDataTableConfig{
		{FileType: "N", FileNumber: 7, Elements: 100},
		{FileType: "F", FileNumber: 8, Elements: 50},
		{FileType: "T", FileNumber: 4, Elements: 20},
	}
}

// DefaultModbusConfig returns Modbus server config.
func DefaultModbusConfig() ModbusServerConfig {
	return ModbusServerConfig{
		Enabled:              true,
		CoilCount:            100,
		DiscreteInputCount:   100,
		InputRegisterCount:   100,
		HoldingRegisterCount: 100,
	}
}

// DefaultLogixTags returns the standard logix tags used by selftest.
func DefaultLogixTags() []LogixTagConfig {
	return []LogixTagConfig{
		{Name: "scada", Type: "DINT", ArrayLength: 1, UpdatePattern: "counter"},
		{Name: "sensor_temp", Type: "REAL", ArrayLength: 10, UpdatePattern: "sine"},
		{Name: "motor_speed", Type: "INT", ArrayLength: 1, UpdatePattern: "static"},
		{Name: "plc_status", Type: "DINT", ArrayLength: 4, UpdatePattern: "random"},
	}
}

// DefaultAdapterAssemblies returns the standard adapter assemblies used by selftest.
func DefaultAdapterAssemblies() []AdapterAssemblyConfig {
	return []AdapterAssemblyConfig{
		{
			Name:          "InputAssembly",
			Class:         spec.CIPClassAssembly,
			Instance:      0x65,
			Attribute:     0x03,
			SizeBytes:     16,
			Writable:      false,
			UpdatePattern: "counter",
		},
		{
			Name:          "InputAssembly2",
			Class:         spec.CIPClassAssembly,
			Instance:      0x66,
			Attribute:     0x03,
			SizeBytes:     16,
			Writable:      false,
			UpdatePattern: "counter",
		},
		{
			Name:          "OutputAssembly",
			Class:         spec.CIPClassAssembly,
			Instance:      0x67,
			Attribute:     0x03,
			SizeBytes:     16,
			Writable:      true,
			UpdatePattern: "static",
		},
	}
}

// EnrichForScenario injects scenario-specific config sections into a client config
// if they are not already populated. This is additive only.
func EnrichForScenario(cfg *Config, scenario string) {
	switch scenario {
	case "edge_valid", "edge_vendor", "unconnected_send":
		if len(cfg.EdgeTargets) == 0 {
			cfg.EdgeTargets = DefaultEdgeTargets()
		}
	case "vendor_variants":
		if len(cfg.ProtocolVariants) == 0 {
			cfg.ProtocolVariants = DefaultProtocolVariants()
		}
	case "firewall_pack", "firewall_hirschmann", "firewall_moxa", "firewall_dynics":
		if len(cfg.CustomTargets) == 0 {
			cfg.CustomTargets = DefaultCustomTargets()
		}
	case "mixed_state":
		if len(cfg.IOConnections) == 0 {
			cfg.IOConnections = []IOConnectionConfig{DefaultIOConnection()}
		}
	case "rockwell":
		if len(cfg.EdgeTargets) == 0 {
			cfg.EdgeTargets = DefaultEdgeTargets()
		}
		if len(cfg.ProtocolVariants) == 0 {
			cfg.ProtocolVariants = DefaultProtocolVariants()
		}
	}

	// Scenarios that work with basic read targets need no extra enrichment:
	// baseline, mixed, stress, churn, dpi_explicit,
	// evasion_segment, evasion_fuzz, evasion_anomaly, evasion_timing,
	// pccc, modbus, modbus_pipeline, io

	// Ensure there are at least basic read targets for any scenario
	if len(cfg.ReadTargets) == 0 && len(cfg.CustomTargets) == 0 && len(cfg.EdgeTargets) == 0 {
		cfg.ReadTargets = DefaultReadTargets()
	}
}

// EnrichServerForScenario injects scenario-specific server config sections
// if they are not already populated. This is additive only.
func EnrichServerForScenario(cfg *ServerConfig, scenario string) {
	switch {
	case scenario == "edge_vendor" || scenario == "rockwell":
		if cfg.Server.Personality == "adapter" || cfg.Server.Personality == "" {
			cfg.Server.Personality = "logix_like"
		}
		if len(cfg.LogixTags) == 0 {
			cfg.LogixTags = DefaultLogixTags()
		}
	case scenario == "pccc":
		if len(cfg.PCCCDataTables) == 0 {
			cfg.PCCCDataTables = DefaultPCCCDataTables()
		}
	case scenario == "modbus" || scenario == "modbus_pipeline":
		if !cfg.ModbusConfig.Enabled {
			cfg.ModbusConfig = DefaultModbusConfig()
		}
	case strings.HasPrefix(scenario, "evasion_") || strings.HasPrefix(scenario, "firewall_"):
		// These work with whatever personality is already configured
	}
}
