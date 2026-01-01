package cipclient

import (
	"encoding/binary"
	"sync"
)

// ProtocolProfile defines protocol encoding and framing behavior.
type ProtocolProfile struct {
	Name                   string
	ENIPByteOrder          binary.ByteOrder
	CIPByteOrder           binary.ByteOrder
	IncludeCIPPathSize     bool
	IncludeCIPRespReserved bool
	UseCPF                 bool
	IOSequenceMode         string // "increment", "random", "omit"
}

// Default profiles.
var (
	StrictODVAProfile = ProtocolProfile{
		Name:                   "strict_odva",
		ENIPByteOrder:          binary.LittleEndian,
		CIPByteOrder:           binary.LittleEndian,
		IncludeCIPPathSize:     true,
		IncludeCIPRespReserved: true,
		UseCPF:                 true,
		IOSequenceMode:         "increment",
	}
	LegacyCompatProfile = ProtocolProfile{
		Name:                   "legacy_compat",
		ENIPByteOrder:          binary.BigEndian,
		CIPByteOrder:           binary.BigEndian,
		IncludeCIPPathSize:     false,
		IncludeCIPRespReserved: false,
		UseCPF:                 false,
		IOSequenceMode:         "omit",
	}
	VendorProfiles = map[string]ProtocolProfile{
		"rockwell_v32": {
			Name:                   "rockwell_v32",
			ENIPByteOrder:          binary.LittleEndian,
			CIPByteOrder:           binary.LittleEndian,
			IncludeCIPPathSize:     true,
			IncludeCIPRespReserved: true,
			UseCPF:                 true,
			IOSequenceMode:         "increment",
		},
		"schneider_m580": {
			Name:                   "schneider_m580",
			ENIPByteOrder:          binary.LittleEndian,
			CIPByteOrder:           binary.LittleEndian,
			IncludeCIPPathSize:     true,
			IncludeCIPRespReserved: false,
			UseCPF:                 true,
			IOSequenceMode:         "omit",
		},
		"siemens_s7_1200": {
			Name:                   "siemens_s7_1200",
			ENIPByteOrder:          binary.LittleEndian,
			CIPByteOrder:           binary.LittleEndian,
			IncludeCIPPathSize:     true,
			IncludeCIPRespReserved: true,
			UseCPF:                 true,
			IOSequenceMode:         "omit",
		},
	}
)

var (
	profileMu      sync.RWMutex
	currentProfile = StrictODVAProfile
)

// CurrentProtocolProfile returns the active protocol profile.
func CurrentProtocolProfile() ProtocolProfile {
	profileMu.RLock()
	defer profileMu.RUnlock()
	return currentProfile
}

// SetProtocolProfile sets the active protocol profile.
func SetProtocolProfile(profile ProtocolProfile) {
	profileMu.Lock()
	defer profileMu.Unlock()
	currentProfile = profile
}

// ResolveProtocolProfile resolves the profile based on mode, variant, and overrides.
func ResolveProtocolProfile(mode, variant, enipEndian, cipEndian string, cipPathSize, cipRespReserved, useCPF *bool, ioSequenceMode string) ProtocolProfile {
	profile := StrictODVAProfile

	switch mode {
	case "legacy_compat":
		profile = LegacyCompatProfile
	case "vendor_variant":
		profile = StrictODVAProfile
		if variant != "" {
			if vendorProfile, ok := VendorProfiles[variant]; ok {
				profile = vendorProfile
			} else {
				profile.Name = variant
			}
		}
	}

	// Apply overrides if provided.
	if enipEndian == "big" {
		profile.ENIPByteOrder = binary.BigEndian
	} else if enipEndian == "little" {
		profile.ENIPByteOrder = binary.LittleEndian
	}

	if cipEndian == "big" {
		profile.CIPByteOrder = binary.BigEndian
	} else if cipEndian == "little" {
		profile.CIPByteOrder = binary.LittleEndian
	}

	if cipPathSize != nil {
		profile.IncludeCIPPathSize = *cipPathSize
	}
	if cipRespReserved != nil {
		profile.IncludeCIPRespReserved = *cipRespReserved
	}
	if useCPF != nil {
		profile.UseCPF = *useCPF
	}
	if ioSequenceMode != "" {
		profile.IOSequenceMode = ioSequenceMode
	}

	return profile
}
