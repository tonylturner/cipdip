package client

import (
	"strings"

	"github.com/tturner/cipdip/internal/cip/spec"
)

// CIPProfileClassSet captures CIP application profile class coverage.
type CIPProfileClassSet struct {
	Name    string
	Classes []uint16
}

var (
	standardCoverageClasses = []uint16{
		spec.CIPClassIdentityObject,
		spec.CIPClassMessageRouter,
		spec.CIPClassAssembly,
		spec.CIPClassConnection,
		spec.CIPClassConnectionManager,
		spec.CIPClassFileObject,
		spec.CIPClassEventLog,
		spec.CIPClassTimeSync,
		spec.CIPClassModbus,
		spec.CIPClassSymbolObject,
		spec.CIPClassTemplateObject,
		spec.CIPClassProgramName,
		spec.CIPClassTCPIPInterface,
		spec.CIPClassEthernetLink,
		spec.CIPClassPort,
	}

	cipApplicationProfiles = map[string]CIPProfileClassSet{
		"energy": {
			Name: "energy",
			Classes: []uint16{
				spec.CIPClassEnergyBase,
				spec.CIPClassEnergyElectrical,
				spec.CIPClassEnergyNonElectrical,
				spec.CIPClassEnergyPowerManagement,
			},
		},
		"safety": {
			Name: "safety",
			Classes: []uint16{
				spec.CIPClassSafetySupervisor,
				spec.CIPClassSafetyValidator,
				spec.CIPClassSafetyDiscreteOutputPoint,
				spec.CIPClassSafetyDiscreteOutputGroup,
				spec.CIPClassSafetyDiscreteInputPoint,
				spec.CIPClassSafetyDiscreteInputGroup,
				spec.CIPClassSafetyDualChannelOutput,
			},
		},
		"motion": {
			Name:    "motion",
			Classes: []uint16{spec.CIPClassMotionAxis},
		},
	}
)

// ResolveCIPProfileClasses returns a merged, de-duplicated list of classes for the requested profiles.
func ResolveCIPProfileClasses(profiles []string, overrides map[string][]uint16) []uint16 {
	seen := make(map[uint16]struct{})
	add := func(classes []uint16) {
		for _, classID := range classes {
			seen[classID] = struct{}{}
		}
	}

	add(standardCoverageClasses)

	for _, raw := range profiles {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if name == "all" {
			for key, spec := range cipApplicationProfiles {
				if override, ok := overrides[key]; ok {
					add(override)
					continue
				}
				add(spec.Classes)
			}
			continue
		}
		if override, ok := overrides[name]; ok {
			add(override)
			continue
		}
		if spec, ok := cipApplicationProfiles[name]; ok {
			add(spec.Classes)
		}
	}

	out := make([]uint16, 0, len(seen))
	for classID := range seen {
		out = append(out, classID)
	}
	return out
}

// NormalizeCIPProfiles expands "all" into the known profile list.
func NormalizeCIPProfiles(profiles []string) []string {
	var out []string
	seen := make(map[string]struct{})
	add := func(name string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	for _, raw := range profiles {
		name := strings.ToLower(strings.TrimSpace(raw))
		switch name {
		case "":
			continue
		case "all":
			add("energy")
			add("safety")
			add("motion")
		default:
			add(name)
		}
	}
	return out
}

