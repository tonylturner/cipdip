package cipclient

import "strings"

// CIPProfileClassSet captures CIP application profile class coverage.
type CIPProfileClassSet struct {
	Name    string
	Classes []uint16
}

var (
	standardCoverageClasses = []uint16{
		CIPClassIdentityObject,
		CIPClassMessageRouter,
		CIPClassAssembly,
		CIPClassConnection,
		CIPClassConnectionManager,
		CIPClassFileObject,
		CIPClassEventLog,
		CIPClassTimeSync,
		CIPClassModbus,
		CIPClassSymbolObject,
		CIPClassTemplateObject,
		CIPClassProgramName,
		CIPClassTCPIPInterface,
		CIPClassEthernetLink,
		CIPClassPort,
	}

	cipApplicationProfiles = map[string]CIPProfileClassSet{
		"energy": {
			Name: "energy",
			Classes: []uint16{
				CIPClassEnergyBase,
				CIPClassEnergyElectrical,
				CIPClassEnergyNonElectrical,
				CIPClassEnergyPowerManagement,
			},
		},
		"safety": {
			Name: "safety",
			Classes: []uint16{
				CIPClassSafetySupervisor,
				CIPClassSafetyValidator,
				CIPClassSafetyDiscreteOutputPoint,
				CIPClassSafetyDiscreteOutputGroup,
				CIPClassSafetyDiscreteInputPoint,
				CIPClassSafetyDiscreteInputGroup,
				CIPClassSafetyDualChannelOutput,
			},
		},
		"motion": {
			Name:    "motion",
			Classes: []uint16{CIPClassMotionAxis},
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
