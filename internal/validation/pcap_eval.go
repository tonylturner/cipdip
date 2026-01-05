package validation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PacketExpectation describes validation expectations for a packet.
type PacketExpectation struct {
	ID            string   `json:"id"`
	Outcome       string   `json:"outcome"` // valid or invalid
	Direction     string   `json:"direction"`
	PacketType    string   `json:"packet_type"`
	ServiceShape  string   `json:"service_shape"`
	ExpectLayers  []string `json:"expect_layers,omitempty"`
	ExpectENIP    bool     `json:"expect_enip,omitempty"`
	ExpectCPF     bool     `json:"expect_cpf,omitempty"`
	ExpectCIP     bool     `json:"expect_cip,omitempty"`
	ExpectCIPPath bool     `json:"expect_cip_path,omitempty"`
	ExpectStatus  bool     `json:"expect_status,omitempty"`
	ExpectSymbol  bool     `json:"expect_symbol,omitempty"`
}

// ValidationManifest provides expected metadata for packets in a PCAP.
type ValidationManifest struct {
	PCAP    string              `json:"pcap"`
	Packets []PacketExpectation `json:"packets"`
}

// ScenarioResult captures a per-scenario validation outcome.
type ScenarioResult struct {
	Name    string `json:"name"`
	Pass    bool   `json:"pass"`
	Details string `json:"details,omitempty"`
}

// PacketEvaluation captures validation results for a packet.
type PacketEvaluation struct {
	PacketIndex int              `json:"packet_index"`
	Expected    PacketExpectation `json:"expected"`
	Pass        bool             `json:"pass"`
	Scenarios   []ScenarioResult `json:"scenarios"`
}

// ValidationManifestPath returns the sidecar manifest path for a PCAP.
func ValidationManifestPath(pcapPath string) string {
	ext := filepath.Ext(pcapPath)
	base := strings.TrimSuffix(pcapPath, ext)
	return base + ".validation.json"
}

// WriteValidationManifest writes the manifest to disk.
func WriteValidationManifest(path string, manifest ValidationManifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}

// LoadValidationManifest reads the manifest from disk.
func LoadValidationManifest(path string) (*ValidationManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var manifest ValidationManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &manifest, nil
}

// EvaluatePacket runs validation scenarios against tshark results.
func EvaluatePacket(expect PacketExpectation, result ValidateResult, negativePolicy string) PacketEvaluation {
	eval := PacketEvaluation{
		Expected:  expect,
		Scenarios: make([]ScenarioResult, 0, 8),
	}

	layersOk := true
	if len(expect.ExpectLayers) > 0 {
		missing := missingLayers(expect.ExpectLayers, result.Layers)
		if len(missing) > 0 {
			layersOk = false
			eval.Scenarios = append(eval.Scenarios, ScenarioResult{
				Name:    "layers",
				Pass:    false,
				Details: "missing: " + strings.Join(missing, ","),
			})
		} else {
			eval.Scenarios = append(eval.Scenarios, ScenarioResult{Name: "layers", Pass: true})
		}
	}

	if expect.ExpectENIP {
		pass := fieldPresent(result.Fields, "enip.command")
		eval.Scenarios = append(eval.Scenarios, ScenarioResult{Name: "enip", Pass: pass})
	}
	if expect.ExpectCPF {
		pass := fieldPresent(result.Fields, "cpf.item_count")
		eval.Scenarios = append(eval.Scenarios, ScenarioResult{Name: "cpf", Pass: pass})
	}
	if expect.ExpectCIP {
		pass := fieldPresent(result.Fields, "cip.service")
		eval.Scenarios = append(eval.Scenarios, ScenarioResult{Name: "cip", Pass: pass})
	}
	if expect.ExpectCIPPath {
		pass := fieldPresent(result.Fields, "cip.path.class") || fieldPresent(result.Fields, "cip.class")
		eval.Scenarios = append(eval.Scenarios, ScenarioResult{Name: "cip_path", Pass: pass})
	}
	if expect.ExpectStatus {
		pass := fieldPresent(result.Fields, "cip.general_status")
		eval.Scenarios = append(eval.Scenarios, ScenarioResult{Name: "cip_status", Pass: pass})
	}

	eval.Scenarios = append(eval.Scenarios, evaluateMalformed(expect, result, negativePolicy, layersOk))

	eval.Pass = true
	for _, scenario := range eval.Scenarios {
		if !scenario.Pass {
			eval.Pass = false
			break
		}
	}
	return eval
}

func evaluateMalformed(expect PacketExpectation, result ValidateResult, policy string, layersOk bool) ScenarioResult {
	expectInvalid := strings.EqualFold(expect.Outcome, "invalid")
	if !expectInvalid {
		return ScenarioResult{Name: "malformed", Pass: !result.Malformed}
	}

	switch strings.ToLower(policy) {
	case "internal":
		return ScenarioResult{Name: "malformed", Pass: result.Malformed}
	case "either":
		return ScenarioResult{Name: "malformed", Pass: result.Malformed || !layersOk}
	default:
		return ScenarioResult{Name: "malformed", Pass: result.Malformed}
	}
}

func missingLayers(expected, actual []string) []string {
	missing := make([]string, 0)
	actualSet := make(map[string]struct{}, len(actual))
	for _, layer := range actual {
		actualSet[strings.ToLower(layer)] = struct{}{}
	}
	for _, layer := range expected {
		if _, ok := actualSet[strings.ToLower(layer)]; !ok {
			missing = append(missing, layer)
		}
	}
	return missing
}

func fieldPresent(fields map[string]string, key string) bool {
	val, ok := fields[key]
	return ok && strings.TrimSpace(val) != ""
}
