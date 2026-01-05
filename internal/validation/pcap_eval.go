package validation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tturner/cipdip/internal/cipclient"
)

const (
	ServiceShapeNone           = "none"
	ServiceShapePayload        = "payload"
	ServiceShapeRead           = "read"
	ServiceShapeWrite          = "write"
	ServiceShapeFragmented     = "fragmented"
	ServiceShapeForwardOpen    = "forward_open"
	ServiceShapeForwardClose   = "forward_close"
	ServiceShapeUnconnectedSend = "unconnected_send"
	ServiceShapeRockwellTag    = "rockwell_tag"
	ServiceShapeRockwellTagFrag = "rockwell_tag_fragmented"
	ServiceShapeTemplate       = "rockwell_template"
	ServiceShapePCCC           = "rockwell_pccc"
	ServiceShapeFileObject     = "file_object"
	ServiceShapeModbus         = "modbus_object"
	ServiceShapeSafetyReset    = "safety_reset"
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
		if !pass {
			pass = internalCIPPathPresent(result)
		}
		eval.Scenarios = append(eval.Scenarios, ScenarioResult{Name: "cip_path", Pass: pass})
	}
	if expect.ExpectSymbol {
		pass := fieldPresent(result.Fields, "cip.path.symbol")
		eval.Scenarios = append(eval.Scenarios, ScenarioResult{Name: "cip_symbol", Pass: pass})
	}
	if expect.ExpectStatus {
		pass := fieldPresent(result.Fields, "cip.general_status")
		if !pass {
			if status, ok := internalResponseStatus(result, expect); ok {
				pass = status
			}
		}
		eval.Scenarios = append(eval.Scenarios, ScenarioResult{Name: "cip_status", Pass: pass})
	}

	eval.Scenarios = append(eval.Scenarios, evaluateMalformed(expect, result, negativePolicy, layersOk))
	if expect.Direction == "request" && expect.ServiceShape != "" && expect.ServiceShape != ServiceShapeNone {
		eval.Scenarios = append(eval.Scenarios, evaluateServiceShape(expect, result))
	}

	eval.Pass = true
	for _, scenario := range eval.Scenarios {
		if !scenario.Pass {
			eval.Pass = false
			break
		}
	}
	return eval
}

func internalResponseStatus(result ValidateResult, expect PacketExpectation) (bool, bool) {
	if result.Internal == nil || len(result.Internal.CIPData) == 0 {
		return false, false
	}
	if expect.Direction != "response" {
		return false, false
	}
	resp, err := decodeResponseForExpectation(result.Internal.CIPData)
	if err != nil {
		return false, true
	}
	_ = resp
	return true, true
}

func evaluateServiceShape(expect PacketExpectation, result ValidateResult) ScenarioResult {
	if result.Internal == nil || len(result.Internal.CIPData) == 0 {
		return ScenarioResult{Name: "service_data", Pass: false, Details: "missing internal CIP data"}
	}
	if expect.Direction != "request" {
		return ScenarioResult{Name: "service_data", Pass: true}
	}
	req, err := decodeRequestForExpectation(result.Internal.CIPData)
	if err != nil {
		return ScenarioResult{Name: "service_data", Pass: false, Details: err.Error()}
	}

	payloadLen := len(req.Payload)
	switch expect.ServiceShape {
	case ServiceShapeNone:
		return ScenarioResult{Name: "service_data", Pass: payloadLen == 0, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
	case ServiceShapePayload:
		return ScenarioResult{Name: "service_data", Pass: payloadLen > 0, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
	case ServiceShapeRead:
		return ScenarioResult{Name: "service_data", Pass: payloadLen >= 2, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
	case ServiceShapeWrite:
		return ScenarioResult{Name: "service_data", Pass: payloadLen >= 1, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
	case ServiceShapeFragmented, ServiceShapeRockwellTagFrag:
		return ScenarioResult{Name: "service_data", Pass: payloadLen >= 6, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
	case ServiceShapeRockwellTag:
		return ScenarioResult{Name: "service_data", Pass: payloadLen >= 2, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
	case ServiceShapeTemplate:
		return ScenarioResult{Name: "service_data", Pass: payloadLen >= 6, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
	case ServiceShapeForwardOpen:
		return ScenarioResult{Name: "service_data", Pass: payloadLen >= 20, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
	case ServiceShapeForwardClose:
		return ScenarioResult{Name: "service_data", Pass: payloadLen >= 3, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
	case ServiceShapeUnconnectedSend:
		embedded, _, ok := parseUnconnectedSendPayload(req.Payload)
		return ScenarioResult{Name: "service_data", Pass: ok && len(embedded) > 0, Details: fmt.Sprintf("embedded_len=%d", len(embedded))}
	case ServiceShapeFileObject, ServiceShapeModbus, ServiceShapePCCC, ServiceShapeSafetyReset:
		return ScenarioResult{Name: "service_data", Pass: payloadLen > 0, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
	default:
		return ScenarioResult{Name: "service_data", Pass: payloadLen > 0, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
	}
}

func internalCIPPathPresent(result ValidateResult) bool {
	if result.Internal == nil || len(result.Internal.CIPData) == 0 {
		return false
	}
	req, err := decodeRequestForExpectation(result.Internal.CIPData)
	if err != nil {
		return false
	}
	if req.Path.Name != "" {
		return true
	}
	return req.Path.Class != 0 || req.Path.Instance != 0 || req.Path.Attribute != 0
}

func decodeRequestForExpectation(cipData []byte) (cipclient.CIPRequest, error) {
	req, err := cipclient.DecodeCIPRequest(cipData)
	if err != nil {
		return cipclient.CIPRequest{}, err
	}
	return req, nil
}

func decodeResponseForExpectation(cipData []byte) (cipclient.CIPResponse, error) {
	resp, err := cipclient.DecodeCIPResponse(cipData, cipclient.CIPPath{})
	if err != nil {
		return cipclient.CIPResponse{}, err
	}
	return resp, nil
}

// DecodeRequestForReport exposes CIP request decoding for report helpers.
func DecodeRequestForReport(cipData []byte) (cipclient.CIPRequest, error) {
	return decodeRequestForExpectation(cipData)
}

// DecodeResponseForReport exposes CIP response decoding for report helpers.
func DecodeResponseForReport(cipData []byte) (cipclient.CIPResponse, error) {
	return decodeResponseForExpectation(cipData)
}

func parseUnconnectedSendPayload(payload []byte) ([]byte, []byte, bool) {
	embedded, route, ok := cipclient.ParseUnconnectedSendRequestPayload(payload)
	return embedded, route, ok
}

func evaluateMalformed(expect PacketExpectation, result ValidateResult, policy string, layersOk bool) ScenarioResult {
	expectInvalid := strings.EqualFold(expect.Outcome, "invalid")
	if !expectInvalid {
		return ScenarioResult{Name: "malformed", Pass: !result.Malformed}
	}

	expertError := strings.EqualFold(result.SeverityMax, "error")

	switch strings.ToLower(policy) {
	case "internal":
		return ScenarioResult{Name: "malformed", Pass: result.Malformed || expertError}
	case "either":
		return ScenarioResult{Name: "malformed", Pass: result.Malformed || expertError || !layersOk}
	default:
		return ScenarioResult{Name: "malformed", Pass: result.Malformed || expertError}
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
