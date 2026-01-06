package validation

import (
	"encoding/json"
	"fmt"
	"github.com/tturner/cipdip/internal/cip/spec"
	"os"
	"path/filepath"
	"strings"

	"github.com/tturner/cipdip/internal/cip/protocol"
)

const (
	ServiceShapeNone            = "none"
	ServiceShapePayload         = "payload"
	ServiceShapeRead            = "read"
	ServiceShapeWrite           = "write"
	ServiceShapeFragmented      = "fragmented"
	ServiceShapeForwardOpen     = "forward_open"
	ServiceShapeForwardClose    = "forward_close"
	ServiceShapeUnconnectedSend = "unconnected_send"
	ServiceShapeRockwellTag     = "rockwell_tag"
	ServiceShapeRockwellTagFrag = "rockwell_tag_fragmented"
	ServiceShapeTemplate        = "rockwell_template"
	ServiceShapePCCC            = "rockwell_pccc"
	ServiceShapeFileObject      = "file_object"
	ServiceShapeModbus          = "modbus_object"
	ServiceShapeSafetyReset     = "safety_reset"
)

const (
	GradePass            = "A_pass"
	GradeFail            = "A_fail"
	GradeExpectedInvalid = "expected_invalid"
)

const (
	FailureENIPLengthMismatch         = "INV_ENIP_LENGTH_MISMATCH"
	FailureENIPParse                  = "INV_ENIP_PARSE"
	FailureCPFItemCountImplausible    = "INV_CPF_ITEMCOUNT_IMPLAUSIBLE"
	FailureCPFItemLengthMismatch      = "INV_CPF_ITEM_LENGTH_MISMATCH"
	FailureCPFParse                   = "INV_CPF_PARSE"
	FailureCIPParse                   = "INV_CIP_PARSE"
	FailureCIPPathSizeMismatch        = "INV_CIP_PATHSIZE_MISMATCH"
	FailureCIPPathMissing             = "INV_CIP_PATH_MISSING"
	FailureCIPServiceDataShape        = "INV_CIP_SERVICE_DATA_SHAPE_MISMATCH"
	FailureCIPStatusMissing           = "INV_CIP_STATUS_MISSING"
	FailureCIPResponseServiceMismatch = "INV_CIP_RESPONSE_SERVICE_MISMATCH"
	FailureTsharkMalformed            = "TSHARK_MALFORMED"
)

// PacketExpectation describes validation expectations for a packet.
type PacketExpectation struct {
	ID            string   `json:"id"`
	Outcome       string   `json:"outcome"` // valid or invalid
	Direction     string   `json:"direction"`
	PacketType    string   `json:"packet_type"`
	ServiceShape  string   `json:"service_shape"`
	TrafficMode   string   `json:"traffic_mode"`
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
	PacketIndex     int               `json:"packet_index"`
	Expected        PacketExpectation `json:"expected"`
	Pass            bool              `json:"pass"`
	Scenarios       []ScenarioResult  `json:"scenarios"`
	Experts         []ExpertInfo      `json:"tshark_experts,omitempty"`
	Pairing         *PairingResult    `json:"pairing,omitempty"`
	ExpertSummary   ExpertSummary     `json:"expert_summary"`
	PassCategory    string            `json:"pass_category"`
	Grade           string            `json:"grade,omitempty"`
	FailureLabels   []string          `json:"failure_labels,omitempty"`
	ExtractedFields ExtractedFields   `json:"extracted_fields,omitempty"`
}

// ExtractedFields captures authoritative parsed fields for Grade A checks.
type ExtractedFields struct {
	ENIP   ENIPFields   `json:"enip"`
	CPF    CPFFields    `json:"cpf"`
	CIP    CIPFields    `json:"cip"`
	Tshark TsharkFields `json:"tshark"`
}

type ENIPFields struct {
	Command string `json:"command,omitempty"`
	Length  string `json:"length,omitempty"`
	Session string `json:"session,omitempty"`
	Status  string `json:"status,omitempty"`
}

type CPFFields struct {
	ItemCount int       `json:"item_count"`
	Items     []CPFItem `json:"items,omitempty"`
}

type CIPFields struct {
	Service        string `json:"service,omitempty"`
	Class          string `json:"class,omitempty"`
	Instance       string `json:"instance,omitempty"`
	Attribute      string `json:"attribute,omitempty"`
	Symbol         string `json:"symbol,omitempty"`
	PathSizeWords  int    `json:"path_size_words,omitempty"`
	ServiceDataLen int    `json:"service_data_len,omitempty"`
}

type TsharkFields struct {
	Malformed     bool         `json:"malformed"`
	Experts       []ExpertInfo `json:"experts,omitempty"`
	PathClass     string       `json:"path_class,omitempty"`
	PathInstance  string       `json:"path_instance,omitempty"`
	PathAttribute string       `json:"path_attribute,omitempty"`
	PathSymbol    string       `json:"path_symbol,omitempty"`
}

// PairingResult captures request/response pairing checks.
type PairingResult struct {
	BaseID        string `json:"base_id"`
	RequestIndex  int    `json:"request_index"`
	ResponseIndex int    `json:"response_index"`
	Required      bool   `json:"required"`
	Pass          bool   `json:"pass"`
	Reason        string `json:"reason,omitempty"`
	OrderOK       bool   `json:"order_ok,omitempty"`
	SessionMatch  bool   `json:"session_match,omitempty"`
	TupleMatch    bool   `json:"tuple_match,omitempty"`
	ServiceMatch  bool   `json:"service_match,omitempty"`
	StatusPresent bool   `json:"status_present,omitempty"`
}

// ExpertSummary captures expert classification counts.
type ExpertSummary struct {
	ExpectedCount   int `json:"expected_expert_count"`
	UnexpectedCount int `json:"unexpected_expert_count"`
	TransportCount  int `json:"transport_expert_count"`
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
func EvaluatePacket(expect PacketExpectation, result ValidateResult, negativePolicy, expertPolicy, conversationMode, profile string, pairing *PairingResult) PacketEvaluation {
	eval := PacketEvaluation{
		Expected:        expect,
		Scenarios:       make([]ScenarioResult, 0, 8),
		Experts:         append([]ExpertInfo(nil), result.Experts...),
		Pairing:         pairing,
		ExtractedFields: buildExtractedFields(result),
	}
	if strings.TrimSpace(eval.Expected.TrafficMode) == "" {
		eval.Expected.TrafficMode = "client_only"
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
		pass, details := evaluateCPF(expect, result)
		eval.Scenarios = append(eval.Scenarios, ScenarioResult{Name: "cpf", Pass: pass, Details: details})
	}
	if expect.ExpectCIP {
		pass := fieldPresent(result.Fields, "cip.service")
		eval.Scenarios = append(eval.Scenarios, ScenarioResult{Name: "cip", Pass: pass})
	}
	if expect.ExpectCIPPath {
		pass, details := evaluateCIPPath(expect, result)
		eval.Scenarios = append(eval.Scenarios, ScenarioResult{Name: "cip_path", Pass: pass, Details: details})
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
	expertScenario, expertTriggered, summary := evaluateExperts(expect, result, expertPolicy, conversationMode, pairing)
	eval.ExpertSummary = summary
	eval.Scenarios = append(eval.Scenarios, expertScenario)
	pairScenario, pairTriggered := evaluatePairing(expect, pairing)
	if pairScenario.Name != "" {
		eval.Scenarios = append(eval.Scenarios, pairScenario)
	}
	if expect.Direction == "request" && expect.ServiceShape != "" && expect.ServiceShape != ServiceShapeNone {
		eval.Scenarios = append(eval.Scenarios, evaluateServiceShape(expect, result))
	}

	expectInvalid := strings.EqualFold(expect.Outcome, "invalid")
	if expectInvalid {
		observedFailure := false
		for _, scenario := range eval.Scenarios {
			if scenario.Name == "malformed" && scenario.Pass {
				observedFailure = true
			}
		}
		if expertTriggered || pairTriggered {
			observedFailure = true
		}
		eval.Pass = observedFailure
		if eval.Pass {
			eval.PassCategory = "expected_invalid_passed"
		} else {
			eval.PassCategory = "fail"
		}
		eval.Grade = GradeExpectedInvalid
		eval.FailureLabels = nil
		return eval
	}

	eval.Pass = true
	for _, scenario := range eval.Scenarios {
		if !scenario.Pass {
			eval.Pass = false
			break
		}
	}
	eval.PassCategory = categorizePass(eval)
	eval.Grade, eval.FailureLabels = evaluateGradeA(expect, result, profile, pairing)
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
	if expect.Direction == "response" {
		resp, err := decodeResponseForExpectation(result.Internal.CIPData)
		if err != nil {
			return ScenarioResult{Name: "service_data", Pass: false, Details: err.Error()}
		}
		payloadLen := len(resp.Payload)
		baseService := protocol.CIPServiceCode(uint8(resp.Service) & 0x7F)
		switch expect.ServiceShape {
		case ServiceShapeNone, ServiceShapeForwardClose:
			return ScenarioResult{Name: "service_data", Pass: payloadLen == 0, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
		case ServiceShapeForwardOpen:
			return ScenarioResult{Name: "service_data", Pass: payloadLen >= 17, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
		case ServiceShapeRockwellTag, ServiceShapeRead:
			if baseService == spec.CIPServiceWriteTag || baseService == spec.CIPServiceWriteTagFragmented {
				return ScenarioResult{Name: "service_data", Pass: payloadLen == 0, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
			}
			return ScenarioResult{Name: "service_data", Pass: payloadLen >= 2, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
		case ServiceShapeModbus:
			switch baseService {
			case 0x4F, 0x50:
				return ScenarioResult{Name: "service_data", Pass: payloadLen >= 4, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
			default:
				return ScenarioResult{Name: "service_data", Pass: payloadLen >= 2, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
			}
		case ServiceShapeFileObject:
			return ScenarioResult{Name: "service_data", Pass: payloadLen >= 6, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
		default:
			return ScenarioResult{Name: "service_data", Pass: payloadLen > 0, Details: fmt.Sprintf("payload_len=%d", payloadLen)}
		}
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

func decodeRequestForExpectation(cipData []byte) (protocol.CIPRequest, error) {
	req, err := protocol.DecodeCIPRequest(cipData)
	if err != nil {
		return protocol.CIPRequest{}, err
	}
	return req, nil
}

func decodeResponseForExpectation(cipData []byte) (protocol.CIPResponse, error) {
	resp, err := protocol.DecodeCIPResponse(cipData, protocol.CIPPath{})
	if err != nil {
		return protocol.CIPResponse{}, err
	}
	return resp, nil
}

// DecodeRequestForReport exposes CIP request decoding for report helpers.
func DecodeRequestForReport(cipData []byte) (protocol.CIPRequest, error) {
	return decodeRequestForExpectation(cipData)
}

// DecodeResponseForReport exposes CIP response decoding for report helpers.
func DecodeResponseForReport(cipData []byte) (protocol.CIPResponse, error) {
	return decodeResponseForExpectation(cipData)
}

func parseUnconnectedSendPayload(payload []byte) ([]byte, []byte, bool) {
	embedded, route, ok := protocol.ParseUnconnectedSendRequestPayload(payload)
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

func evaluateExperts(expect PacketExpectation, result ValidateResult, expertPolicy, conversationMode string, pairing *PairingResult) (ScenarioResult, bool, ExpertSummary) {
	if strings.EqualFold(expertPolicy, "off") {
		return ScenarioResult{Name: "experts", Pass: true, Details: "policy=off"}, false, ExpertSummary{}
	}
	if len(result.Experts) == 0 {
		return ScenarioResult{Name: "experts", Pass: true, Details: "experts=0"}, false, ExpertSummary{}
	}

	expectResponse := pairing != nil && pairing.Required
	failures := []string{}
	triggered := false
	summary := ExpertSummary{}

	for _, expert := range result.Experts {
		msgLower := strings.ToLower(expert.Message)
		isTCP := expert.Layer == "tcp"
		isCIP := expert.Layer == "cip" || expert.Layer == "enip"
		isTransport := isTCP

		if strings.Contains(msgLower, "cip request without a response") {
			if strings.EqualFold(expect.TrafficMode, "client_only") {
				summary.ExpectedCount++
				continue
			}
			if expectResponse && (pairing == nil || !pairing.Pass) {
				failures = append(failures, "cip_request_without_response")
				triggered = true
				summary.UnexpectedCount++
			}
			continue
		}

		if expert.SeverityRank < 2 {
			if isTransport {
				summary.TransportCount++
			}
			continue
		}

		switch strings.ToLower(expertPolicy) {
		case "strict":
			if isTCP && strings.EqualFold(conversationMode, "off") {
				continue
			}
			failures = append(failures, fmt.Sprintf("%s:%s", expert.Layer, expert.Severity))
			triggered = true
			summary.UnexpectedCount++
		default:
			if isCIP {
				failures = append(failures, fmt.Sprintf("%s:%s", expert.Layer, expert.Severity))
				triggered = true
				summary.UnexpectedCount++
			} else if isTCP && strings.EqualFold(conversationMode, "strict") {
				failures = append(failures, fmt.Sprintf("%s:%s", expert.Layer, expert.Severity))
				triggered = true
				summary.UnexpectedCount++
			} else if isTransport {
				summary.TransportCount++
			}
		}
	}

	if triggered {
		return ScenarioResult{Name: "experts", Pass: false, Details: "policy=" + expertPolicy + " failures=" + strings.Join(failures, ",")}, true, summary
	}
	return ScenarioResult{Name: "experts", Pass: true, Details: "policy=" + expertPolicy}, false, summary
}

func evaluatePairing(expect PacketExpectation, pairing *PairingResult) (ScenarioResult, bool) {
	if strings.EqualFold(expect.TrafficMode, "client_only") {
		return ScenarioResult{}, false
	}
	if pairing == nil || !pairing.Required {
		return ScenarioResult{}, false
	}
	if pairing.Pass {
		return ScenarioResult{Name: "pairing", Pass: true}, false
	}
	return ScenarioResult{Name: "pairing", Pass: false, Details: pairing.Reason}, true
}

func evaluateCPF(expect PacketExpectation, result ValidateResult) (bool, string) {
	if result.CPFItemCount == 0 {
		return false, "missing item_count"
	}
	if result.CPFItemCount < 1 || result.CPFItemCount > 8 {
		return false, fmt.Sprintf("implausible item_count=%d", result.CPFItemCount)
	}
	if len(result.CPFItems) != result.CPFItemCount {
		return false, fmt.Sprintf("item_count=%d items=%d", result.CPFItemCount, len(result.CPFItems))
	}
	for _, item := range result.CPFItems {
		if item.TypeID == "" {
			return false, "missing item type"
		}
		if item.Length < 0 {
			return false, "negative item length"
		}
	}
	return true, fmt.Sprintf("item_count=%d", result.CPFItemCount)
}

func evaluateCIPPath(expect PacketExpectation, result ValidateResult) (bool, string) {
	tsharkPath := strings.TrimSpace(result.Fields["cip.path.class"]) != "" ||
		strings.TrimSpace(result.Fields["cip.path.instance"]) != "" ||
		strings.TrimSpace(result.Fields["cip.path.attribute"]) != "" ||
		strings.TrimSpace(result.Fields["cip.path.symbol"]) != ""
	internalPath := internalCIPPathPresent(result)
	if tsharkPath || internalPath {
		return true, fmt.Sprintf("tshark=%t internal=%t", tsharkPath, internalPath)
	}
	return false, "missing path"
}

func categorizePass(eval PacketEvaluation) string {
	if !eval.Pass {
		return "fail"
	}
	if eval.ExpertSummary.UnexpectedCount == 0 && eval.ExpertSummary.ExpectedCount == 0 && eval.ExpertSummary.TransportCount == 0 {
		return "pass_clean"
	}
	if eval.ExpertSummary.UnexpectedCount == 0 && eval.ExpertSummary.ExpectedCount > 0 {
		return "pass_with_expected_experts"
	}
	if eval.ExpertSummary.UnexpectedCount == 0 && eval.ExpertSummary.TransportCount > 0 {
		return "pass_with_transport_warnings"
	}
	return "pass_with_warnings"
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

func buildExtractedFields(result ValidateResult) ExtractedFields {
	fields := ExtractedFields{
		ENIP: ENIPFields{
			Command: result.Fields["enip.command"],
			Length:  result.Fields["enip.length"],
			Session: result.Fields["enip.session"],
			Status:  result.Fields["enip.status"],
		},
		CPF: CPFFields{
			ItemCount: result.CPFItemCount,
			Items:     append([]CPFItem(nil), result.CPFItems...),
		},
		CIP: CIPFields{
			Service:   result.Fields["cip.service"],
			Class:     result.Fields["cip.path.class"],
			Instance:  result.Fields["cip.path.instance"],
			Attribute: result.Fields["cip.path.attribute"],
			Symbol:    result.Fields["cip.path.symbol"],
		},
		Tshark: TsharkFields{
			Malformed:     result.Malformed,
			Experts:       append([]ExpertInfo(nil), result.Experts...),
			PathClass:     result.Fields["cip.path.class"],
			PathInstance:  result.Fields["cip.path.instance"],
			PathAttribute: result.Fields["cip.path.attribute"],
			PathSymbol:    result.Fields["cip.path.symbol"],
		},
	}
	if result.Internal != nil {
		if result.Internal.ENIPCommand != 0 {
			fields.ENIP.Command = fmt.Sprintf("0x%04X", result.Internal.ENIPCommand)
		}
		if result.Internal.ENIPLength > 0 {
			fields.ENIP.Length = fmt.Sprintf("%d", result.Internal.ENIPLength)
		}
		if result.Internal.ENIPSession != 0 {
			fields.ENIP.Session = fmt.Sprintf("0x%08X", result.Internal.ENIPSession)
		}
		if result.Internal.CPFItemCount > 0 {
			fields.CPF.ItemCount = result.Internal.CPFItemCount
			fields.CPF.Items = append([]CPFItem(nil), result.Internal.CPFItems...)
		}
		if result.Internal.CIPService != 0 {
			fields.CIP.Service = fmt.Sprintf("0x%02X", result.Internal.CIPService)
		}
		if len(result.Internal.CIPData) > 0 {
			req, err := decodeRequestForExpectation(result.Internal.CIPData)
			if err == nil && !result.Internal.CIPIsResponse {
				fields.CIP.Class = fmt.Sprintf("0x%04X", req.Path.Class)
				fields.CIP.Instance = fmt.Sprintf("0x%04X", req.Path.Instance)
				fields.CIP.Attribute = fmt.Sprintf("0x%04X", req.Path.Attribute)
				fields.CIP.Symbol = req.Path.Name
				fields.CIP.PathSizeWords = result.Internal.CIPPathSizeWords
				fields.CIP.ServiceDataLen = result.Internal.CIPServiceDataLen
			}
			if result.Internal.CIPIsResponse {
				fields.CIP.ServiceDataLen = result.Internal.CIPServiceDataLen
			}
		}
	}
	return fields
}

func evaluateGradeA(expect PacketExpectation, result ValidateResult, profile string, pairing *PairingResult) (string, []string) {
	if strings.EqualFold(expect.Outcome, "invalid") {
		return GradeExpectedInvalid, nil
	}
	profile = strings.ToLower(strings.TrimSpace(profile))
	if profile == "" {
		profile = "client_wire"
	}
	if profile == "client_wire" && expect.Direction != "request" {
		return GradePass, nil
	}
	if profile == "server_wire" && expect.Direction != "response" {
		return GradePass, nil
	}

	labels := []string{}
	if result.Internal == nil {
		labels = append(labels, FailureENIPParse)
		return GradeFail, labels
	}
	if result.Internal.ENIPParseError != "" {
		labels = append(labels, FailureENIPParse)
	}
	if result.Internal.ENIPLengthMismatch {
		labels = append(labels, FailureENIPLengthMismatch)
	}
	if result.Internal.CPFParseError != "" {
		labels = append(labels, FailureCPFParse)
	}
	if result.Internal.CPFItemCount < 1 || result.Internal.CPFItemCount > 8 {
		labels = append(labels, FailureCPFItemCountImplausible)
	}
	if result.Internal.CPFItemCount > 0 && len(result.Internal.CPFItems) != result.Internal.CPFItemCount {
		labels = append(labels, FailureCPFItemLengthMismatch)
	}
	if result.Internal.CIPParseError != "" {
		labels = append(labels, FailureCIPParse)
	}
	if expect.ExpectCIPPath {
		hasPath := fieldPresent(result.Fields, "cip.path.class") ||
			fieldPresent(result.Fields, "cip.path.instance") ||
			fieldPresent(result.Fields, "cip.path.attribute") ||
			fieldPresent(result.Fields, "cip.path.symbol") ||
			internalCIPPathPresent(result)
		if !hasPath {
			labels = append(labels, FailureCIPPathMissing)
		}
	}
	if result.Internal.CIPPathSizeWords > 0 && result.Internal.CIPPathBytes > 0 {
		if result.Internal.CIPPathSizeWords*2 != result.Internal.CIPPathBytes {
			labels = append(labels, FailureCIPPathSizeMismatch)
		}
	}
	if expect.Direction == "response" {
		if !result.Internal.CIPIsResponse {
			labels = append(labels, FailureCIPResponseServiceMismatch)
		}
		if profile == "server_wire" && !result.Internal.CIPStatusPresent {
			labels = append(labels, FailureCIPStatusMissing)
		}
	}
	if result.Malformed {
		labels = append(labels, FailureTsharkMalformed)
	}
	if expect.Direction == "request" && expect.ServiceShape != "" && expect.ServiceShape != ServiceShapeNone {
		shape := evaluateServiceShape(expect, result)
		if !shape.Pass {
			labels = append(labels, FailureCIPServiceDataShape)
		}
	}

	if len(labels) > 0 {
		return GradeFail, labels
	}
	return GradePass, nil
}
