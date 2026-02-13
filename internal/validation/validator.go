package validation

import (
	"fmt"
	"strings"

	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
	"github.com/tonylturner/cipdip/internal/enip"
)

const (
	SeverityError = "error"
	SeverityWarn  = "warning"
)

// Finding captures a validation issue with severity.
type Finding struct {
	Code     string
	Message  string
	Severity string
}

// Validator validates ENIP/CIP packets using shared parsers and spec rules.
type Validator struct {
	Strict   bool
	Profile  string
	Registry *spec.Registry
}

// NewValidator constructs a new Validator with defaults.
func NewValidator(strict bool, profile string, registry *spec.Registry) *Validator {
	if registry == nil {
		registry = spec.DefaultRegistry()
	}
	return &Validator{
		Strict:   strict,
		Profile:  profile,
		Registry: registry,
	}
}

// ValidateENIP validates an ENIP encapsulation packet.
func (v *Validator) ValidateENIP(encap enip.ENIPEncapsulation) []Finding {
	findings := []Finding{}

	if !isValidENIPCommand(encap.Command) {
		findings = append(findings, Finding{
			Code:     "enip.invalid_command",
			Message:  fmt.Sprintf("invalid ENIP command 0x%04X", encap.Command),
			Severity: SeverityError,
		})
	}

	if encap.Length != uint16(len(encap.Data)) {
		findings = append(findings, Finding{
			Code:     "enip.length_mismatch",
			Message:  fmt.Sprintf("length field %d does not match data length %d", encap.Length, len(encap.Data)),
			Severity: SeverityError,
		})
	}

	if requiresSession(encap.Command) && encap.SessionID == 0 {
		findings = append(findings, Finding{
			Code:     "enip.session_missing",
			Message:  fmt.Sprintf("session ID must be non-zero for command 0x%04X", encap.Command),
			Severity: SeverityError,
		})
	}

	if v.Strict && isClientWireProfile(v.Profile) && encap.Status != 0 {
		findings = append(findings, Finding{
			Code:     "enip.status_nonzero",
			Message:  fmt.Sprintf("status must be 0 for client wire packets, got 0x%08X", encap.Status),
			Severity: SeverityError,
		})
	}

	if v.Strict && senderContextAllZero(encap.SenderContext) {
		findings = append(findings, Finding{
			Code:     "enip.sender_context_zero",
			Message:  "sender context should not be all zeros",
			Severity: SeverityWarn,
		})
	}

	if v.Strict && encap.Options != 0 {
		findings = append(findings, Finding{
			Code:     "enip.options_nonzero",
			Message:  fmt.Sprintf("options field should be 0, got 0x%08X", encap.Options),
			Severity: SeverityWarn,
		})
	}

	switch encap.Command {
	case enip.ENIPCommandRegisterSession:
		findings = append(findings, v.validateRegisterSession(encap)...)
	case enip.ENIPCommandSendRRData:
		findings = append(findings, v.validateSendRRData(encap)...)
	case enip.ENIPCommandSendUnitData:
		findings = append(findings, v.validateSendUnitData(encap)...)
	}

	return findings
}

// ValidateCIPRequest validates a CIP request using spec registry rules.
func (v *Validator) ValidateCIPRequest(req protocol.CIPRequest) []Finding {
	findings := []Finding{}

	if !spec.IsKnownService(req.Service) {
		findings = append(findings, Finding{
			Code:     "cip.service_unknown",
			Message:  fmt.Sprintf("unknown CIP service 0x%02X", req.Service),
			Severity: SeverityWarn,
		})
	}
	if v.Strict && (uint8(req.Service)&0x80) != 0 {
		findings = append(findings, Finding{
			Code:     "cip.service_response_bit",
			Message:  fmt.Sprintf("response service code not allowed in request: 0x%02X", req.Service),
			Severity: SeverityError,
		})
	}
	if v.Strict && req.Service == spec.CIPServiceErrorResponse {
		findings = append(findings, Finding{
			Code:     "cip.service_error_response",
			Message:  "error response service not allowed in request",
			Severity: SeverityError,
		})
	}

	if v.Strict && !hasCIPPath(req) {
		findings = append(findings, Finding{
			Code:     "cip.path_missing",
			Message:  "CIP request is missing a path",
			Severity: SeverityError,
		})
	}

	if len(req.Payload) > 65535 {
		findings = append(findings, Finding{
			Code:     "cip.payload_too_large",
			Message:  fmt.Sprintf("payload size %d exceeds maximum 65535", len(req.Payload)),
			Severity: SeverityError,
		})
	}

	registry := v.registry()
	if def, ok := registry.LookupService(req.Path.Class, req.Service); ok {
		findings = append(findings, v.applyServiceDef(def, req.Path, req.RawPath, req.Payload, true)...)
	}

	return findings
}

// ValidateCIPResponse validates a CIP response using spec registry rules.
func (v *Validator) ValidateCIPResponse(resp protocol.CIPResponse, expectedService protocol.CIPServiceCode) []Finding {
	findings := []Finding{}

	if !matchesService(resp.Service, expectedService) {
		findings = append(findings, Finding{
			Code:     "cip.response_service_mismatch",
			Message:  fmt.Sprintf("service code mismatch: expected 0x%02X, got 0x%02X", expectedService, resp.Service),
			Severity: SeverityError,
		})
	}

	registry := v.registry()
	if def, ok := registry.LookupService(resp.Path.Class, expectedService); ok {
		findings = append(findings, v.applyServiceDef(def, resp.Path, nil, resp.Payload, false)...)
	}

	return findings
}

// FindingsError returns an error if any findings are errors.
func FindingsError(findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}
	errs := []string{}
	for _, finding := range findings {
		if finding.Severity == SeverityError {
			errs = append(errs, fmt.Sprintf("%s: %s", finding.Code, finding.Message))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("validation failed: %s", strings.Join(errs, "; "))
}

func (v *Validator) registry() *spec.Registry {
	if v.Registry == nil {
		return spec.DefaultRegistry()
	}
	return v.Registry
}

func (v *Validator) applyServiceDef(def spec.ServiceDef, path protocol.CIPPath, rawPath []byte, payload []byte, isRequest bool) []Finding {
	findings := []Finding{}
	if !v.Strict {
		return findings
	}
	if def.RequiresInstance && !pathHasInstance(path, rawPath) {
		findings = append(findings, Finding{
			Code:     "cip.path_instance_missing",
			Message:  fmt.Sprintf("%s requires instance segment", def.Name),
			Severity: SeverityError,
		})
	}
	if def.RequiresAttribute && !pathHasAttribute(path, rawPath) {
		findings = append(findings, Finding{
			Code:     "cip.path_attribute_missing",
			Message:  fmt.Sprintf("%s requires attribute segment", def.Name),
			Severity: SeverityError,
		})
	}
	if isRequest && def.MinRequestLen > 0 && len(payload) < def.MinRequestLen {
		findings = append(findings, Finding{
			Code:     "cip.payload_too_short",
			Message:  fmt.Sprintf("%s request payload too short (%d < %d)", def.Name, len(payload), def.MinRequestLen),
			Severity: SeverityError,
		})
	}
	if !isRequest && def.MinResponseLen > 0 && len(payload) < def.MinResponseLen {
		findings = append(findings, Finding{
			Code:     "cip.payload_too_short",
			Message:  fmt.Sprintf("%s response payload too short (%d < %d)", def.Name, len(payload), def.MinResponseLen),
			Severity: SeverityError,
		})
	}
	for _, rule := range def.StrictRules {
		if isRequest {
			if err := rule.CheckRequest(payload); err != nil {
				findings = append(findings, Finding{
					Code:     "cip.rule_request_failed",
					Message:  fmt.Sprintf("%s request rule %s failed: %v", def.Name, rule.Name(), err),
					Severity: SeverityError,
				})
			}
			continue
		}
		if err := rule.CheckResponse(payload); err != nil {
			findings = append(findings, Finding{
				Code:     "cip.rule_response_failed",
				Message:  fmt.Sprintf("%s response rule %s failed: %v", def.Name, rule.Name(), err),
				Severity: SeverityError,
			})
		}
	}
	return findings
}

func (v *Validator) validateRegisterSession(encap enip.ENIPEncapsulation) []Finding {
	findings := []Finding{}
	if len(encap.Data) < 4 {
		findings = append(findings, Finding{
			Code:     "enip.register_session_short",
			Message:  fmt.Sprintf("RegisterSession data too short: %d bytes", len(encap.Data)),
			Severity: SeverityError,
		})
		return findings
	}
	protocolVersion := enip.CurrentOptions().ByteOrder.Uint16(encap.Data[0:2])
	if protocolVersion != 1 {
		findings = append(findings, Finding{
			Code:     "enip.register_session_version",
			Message:  fmt.Sprintf("RegisterSession protocol version must be 1, got %d", protocolVersion),
			Severity: SeverityError,
		})
	}
	if v.Strict {
		optionFlags := enip.CurrentOptions().ByteOrder.Uint16(encap.Data[2:4])
		if optionFlags != 0 {
			findings = append(findings, Finding{
				Code:     "enip.register_session_options",
				Message:  fmt.Sprintf("RegisterSession option flags should be 0, got 0x%04X", optionFlags),
				Severity: SeverityWarn,
			})
		}
	}
	return findings
}

func (v *Validator) validateSendRRData(encap enip.ENIPEncapsulation) []Finding {
	findings := []Finding{}
	if len(encap.Data) < 6 {
		findings = append(findings, Finding{
			Code:     "enip.send_rr_data_short",
			Message:  fmt.Sprintf("SendRRData data too short: %d bytes", len(encap.Data)),
			Severity: SeverityError,
		})
		return findings
	}

	interfaceHandle := enip.CurrentOptions().ByteOrder.Uint32(encap.Data[0:4])
	if interfaceHandle != 0 {
		findings = append(findings, Finding{
			Code:     "enip.send_rr_data_interface_handle",
			Message:  fmt.Sprintf("SendRRData Interface Handle must be 0, got 0x%08X", interfaceHandle),
			Severity: SeverityError,
		})
	}
	if enip.CurrentOptions().UseCPF {
		if _, err := enip.ParseCPFItems(encap.Data[6:]); err != nil {
			findings = append(findings, Finding{
				Code:     "enip.cpf_parse_failed",
				Message:  fmt.Sprintf("invalid CPF items: %v", err),
				Severity: SeverityError,
			})
		}
	}

	return findings
}

func (v *Validator) validateSendUnitData(encap enip.ENIPEncapsulation) []Finding {
	findings := []Finding{}
	opts := enip.CurrentOptions()
	if opts.UseCPF {
		if len(encap.Data) < 6 {
			findings = append(findings, Finding{
				Code:     "enip.send_unit_data_short",
				Message:  fmt.Sprintf("SendUnitData data too short: %d bytes", len(encap.Data)),
				Severity: SeverityError,
			})
			return findings
		}
		items, err := enip.ParseCPFItems(encap.Data[6:])
		if err != nil {
			findings = append(findings, Finding{
				Code:     "enip.cpf_parse_failed",
				Message:  fmt.Sprintf("invalid CPF items: %v", err),
				Severity: SeverityError,
			})
			return findings
		}
		connID := uint32(0)
		for _, item := range items {
			if item.TypeID == enip.CPFItemConnectedAddress && len(item.Data) >= 4 {
				connID = opts.ByteOrder.Uint32(item.Data[0:4])
				break
			}
		}
		if connID == 0 {
			findings = append(findings, Finding{
				Code:     "enip.send_unit_data_connid_missing",
				Message:  "SendUnitData Connection ID must be non-zero",
				Severity: SeverityError,
			})
		}
		return findings
	}

	if len(encap.Data) < 4 {
		findings = append(findings, Finding{
			Code:     "enip.send_unit_data_short",
			Message:  fmt.Sprintf("SendUnitData data too short: %d bytes", len(encap.Data)),
			Severity: SeverityError,
		})
		return findings
	}
	connID := opts.ByteOrder.Uint32(encap.Data[0:4])
	if connID == 0 {
		findings = append(findings, Finding{
			Code:     "enip.send_unit_data_connid_missing",
			Message:  "SendUnitData Connection ID must be non-zero",
			Severity: SeverityError,
		})
	}
	return findings
}

func isValidENIPCommand(cmd uint16) bool {
	switch cmd {
	case enip.ENIPCommandRegisterSession,
		enip.ENIPCommandUnregisterSession,
		enip.ENIPCommandSendRRData,
		enip.ENIPCommandSendUnitData,
		enip.ENIPCommandListIdentity,
		enip.ENIPCommandListServices,
		enip.ENIPCommandListInterfaces:
		return true
	default:
		return false
	}
}

func requiresSession(cmd uint16) bool {
	switch cmd {
	case enip.ENIPCommandRegisterSession,
		enip.ENIPCommandListIdentity,
		enip.ENIPCommandListServices,
		enip.ENIPCommandListInterfaces:
		return false
	default:
		return true
	}
}

func senderContextAllZero(ctx [8]byte) bool {
	for _, b := range ctx {
		if b != 0 {
			return false
		}
	}
	return true
}

func matchesService(actual, expected protocol.CIPServiceCode) bool {
	if actual == expected {
		return true
	}
	if actual == expected|0x80 {
		return true
	}
	return false
}

func hasCIPPath(req protocol.CIPRequest) bool {
	if len(req.RawPath) > 0 || req.Path.Name != "" {
		return true
	}
	return req.Path.Class != 0 || req.Path.Instance != 0 || req.Path.Attribute != 0
}

func pathHasInstance(path protocol.CIPPath, rawPath []byte) bool {
	if len(rawPath) > 0 || path.Name != "" {
		return true
	}
	return path.Instance != 0
}

func pathHasAttribute(path protocol.CIPPath, rawPath []byte) bool {
	if len(rawPath) > 0 || path.Name != "" {
		return true
	}
	return path.Attribute != 0
}

func isClientWireProfile(profile string) bool {
	return strings.EqualFold(strings.TrimSpace(profile), "client_wire")
}
