package catalog

import (
	"fmt"
	"strings"

	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
)

// ValidationError represents a catalog validation error.
type ValidationError struct {
	Key     string
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s: %s", e.Key, e.Field, e.Message)
}

// ValidationResult holds results from catalog validation.
type ValidationResult struct {
	Errors   []ValidationError
	Warnings []ValidationError
}

// IsValid returns true if no errors were found.
func (r *ValidationResult) IsValid() bool {
	return len(r.Errors) == 0
}

// ValidateAgainstSpec validates catalog entries against the CIP spec package.
func ValidateAgainstSpec(c *Catalog) *ValidationResult {
	result := &ValidationResult{}

	for _, e := range c.ListAll() {
		validateEntry(e, result)
	}

	return result
}

func validateEntry(e *Entry, result *ValidationResult) {
	// Validate service code is known
	serviceCode := protocol.CIPServiceCode(e.ServiceCode)
	if !spec.IsKnownService(serviceCode) {
		result.Warnings = append(result.Warnings, ValidationError{
			Key:     e.Key,
			Field:   "service_code",
			Message: fmt.Sprintf("unknown service code 0x%02X", e.ServiceCode),
		})
	} else {
		// Check service name matches spec
		specName := spec.ServiceName(serviceCode)
		normalizedSpec := normalizeServiceName(specName)
		normalizedEntry := normalizeServiceName(e.ServiceName)
		if normalizedSpec != normalizedEntry {
			result.Warnings = append(result.Warnings, ValidationError{
				Key:     e.Key,
				Field:   "service_name",
				Message: fmt.Sprintf("service name %q doesn't match spec %q", e.ServiceName, specName),
			})
		}
	}

	// Validate class code is known
	if !spec.IsKnownClass(e.ObjectClass) {
		result.Warnings = append(result.Warnings, ValidationError{
			Key:     e.Key,
			Field:   "object_class",
			Message: fmt.Sprintf("unknown class code 0x%02X", e.ObjectClass),
		})
	}

	// Validate EPATH kind matches entry structure
	switch e.EPATH.Kind {
	case EPATHLogical:
		if e.EPATH.Class == 0 {
			result.Errors = append(result.Errors, ValidationError{
				Key:     e.Key,
				Field:   "epath.class",
				Message: "logical path requires class",
			})
		}
		// Instance defaults to 1 if not specified, so no error
	case EPATHSymbolic:
		if !containsInput(e.RequiresInput, "symbol_path") && !containsInput(e.RequiresInput, "tag_path") {
			result.Errors = append(result.Errors, ValidationError{
				Key:     e.Key,
				Field:   "requires_input",
				Message: "symbolic path requires symbol_path or tag_path in requires_input",
			})
		}
	case EPATHUCMMWrap:
		if e.PayloadSchema == nil || e.PayloadSchema.Type != "unconnected_send" {
			result.Warnings = append(result.Warnings, ValidationError{
				Key:     e.Key,
				Field:   "payload_schema",
				Message: "ucmm_wrap typically requires unconnected_send payload schema",
			})
		}
	case EPATHMSPInner:
		if e.PayloadSchema == nil || e.PayloadSchema.Type != "multiple_service" {
			result.Warnings = append(result.Warnings, ValidationError{
				Key:     e.Key,
				Field:   "payload_schema",
				Message: "msp_inner typically requires multiple_service payload schema",
			})
		}
	case EPATHRoute:
		// Route paths are valid without additional constraints
	default:
		result.Errors = append(result.Errors, ValidationError{
			Key:     e.Key,
			Field:   "epath.kind",
			Message: fmt.Sprintf("unknown epath kind: %s", e.EPATH.Kind),
		})
	}

	// Validate domain
	switch e.Domain {
	case DomainCore, DomainLogix, DomainLegacy:
		// Valid
	default:
		result.Errors = append(result.Errors, ValidationError{
			Key:     e.Key,
			Field:   "domain",
			Message: fmt.Sprintf("unknown domain: %s", e.Domain),
		})
	}

	// Validate personality
	switch e.Personality {
	case PersonalityAny, PersonalityAdapter, PersonalityLogixLike:
		// Valid
	case "":
		result.Errors = append(result.Errors, ValidationError{
			Key:     e.Key,
			Field:   "personality",
			Message: "missing personality",
		})
	default:
		result.Errors = append(result.Errors, ValidationError{
			Key:     e.Key,
			Field:   "personality",
			Message: fmt.Sprintf("unknown personality: %s", e.Personality),
		})
	}

	// Validate EPATH class matches object_class
	if e.EPATH.Kind == EPATHLogical && e.EPATH.Class != e.ObjectClass {
		result.Errors = append(result.Errors, ValidationError{
			Key:     e.Key,
			Field:   "epath.class",
			Message: fmt.Sprintf("epath.class (0x%02X) doesn't match object_class (0x%02X)", e.EPATH.Class, e.ObjectClass),
		})
	}
}

func normalizeServiceName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "")
	name = strings.ReplaceAll(name, " ", "")
	name = strings.ReplaceAll(name, "-", "")
	return name
}

func containsInput(inputs []string, target string) bool {
	for _, input := range inputs {
		if input == target {
			return true
		}
	}
	return false
}
