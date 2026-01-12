package profile

import "fmt"

// ValidationWarning represents a warning or error from profile validation.
type ValidationWarning struct {
	Level   string // "warning" or "error"
	Message string
}

// ValidateProfileConsistency checks a profile for internal consistency beyond
// the basic Validate() method. It returns warnings for issues that won't prevent
// operation but may indicate misconfigurations.
func ValidateProfileConsistency(p *Profile) []ValidationWarning {
	var warnings []ValidationWarning

	// Check 1: Adapter profile with tags but no field mappings
	if p.Metadata.Personality == "adapter" {
		if len(p.DataModel.Tags) > 0 && !p.HasFieldMappings() {
			warnings = append(warnings, ValidationWarning{
				Level:   "error",
				Message: "adapter profile has tags but no assembly field mappings; roles referencing these tags will fail",
			})
		}
	}

	// Check 2: logix_like profile with no tags
	if p.Metadata.Personality == "logix_like" && len(p.DataModel.Tags) == 0 {
		warnings = append(warnings, ValidationWarning{
			Level:   "warning",
			Message: "logix_like profile has no tags defined; consider adding tags for realistic simulation",
		})
	}

	// Check 3: Role tag references exist in data model or field mappings
	for roleName, role := range p.Roles {
		for _, tagName := range role.ReadTags {
			if !hasTagOrField(p, tagName) {
				warnings = append(warnings, ValidationWarning{
					Level:   "error",
					Message: fmt.Sprintf("role %q references undefined read tag: %s", roleName, tagName),
				})
			}
		}
		for _, tagName := range role.WriteTags {
			if !hasTagOrField(p, tagName) {
				warnings = append(warnings, ValidationWarning{
					Level:   "error",
					Message: fmt.Sprintf("role %q references undefined write tag: %s", roleName, tagName),
				})
			}
			// Check if writable
			if !isTagWritable(p, tagName) {
				warnings = append(warnings, ValidationWarning{
					Level:   "warning",
					Message: fmt.Sprintf("role %q writes to non-writable tag: %s", roleName, tagName),
				})
			}
		}
	}

	// Check 4: State machine tag overrides reference valid tags
	for stateName, state := range p.StateMachine.States {
		for tagName := range state.TagOverrides {
			if !hasTagOrField(p, tagName) {
				warnings = append(warnings, ValidationWarning{
					Level:   "warning",
					Message: fmt.Sprintf("state %q overrides undefined tag: %s", stateName, tagName),
				})
			}
		}
	}

	// Check 5: Field mappings don't overlap
	for _, asm := range p.DataModel.Assemblies {
		overlaps := findFieldOverlaps(asm.Fields)
		for _, overlap := range overlaps {
			warnings = append(warnings, ValidationWarning{
				Level:   "error",
				Message: fmt.Sprintf("assembly %q has overlapping fields: %s", asm.Name, overlap),
			})
		}
	}

	// Check 6: Adapter profile assemblies should have reasonable sizes
	for _, asm := range p.DataModel.Assemblies {
		if asm.SizeBytes == 0 {
			warnings = append(warnings, ValidationWarning{
				Level:   "warning",
				Message: fmt.Sprintf("assembly %q has zero size", asm.Name),
			})
		}
		if asm.SizeBytes > 500 {
			warnings = append(warnings, ValidationWarning{
				Level:   "warning",
				Message: fmt.Sprintf("assembly %q has unusually large size: %d bytes", asm.Name, asm.SizeBytes),
			})
		}
	}

	return warnings
}

// hasTagOrField returns true if the tag name exists in tags or field mappings.
func hasTagOrField(p *Profile, name string) bool {
	for _, tag := range p.DataModel.Tags {
		if tag.Name == name {
			return true
		}
	}
	for _, asm := range p.DataModel.Assemblies {
		for _, field := range asm.Fields {
			if field.Name == name {
				return true
			}
		}
	}
	return false
}

// isTagWritable returns true if the tag/field is writable.
func isTagWritable(p *Profile, name string) bool {
	for _, tag := range p.DataModel.Tags {
		if tag.Name == name {
			return tag.Writable
		}
	}
	for _, asm := range p.DataModel.Assemblies {
		for _, field := range asm.Fields {
			if field.Name == name {
				return asm.Writable
			}
		}
	}
	return false
}

// findFieldOverlaps finds overlapping field definitions within an assembly.
func findFieldOverlaps(fields []FieldMapping) []string {
	var overlaps []string

	for i := 0; i < len(fields); i++ {
		for j := i + 1; j < len(fields); j++ {
			f1 := fields[i]
			f2 := fields[j]

			// Calculate byte ranges
			f1End := f1.ByteOffset + fieldTypeSize(f1.Type)
			f2End := f2.ByteOffset + fieldTypeSize(f2.Type)

			// Check for byte-level overlap
			if f1.ByteOffset < f2End && f2.ByteOffset < f1End {
				// For BOOL types in the same byte, check bit overlap
				if f1.Type == "BOOL" && f2.Type == "BOOL" && f1.ByteOffset == f2.ByteOffset {
					if f1.BitOffset == f2.BitOffset {
						overlaps = append(overlaps, fmt.Sprintf("%s and %s at byte %d bit %d",
							f1.Name, f2.Name, f1.ByteOffset, f1.BitOffset))
					}
				} else if f1.Type != "BOOL" || f2.Type != "BOOL" {
					// Non-BOOL types overlap at byte level
					overlaps = append(overlaps, fmt.Sprintf("%s (bytes %d-%d) and %s (bytes %d-%d)",
						f1.Name, f1.ByteOffset, f1End-1, f2.Name, f2.ByteOffset, f2End-1))
				}
			}
		}
	}

	return overlaps
}

// fieldTypeSize returns the size in bytes of a field type.
func fieldTypeSize(fieldType string) int {
	switch fieldType {
	case "BOOL", "SINT":
		return 1
	case "INT":
		return 2
	case "DINT", "REAL":
		return 4
	default:
		return 4
	}
}
