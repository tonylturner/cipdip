package profile

import (
	"encoding/binary"
	"fmt"
	"math"
)

// ResolvedTag contains the resolved assembly coordinates and field information
// for a tag name in an adapter profile.
type ResolvedTag struct {
	TagName    string
	Assembly   *AssemblyDefinition
	Field      *FieldMapping
	Class      uint16
	Instance   uint16
	Attribute  uint16
	ByteOffset int
	BitOffset  int
	Type       string
	Writable   bool
}

// TagResolver resolves tag names to assembly coordinates for adapter profiles.
// For logix_like profiles, it returns nil (symbolic addressing is used instead).
type TagResolver struct {
	profile *Profile
	tagMap  map[string]*ResolvedTag
}

// NewTagResolver creates a TagResolver for the given profile.
// Returns nil if the profile doesn't use field mappings (logix_like or adapter without mappings).
func NewTagResolver(p *Profile) *TagResolver {
	if !p.IsAdapterWithFieldMappings() {
		return nil
	}

	resolver := &TagResolver{
		profile: p,
		tagMap:  make(map[string]*ResolvedTag),
	}

	// Build the tag map from assembly field mappings
	for i := range p.DataModel.Assemblies {
		asm := &p.DataModel.Assemblies[i]
		for j := range asm.Fields {
			field := &asm.Fields[j]
			resolver.tagMap[field.Name] = &ResolvedTag{
				TagName:    field.Name,
				Assembly:   asm,
				Field:      field,
				Class:      asm.Class,
				Instance:   asm.Instance,
				Attribute:  asm.Attribute,
				ByteOffset: field.ByteOffset,
				BitOffset:  field.BitOffset,
				Type:       field.Type,
				Writable:   asm.Writable,
			}
		}
	}

	return resolver
}

// Resolve returns the resolved tag information for a tag name.
// Returns nil if the tag is not found in the field mappings.
func (r *TagResolver) Resolve(tagName string) *ResolvedTag {
	if r == nil {
		return nil
	}
	return r.tagMap[tagName]
}

// IsAdapterProfile returns true if this resolver is for an adapter profile.
func (r *TagResolver) IsAdapterProfile() bool {
	return r != nil && r.profile.Metadata.Personality == "adapter"
}

// HasMapping returns true if the tag name has a field mapping.
func (r *TagResolver) HasMapping(tagName string) bool {
	if r == nil {
		return false
	}
	_, ok := r.tagMap[tagName]
	return ok
}

// TagNames returns all tag names that have field mappings.
func (r *TagResolver) TagNames() []string {
	if r == nil {
		return nil
	}
	names := make([]string, 0, len(r.tagMap))
	for name := range r.tagMap {
		names = append(names, name)
	}
	return names
}

// ExtractValue extracts a field value from assembly data payload.
// The payload should be the raw assembly data from a Get_Attribute_Single response.
func (r *ResolvedTag) ExtractValue(payload []byte) (interface{}, error) {
	if r.ByteOffset >= len(payload) {
		return nil, fmt.Errorf("byte offset %d exceeds payload length %d", r.ByteOffset, len(payload))
	}

	switch r.Type {
	case "BOOL":
		if r.ByteOffset >= len(payload) {
			return nil, fmt.Errorf("byte offset %d exceeds payload length %d", r.ByteOffset, len(payload))
		}
		byteVal := payload[r.ByteOffset]
		return (byteVal>>r.BitOffset)&1 == 1, nil

	case "SINT":
		if r.ByteOffset >= len(payload) {
			return nil, fmt.Errorf("byte offset %d exceeds payload length %d", r.ByteOffset, len(payload))
		}
		return int8(payload[r.ByteOffset]), nil

	case "INT":
		if r.ByteOffset+2 > len(payload) {
			return nil, fmt.Errorf("INT at offset %d exceeds payload length %d", r.ByteOffset, len(payload))
		}
		return int16(binary.LittleEndian.Uint16(payload[r.ByteOffset:])), nil

	case "DINT":
		if r.ByteOffset+4 > len(payload) {
			return nil, fmt.Errorf("DINT at offset %d exceeds payload length %d", r.ByteOffset, len(payload))
		}
		return int32(binary.LittleEndian.Uint32(payload[r.ByteOffset:])), nil

	case "REAL":
		if r.ByteOffset+4 > len(payload) {
			return nil, fmt.Errorf("REAL at offset %d exceeds payload length %d", r.ByteOffset, len(payload))
		}
		bits := binary.LittleEndian.Uint32(payload[r.ByteOffset:])
		return math.Float32frombits(bits), nil

	default:
		return nil, fmt.Errorf("unsupported type: %s", r.Type)
	}
}

// SetValue sets a field value in assembly data payload.
// The payload should be a mutable byte slice of sufficient size.
func (r *ResolvedTag) SetValue(payload []byte, value interface{}) error {
	if r.ByteOffset >= len(payload) {
		return fmt.Errorf("byte offset %d exceeds payload length %d", r.ByteOffset, len(payload))
	}

	switch r.Type {
	case "BOOL":
		boolVal, ok := value.(bool)
		if !ok {
			return fmt.Errorf("expected bool value for BOOL type, got %T", value)
		}
		if boolVal {
			payload[r.ByteOffset] |= (1 << r.BitOffset)
		} else {
			payload[r.ByteOffset] &^= (1 << r.BitOffset)
		}
		return nil

	case "SINT":
		var intVal int8
		switch v := value.(type) {
		case int8:
			intVal = v
		case int:
			intVal = int8(v)
		case int32:
			intVal = int8(v)
		case int64:
			intVal = int8(v)
		default:
			return fmt.Errorf("expected int value for SINT type, got %T", value)
		}
		payload[r.ByteOffset] = byte(intVal)
		return nil

	case "INT":
		if r.ByteOffset+2 > len(payload) {
			return fmt.Errorf("INT at offset %d exceeds payload length %d", r.ByteOffset, len(payload))
		}
		var intVal int16
		switch v := value.(type) {
		case int16:
			intVal = v
		case int:
			intVal = int16(v)
		case int32:
			intVal = int16(v)
		case int64:
			intVal = int16(v)
		default:
			return fmt.Errorf("expected int value for INT type, got %T", value)
		}
		binary.LittleEndian.PutUint16(payload[r.ByteOffset:], uint16(intVal))
		return nil

	case "DINT":
		if r.ByteOffset+4 > len(payload) {
			return fmt.Errorf("DINT at offset %d exceeds payload length %d", r.ByteOffset, len(payload))
		}
		var intVal int32
		switch v := value.(type) {
		case int32:
			intVal = v
		case int:
			intVal = int32(v)
		case int64:
			intVal = int32(v)
		default:
			return fmt.Errorf("expected int value for DINT type, got %T", value)
		}
		binary.LittleEndian.PutUint32(payload[r.ByteOffset:], uint32(intVal))
		return nil

	case "REAL":
		if r.ByteOffset+4 > len(payload) {
			return fmt.Errorf("REAL at offset %d exceeds payload length %d", r.ByteOffset, len(payload))
		}
		var floatVal float32
		switch v := value.(type) {
		case float32:
			floatVal = v
		case float64:
			floatVal = float32(v)
		default:
			return fmt.Errorf("expected float value for REAL type, got %T", value)
		}
		bits := math.Float32bits(floatVal)
		binary.LittleEndian.PutUint32(payload[r.ByteOffset:], bits)
		return nil

	default:
		return fmt.Errorf("unsupported type: %s", r.Type)
	}
}

// TypeSize returns the size in bytes of the field type.
func (r *ResolvedTag) TypeSize() int {
	switch r.Type {
	case "BOOL", "SINT":
		return 1
	case "INT":
		return 2
	case "DINT", "REAL":
		return 4
	default:
		return 0
	}
}
