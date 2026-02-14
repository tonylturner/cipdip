package catalog

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// entryYAML is the YAML representation with string hex values.
type entryYAML struct {
	Key           string         `yaml:"key"`
	Name          string         `yaml:"name"`
	ServiceCode   string         `yaml:"service_code"`
	ServiceName   string         `yaml:"service_name"`
	ObjectName    string         `yaml:"object_name"`
	ObjectClass   string         `yaml:"object_class"`
	EPATH         epathYAML      `yaml:"epath"`
	Category      Category       `yaml:"category"`
	Domain        Domain         `yaml:"domain"`
	Vendor        string         `yaml:"vendor,omitempty"`
	Personality   Personality    `yaml:"personality"`
	RequiresInput []string       `yaml:"requires_input,omitempty"`
	PayloadSchema *PayloadSchema `yaml:"payload_schema,omitempty"`
	Description   string         `yaml:"description,omitempty"`
}

type epathYAML struct {
	Kind      EPATHKind `yaml:"kind"`
	Class     string    `yaml:"class,omitempty"`
	Instance  string    `yaml:"instance,omitempty"`
	Attribute string    `yaml:"attribute,omitempty"`
	Member    string    `yaml:"member,omitempty"`
}

// UnmarshalYAML implements yaml.Unmarshaler for Entry.
func (e *Entry) UnmarshalYAML(value *yaml.Node) error {
	var raw entryYAML
	if err := value.Decode(&raw); err != nil {
		return err
	}

	// Parse hex values
	serviceCode, err := parseHexUint8(raw.ServiceCode)
	if err != nil {
		return fmt.Errorf("service_code: %w", err)
	}

	objectClass, err := parseHexUint16(raw.ObjectClass)
	if err != nil {
		return fmt.Errorf("object_class: %w", err)
	}

	epath, err := parseEPATHYAML(raw.EPATH)
	if err != nil {
		return fmt.Errorf("epath: %w", err)
	}

	*e = Entry{
		Key:           raw.Key,
		Name:          raw.Name,
		ServiceCode:   serviceCode,
		ServiceName:   raw.ServiceName,
		ObjectName:    raw.ObjectName,
		ObjectClass:   objectClass,
		EPATH:         epath,
		Category:      raw.Category,
		Domain:        raw.Domain,
		Vendor:        raw.Vendor,
		Personality:   raw.Personality,
		RequiresInput: raw.RequiresInput,
		PayloadSchema: raw.PayloadSchema,
		Description:   raw.Description,
	}

	return nil
}

// MarshalYAML implements yaml.Marshaler for Entry.
func (e Entry) MarshalYAML() (interface{}, error) {
	return entryYAML{
		Key:           e.Key,
		Name:          e.Name,
		ServiceCode:   fmt.Sprintf("0x%02X", e.ServiceCode),
		ServiceName:   e.ServiceName,
		ObjectName:    e.ObjectName,
		ObjectClass:   fmt.Sprintf("0x%02X", e.ObjectClass),
		EPATH:         marshalEPATHYAML(e.EPATH),
		Category:      e.Category,
		Domain:        e.Domain,
		Vendor:        e.Vendor,
		Personality:   e.Personality,
		RequiresInput: e.RequiresInput,
		PayloadSchema: e.PayloadSchema,
		Description:   e.Description,
	}, nil
}

func parseEPATHYAML(raw epathYAML) (EPATH, error) {
	epath := EPATH{Kind: raw.Kind}

	if raw.Class != "" {
		v, err := parseHexUint16(raw.Class)
		if err != nil {
			return epath, fmt.Errorf("class: %w", err)
		}
		epath.Class = v
	}

	if raw.Instance != "" {
		v, err := parseHexUint16(raw.Instance)
		if err != nil {
			return epath, fmt.Errorf("instance: %w", err)
		}
		epath.Instance = v
	} else if raw.Kind == EPATHLogical && epath.Class != 0 {
		// Default instance to 1 for logical paths
		epath.Instance = 1
	}

	if raw.Attribute != "" {
		v, err := parseHexUint16(raw.Attribute)
		if err != nil {
			return epath, fmt.Errorf("attribute: %w", err)
		}
		epath.Attribute = v
	}

	if raw.Member != "" {
		v, err := parseHexUint16(raw.Member)
		if err != nil {
			return epath, fmt.Errorf("member: %w", err)
		}
		epath.Member = v
	}

	return epath, nil
}

func marshalEPATHYAML(e EPATH) epathYAML {
	y := epathYAML{Kind: e.Kind}

	if e.Class != 0 {
		y.Class = fmt.Sprintf("0x%02X", e.Class)
	}
	if e.Instance != 0 && e.Instance != 1 {
		y.Instance = fmt.Sprintf("0x%02X", e.Instance)
	}
	if e.Attribute != 0 {
		y.Attribute = fmt.Sprintf("0x%02X", e.Attribute)
	}
	if e.Member != 0 {
		y.Member = fmt.Sprintf("0x%02X", e.Member)
	}

	return y
}

func parseHexUint8(s string) (uint8, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}

	var base int
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
		base = 16
	} else {
		base = 10
	}

	v, err := strconv.ParseUint(s, base, 8)
	if err != nil {
		return 0, fmt.Errorf("parse %q: %w", s, err)
	}

	return uint8(v), nil
}

func parseHexUint16(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}

	var base int
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
		base = 16
	} else {
		base = 10
	}

	v, err := strconv.ParseUint(s, base, 16)
	if err != nil {
		return 0, fmt.Errorf("parse %q: %w", s, err)
	}

	return uint16(v), nil
}
