// Package catalog provides CIP service catalog types and lookup.
package catalog

import (
	"fmt"

	"github.com/tturner/cipdip/internal/cip/protocol"
)

// EPATHKind identifies the type of EPATH encoding.
type EPATHKind string

const (
	EPATHLogical  EPATHKind = "logical"   // Class/Instance[/Attribute][/Member]
	EPATHSymbolic EPATHKind = "symbolic"  // ANSI symbol segment (Logix tags)
	EPATHRoute    EPATHKind = "route"     // Port segment routing
	EPATHUCMMWrap EPATHKind = "ucmm_wrap" // Unconnected Send wrapper
	EPATHMSPInner EPATHKind = "msp_inner" // Multiple Service Packet inner
)

// Domain classifies the service origin.
type Domain string

const (
	DomainCore   Domain = "core"   // ODVA standard services
	DomainLogix  Domain = "logix"  // Rockwell Logix services
	DomainLegacy Domain = "legacy" // Legacy services (File, PCCC)
)

// Category groups services for UI organization.
type Category string

const (
	CategoryDiscovery    Category = "discovery"
	CategoryConfiguration Category = "configuration"
	CategoryConnection   Category = "connection"
	CategoryDataAccess   Category = "data_access"
	CategoryFileTransfer Category = "file_transfer"
	CategoryTransport    Category = "transport"
	CategoryLegacy       Category = "legacy"
)

// Personality indicates which server mode supports a service.
type Personality string

const (
	PersonalityAny       Personality = "any"
	PersonalityAdapter   Personality = "adapter"
	PersonalityLogixLike Personality = "logix_like"
	PersonalityPCCC      Personality = "pccc"
)

// EPATH defines the path specification for a catalog entry.
type EPATH struct {
	Kind      EPATHKind `yaml:"kind"`
	Class     uint16    `yaml:"class,omitempty"`
	Instance  uint16    `yaml:"instance,omitempty"`
	Attribute uint16    `yaml:"attribute,omitempty"`
	Member    uint16    `yaml:"member,omitempty"`
}

// ToCIPPath converts an EPATH to a protocol.CIPPath.
func (e *EPATH) ToCIPPath() protocol.CIPPath {
	return protocol.CIPPath{
		Class:     e.Class,
		Instance:  e.Instance,
		Attribute: e.Attribute,
	}
}

// PayloadSchema defines service-specific payload structure.
type PayloadSchema struct {
	Type   string         `yaml:"type,omitempty"`
	Params map[string]any `yaml:"params,omitempty"`
}

// Entry represents a single catalog service entry.
type Entry struct {
	Key           string        `yaml:"key"`
	Name          string        `yaml:"name"`
	ServiceCode   uint8         `yaml:"service_code"`
	ServiceName   string        `yaml:"service_name"`
	ObjectName    string        `yaml:"object_name"`
	ObjectClass   uint16        `yaml:"object_class"`
	EPATH         EPATH         `yaml:"epath"`
	Category      Category      `yaml:"category"`
	Domain        Domain        `yaml:"domain"`
	Vendor        string        `yaml:"vendor,omitempty"`
	Personality   Personality   `yaml:"personality"`
	RequiresInput []string      `yaml:"requires_input,omitempty"`
	PayloadSchema *PayloadSchema `yaml:"payload_schema,omitempty"`
	Description   string        `yaml:"description,omitempty"`
}

// ToCIPRequest builds a CIP request from the entry.
func (e *Entry) ToCIPRequest() protocol.CIPRequest {
	return protocol.CIPRequest{
		Service: protocol.CIPServiceCode(e.ServiceCode),
		Path:    e.EPATH.ToCIPPath(),
	}
}

// HasTargets returns true if this entry has selectable targets (attributes).
func (e *Entry) HasTargets() bool {
	return e.EPATH.Attribute != 0 || len(e.RequiresInput) > 0
}

// ServiceGroup represents a group of entries sharing service+object.
type ServiceGroup struct {
	ServiceCode uint8
	ServiceName string
	ObjectClass uint16
	ObjectName  string
	Domain      Domain
	Entries     []*Entry
}

// TargetPreview returns a comma-separated preview of targets.
func (g *ServiceGroup) TargetPreview(max int) string {
	if len(g.Entries) == 0 {
		return "-"
	}

	// Check if entries have attributes or require input
	if len(g.Entries) == 1 {
		e := g.Entries[0]
		if len(e.RequiresInput) > 0 {
			return fmt.Sprintf("<%s>", e.RequiresInput[0])
		}
		if e.EPATH.Attribute == 0 {
			return "-"
		}
		return e.Name
	}

	// Multiple entries - show preview
	names := make([]string, 0, max)
	for i, e := range g.Entries {
		if i >= max {
			break
		}
		names = append(names, e.Name)
	}

	preview := ""
	for i, name := range names {
		if i > 0 {
			preview += ", "
		}
		preview += name
	}

	remaining := len(g.Entries) - max
	if remaining > 0 {
		preview += fmt.Sprintf(", ...(+%d)", remaining)
	}

	return preview
}

// File represents a catalog YAML file.
type File struct {
	Version int      `yaml:"version"`
	Name    string   `yaml:"name"`
	Entries []*Entry `yaml:"entries"`
}

// Validate checks the catalog file for consistency.
func (f *File) Validate() error {
	if f.Version != 1 {
		return fmt.Errorf("unsupported catalog version: %d", f.Version)
	}

	keys := make(map[string]bool)
	for i, e := range f.Entries {
		if e.Key == "" {
			return fmt.Errorf("entry %d: missing key", i)
		}
		if keys[e.Key] {
			return fmt.Errorf("entry %d: duplicate key %q", i, e.Key)
		}
		keys[e.Key] = true

		if e.ServiceCode == 0 {
			return fmt.Errorf("entry %q: missing service_code", e.Key)
		}
		if e.ObjectClass == 0 {
			return fmt.Errorf("entry %q: missing object_class", e.Key)
		}
		if e.EPATH.Kind == "" {
			return fmt.Errorf("entry %q: missing epath.kind", e.Key)
		}
		if e.Domain == "" {
			return fmt.Errorf("entry %q: missing domain", e.Key)
		}
	}

	return nil
}
