package spec

import "github.com/tturner/cipdip/internal/cip/protocol"

// Rule defines a strict validation rule that can be applied to service shapes.
type Rule interface {
	Name() string
	CheckRequest(payload []byte) error
	CheckResponse(payload []byte) error
}

// ServiceDef describes a CIP service definition and shape rules.
type ServiceDef struct {
	ClassID           uint16
	Service           protocol.CIPServiceCode
	Name              string
	RequiresInstance  bool
	RequiresAttribute bool
	MinRequestLen     int
	MinResponseLen    int
	Category          string
	StrictRules       []Rule
}

type serviceKey struct {
	classID uint16
	service uint8
}

// Registry holds the authoritative service definitions.
type Registry struct {
	services map[serviceKey]ServiceDef
}

// NewRegistry returns an empty service registry.
func NewRegistry() *Registry {
	return &Registry{
		services: make(map[serviceKey]ServiceDef),
	}
}

// RegisterService registers a service definition.
func (r *Registry) RegisterService(def ServiceDef) {
	key := serviceKey{classID: def.ClassID, service: uint8(def.Service)}
	r.services[key] = def
}

// LookupService finds a matching service definition, falling back to class-agnostic entries.
func (r *Registry) LookupService(classID uint16, service protocol.CIPServiceCode) (ServiceDef, bool) {
	key := serviceKey{classID: classID, service: uint8(service)}
	if def, ok := r.services[key]; ok {
		return def, true
	}
	key = serviceKey{classID: 0, service: uint8(service)}
	def, ok := r.services[key]
	return def, ok
}

var defaultRegistry *Registry

// DefaultRegistry returns the shared CIP service registry.
func DefaultRegistry() *Registry {
	if defaultRegistry != nil {
		return defaultRegistry
	}
	registry := NewRegistry()
	for code, name := range cipServiceNames {
		registry.RegisterService(ServiceDef{
			ClassID:        0,
			Service:        protocol.CIPServiceCode(code),
			Name:           name,
			MinRequestLen:  0,
			MinResponseLen: 0,
		})
	}
	registerDefaultServices(registry)
	defaultRegistry = registry
	return defaultRegistry
}
