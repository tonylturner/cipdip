package client

import (
	"fmt"

	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
	"github.com/tonylturner/cipdip/internal/enip"
	"github.com/tonylturner/cipdip/internal/validation"
)

// PacketValidator validates packets for ODVA compliance.
type PacketValidator struct {
	strict    bool
	profile   string
	registry  *spec.Registry
	validator *validation.Validator
}

// NewPacketValidator creates a new packet validator.
func NewPacketValidator(strict bool) *PacketValidator {
	registry := spec.DefaultRegistry()
	return &PacketValidator{
		strict:    strict,
		profile:   "client_wire",
		registry:  registry,
		validator: validation.NewValidator(strict, "client_wire", registry),
	}
}

// ValidateENIP validates an ENIP encapsulation packet.
func (v *PacketValidator) ValidateENIP(encap enip.ENIPEncapsulation) error {
	return validation.FindingsError(v.validator.ValidateENIP(encap))
}

// ValidateCIPRequest validates a CIP request.
func (v *PacketValidator) ValidateCIPRequest(req protocol.CIPRequest) error {
	return validation.FindingsError(v.validator.ValidateCIPRequest(req))
}

// ValidateCIPResponse validates a CIP response.
func (v *PacketValidator) ValidateCIPResponse(resp protocol.CIPResponse, expectedService protocol.CIPServiceCode) error {
	return validation.FindingsError(v.validator.ValidateCIPResponse(resp, expectedService))
}

// ValidateRPIMicroseconds validates RPI value.
func (v *PacketValidator) ValidateRPIMicroseconds(rpi uint32) error {
	// ODVA spec: RPI must be in valid range.
	// Minimum: 100 microseconds (0.1ms).
	// Maximum: 4294967295 microseconds (max uint32).
	if rpi < 100 {
		return fmt.Errorf("RPI %d microseconds is below minimum (100)", rpi)
	}
	// Max is already uint32 max, so no upper bound check needed.
	return nil
}

// ValidateConnectionSize validates connection size.
func (v *PacketValidator) ValidateConnectionSize(size int) error {
	if size < 0 {
		return fmt.Errorf("connection size cannot be negative: %d", size)
	}
	if size > 65535 {
		return fmt.Errorf("connection size %d exceeds maximum (65535)", size)
	}
	return nil
}
