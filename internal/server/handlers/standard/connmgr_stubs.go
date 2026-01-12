package standard

import (
	"context"

	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
)

// ConnectionManagerStubs handles stubbed Connection Manager services that return
// "service not supported" errors. These services are documented for future implementation.
//
// Stubbed services:
//   - 0x56 Get_Connection_Data: Returns connection details for a connection number
//   - 0x57 Search_Connection_Data: Searches for connections matching criteria
//   - 0x5A Get_Connection_Owner: Returns the owner of a connection
//
// See notes/tasks.md for implementation details.
type ConnectionManagerStubs struct{}

// NewConnectionManagerStubs creates a new Connection Manager stubs handler.
func NewConnectionManagerStubs() *ConnectionManagerStubs {
	return &ConnectionManagerStubs{}
}

// HandleCIPRequest handles stubbed Connection Manager services.
// Returns a response with status 0x08 (service not supported) for all handled services.
func (h *ConnectionManagerStubs) HandleCIPRequest(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, error) {
	switch req.Service {
	case spec.CIPServiceGetConnectionData: // 0x56
		return h.serviceNotSupported(req), nil

	case spec.CIPServiceSearchConnectionData: // 0x57
		return h.serviceNotSupported(req), nil

	case spec.CIPServiceGetConnectionOwner: // 0x5A
		return h.serviceNotSupported(req), nil
	}

	// For unhandled services, return error response
	return protocol.CIPResponse{
		Service: req.Service,
		Status:  0x08,
		Path:    req.Path,
	}, nil
}

// serviceNotSupported returns a CIP response with status 0x08 (Service not supported).
func (h *ConnectionManagerStubs) serviceNotSupported(req protocol.CIPRequest) protocol.CIPResponse {
	return protocol.CIPResponse{
		Service: req.Service,
		Status:  0x08, // Service not supported
		Path:    req.Path,
	}
}
