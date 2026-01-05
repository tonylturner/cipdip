package cipclient

import (
	"fmt"

	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
	"github.com/tturner/cipdip/internal/enip"
)

// PacketValidator validates packets for ODVA compliance
type PacketValidator struct {
	strict bool // Enable strict ODVA compliance checks
}

// NewPacketValidator creates a new packet validator
func NewPacketValidator(strict bool) *PacketValidator {
	return &PacketValidator{strict: strict}
}

// ValidateENIP validates an ENIP encapsulation packet
func (v *PacketValidator) ValidateENIP(encap enip.ENIPEncapsulation) error {
	// Validate command code
	if !isValidENIPCommand(encap.Command) {
		return fmt.Errorf("invalid ENIP command: 0x%04X", encap.Command)
	}

	// Validate length matches data
	if encap.Length != uint16(len(encap.Data)) {
		return fmt.Errorf("length field (%d) does not match data length (%d)", encap.Length, len(encap.Data))
	}

	// Validate session ID (most commands require non-zero session ID)
	if encap.Command != enip.ENIPCommandRegisterSession && encap.Command != enip.ENIPCommandListIdentity {
		if encap.SessionID == 0 {
			return fmt.Errorf("session ID must be non-zero for command 0x%04X", encap.Command)
		}
	}

	// Validate status (must be 0 in requests)
	if encap.Status != 0 && encap.Command != enip.ENIPCommandRegisterSession {
		// RegisterSession response has status, but requests should be 0
		// This is a request validation, so status should be 0
		if v.strict {
			return fmt.Errorf("status must be 0 in request, got 0x%08X", encap.Status)
		}
	}

	// Validate sender context (should be set)
	if v.strict {
		allZero := true
		for _, b := range encap.SenderContext {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			return fmt.Errorf("sender context should not be all zeros")
		}
	}

	// Validate options (typically 0)
	if v.strict && encap.Options != 0 {
		return fmt.Errorf("options field should be 0, got 0x%08X", encap.Options)
	}

	// Command-specific validation
	switch encap.Command {
	case enip.ENIPCommandRegisterSession:
		return v.validateRegisterSession(encap)
	case enip.ENIPCommandSendRRData:
		return v.validateSendRRData(encap)
	case enip.ENIPCommandSendUnitData:
		return v.validateSendUnitData(encap)
	}

	return nil
}

// ValidateCIPRequest validates a CIP request
func (v *PacketValidator) ValidateCIPRequest(req protocol.CIPRequest) error {
	// Validate service code
	if !spec.IsKnownService(req.Service) {
		return fmt.Errorf("invalid CIP service code: 0x%02X", req.Service)
	}
	if v.strict {
		if uint8(req.Service)&0x80 != 0 {
			return fmt.Errorf("response service code not allowed in request: 0x%02X", req.Service)
		}
		if req.Service == spec.CIPServiceErrorResponse {
			return fmt.Errorf("error response service not allowed in request")
		}
	}

	// Validate path
	if err := v.validateCIPPath(req.Path); err != nil {
		return fmt.Errorf("invalid CIP path: %w", err)
	}

	// Validate payload size (reasonable limits)
	if len(req.Payload) > 65535 {
		return fmt.Errorf("payload size (%d) exceeds maximum (65535)", len(req.Payload))
	}

	// Service-specific validation (non-overlapping codes first)
	switch req.Service {
	case spec.CIPServiceMultipleService:
		if v.strict {
			if req.Path.Class != spec.CIPClassMessageRouter || req.Path.Instance != 0x0001 {
				return fmt.Errorf("Multiple_Service_Packet requires Message Router class 0x0002/instance 0x0001")
			}
			if len(req.Payload) < 4 {
				return fmt.Errorf("Multiple_Service_Packet payload too short")
			}
		}
	case spec.CIPServiceGetAttributeSingle:
		// Get_Attribute_Single should not have payload
		if len(req.Payload) > 0 && v.strict {
			return fmt.Errorf("Get_Attribute_Single should not have payload")
		}
	case spec.CIPServiceSetAttributeSingle:
		// Set_Attribute_Single should have payload
		if len(req.Payload) == 0 {
			return fmt.Errorf("Set_Attribute_Single requires payload")
		}
	case spec.CIPServiceUnconnectedSend:
		if req.Path.Class == spec.CIPClassConnectionManager && req.Path.Instance == 0x0001 {
			if len(req.Payload) < 4 && v.strict {
				return fmt.Errorf("Unconnected_Send requires payload")
			}
			if v.strict {
				embedded, _, ok := protocol.ParseUnconnectedSendRequestPayload(req.Payload)
				if !ok || len(embedded) == 0 {
					return fmt.Errorf("Unconnected_Send requires embedded CIP request")
				}
				if embeddedReq, err := protocol.DecodeCIPRequest(embedded); err == nil {
					if err := v.ValidateCIPRequest(embeddedReq); err != nil {
						return fmt.Errorf("embedded CIP request invalid: %w", err)
					}
				}
			}
		} else {
			if len(req.Payload) == 0 && v.strict {
				return fmt.Errorf("Read_Tag_Fragmented requires payload")
			}
			if v.strict && len(req.Payload) < 6 {
				return fmt.Errorf("Read_Tag_Fragmented requires element count + byte offset")
			}
		}
	case spec.CIPServiceWriteTag, spec.CIPServiceWriteTagFragmented, spec.CIPServiceSetMember, spec.CIPServiceInsertMember, spec.CIPServiceRemoveMember:
		if len(req.Payload) == 0 && v.strict {
			return fmt.Errorf("%s requires payload", spec.ServiceName(req.Service))
		}
		if req.Service == spec.CIPServiceWriteTagFragmented && v.strict && len(req.Payload) < 8 {
			return fmt.Errorf("Write_Tag_Fragmented requires type, element count, and byte offset")
		}
	case spec.CIPServiceForwardOpen:
		if v.strict && req.Path.Class == spec.CIPClassConnectionManager && req.Path.Instance == 0x0001 {
			if len(req.Payload) < 20 {
				return fmt.Errorf("Forward_Open payload too short")
			}
		}
	case spec.CIPServiceForwardClose:
		if v.strict && req.Path.Class == spec.CIPClassConnectionManager && req.Path.Instance == 0x0001 {
			if len(req.Payload) < 3 {
				return fmt.Errorf("Forward_Close payload too short")
			}
		}
	case spec.CIPServiceExecutePCCC:
		if v.strict && len(req.Payload) == 0 {
			return fmt.Errorf("Execute_PCCC requires payload")
		}
	}

	// Tag services (symbol object path)
	if req.Path.Class == spec.CIPClassSymbolObject {
		switch req.Service {
		case spec.CIPServiceReadTag:
			if v.strict && len(req.Payload) < 2 {
				return fmt.Errorf("Read_Tag requires element count")
			}
		case spec.CIPServiceWriteTag:
			if v.strict && len(req.Payload) < 4 {
				return fmt.Errorf("Write_Tag requires type and element count")
			}
		case spec.CIPServiceReadTagFragmented:
			if v.strict && len(req.Payload) < 6 {
				return fmt.Errorf("Read_Tag_Fragmented requires element count and offset")
			}
		case spec.CIPServiceWriteTagFragmented:
			if v.strict && len(req.Payload) < 8 {
				return fmt.Errorf("Write_Tag_Fragmented requires type, element count, and offset")
			}
		}
	}

	// File object services (class 0x37)
	if req.Path.Class == spec.CIPClassFileObject {
		switch req.Service {
		case spec.CIPServiceInitiateUpload, spec.CIPServiceInitiateDownload, spec.CIPServiceInitiatePartialRead,
			spec.CIPServiceInitiatePartialWrite, spec.CIPServiceUploadTransfer, spec.CIPServiceDownloadTransfer:
			if v.strict && len(req.Payload) == 0 {
				return fmt.Errorf("File Object service 0x%02X requires payload", req.Service)
			}
		case spec.CIPServiceClearFile:
			// Clear file may have no payload.
		}
	}

	// Event Log member operations (class 0x41)
	if req.Path.Class == spec.CIPClassEventLog {
		switch req.Service {
		case spec.CIPServiceGetMember, spec.CIPServiceSetMember, spec.CIPServiceInsertMember, spec.CIPServiceRemoveMember:
			if v.strict && len(req.Payload) == 0 {
				return fmt.Errorf("Event Log member service requires payload")
			}
		}
	}

	// Modbus object services (class 0x44)
	if req.Path.Class == spec.CIPClassModbus {
		switch req.Service {
		case 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51:
			if v.strict {
				minLen := 4
				if req.Service == 0x51 {
					minLen = 1
				}
				if len(req.Payload) < minLen {
					return fmt.Errorf("Modbus object service 0x%02X requires payload", req.Service)
				}
			}
		}
	}

	return nil
}

// ValidateCIPResponse validates a CIP response
func (v *PacketValidator) ValidateCIPResponse(resp protocol.CIPResponse, expectedService protocol.CIPServiceCode) error {
	// Validate service code matches request
	if resp.Service != expectedService {
		return fmt.Errorf("service code mismatch: expected 0x%02X, got 0x%02X", expectedService, resp.Service)
	}

	// Validate status code
	if resp.Status > 0xFF {
		return fmt.Errorf("invalid status code: 0x%02X", resp.Status)
	}

	// Validate extended status format
	if resp.Status != 0x00 && len(resp.ExtStatus) > 0 {
		// Extended status should have size byte
		if len(resp.ExtStatus) < 1 {
			return fmt.Errorf("extended status missing size byte")
		}
	}

	// Validate payload structure based on service
	switch resp.Service {
	case spec.CIPServiceGetAttributeSingle:
		if resp.Status == 0x00 && len(resp.Payload) == 0 {
			// Success response should have payload (attribute value)
			if v.strict {
				return fmt.Errorf("Get_Attribute_Single success response should have payload")
			}
		}
	case spec.CIPServiceForwardOpen:
		if v.strict && resp.Status == 0x00 && len(resp.Payload) < 17 {
			return fmt.Errorf("Forward_Open success response payload too short")
		}
	case spec.CIPServiceUnconnectedSend:
		if v.strict && resp.Status == 0x00 {
			embedded, ok := protocol.ParseUnconnectedSendResponsePayload(resp.Payload)
			if !ok || len(embedded) == 0 {
				return fmt.Errorf("Unconnected_Send response missing embedded payload")
			}
		}
	}

	return nil
}

// ValidateRPIMicroseconds validates RPI value
func (v *PacketValidator) ValidateRPIMicroseconds(rpi uint32) error {
	// ODVA spec: RPI must be in valid range
	// Minimum: 100 microseconds (0.1ms)
	// Maximum: 4294967295 microseconds (max uint32)
	if rpi < 100 {
		return fmt.Errorf("RPI %d microseconds is below minimum (100)", rpi)
	}
	// Max is already uint32 max, so no upper bound check needed
	return nil
}

// ValidateConnectionSize validates connection size
func (v *PacketValidator) ValidateConnectionSize(size int) error {
	if size < 0 {
		return fmt.Errorf("connection size cannot be negative: %d", size)
	}
	if size > 65535 {
		return fmt.Errorf("connection size %d exceeds maximum (65535)", size)
	}
	return nil
}

// validateRegisterSession validates RegisterSession structure
func (v *PacketValidator) validateRegisterSession(encap enip.ENIPEncapsulation) error {
	if len(encap.Data) < 4 {
		return fmt.Errorf("RegisterSession data too short: %d bytes (minimum 4)", len(encap.Data))
	}

	// Protocol version should be 1
	protocolVersion := currentENIPByteOrder().Uint16(encap.Data[0:2])
	if protocolVersion != 1 {
		return fmt.Errorf("RegisterSession protocol version must be 1, got %d", protocolVersion)
	}

	// Option flags should be 0
	optionFlags := currentENIPByteOrder().Uint16(encap.Data[2:4])
	if v.strict && optionFlags != 0 {
		return fmt.Errorf("RegisterSession option flags should be 0, got 0x%04X", optionFlags)
	}

	return nil
}

// validateSendRRData validates SendRRData structure
func (v *PacketValidator) validateSendRRData(encap enip.ENIPEncapsulation) error {
	if len(encap.Data) < 6 {
		return fmt.Errorf("SendRRData data too short: %d bytes (minimum 6)", len(encap.Data))
	}

	// Interface Handle should be 0 for UCMM
	interfaceHandle := currentENIPByteOrder().Uint32(encap.Data[0:4])
	if interfaceHandle != 0 {
		return fmt.Errorf("SendRRData Interface Handle must be 0 for UCMM, got 0x%08X", interfaceHandle)
	}

	profile := CurrentProtocolProfile()
	if profile.UseCPF {
		if _, err := enip.ParseCPFItems(encap.Data[6:]); err != nil {
			return fmt.Errorf("invalid CPF items: %w", err)
		}
	}

	return nil
}

// validateSendUnitData validates SendUnitData structure
func (v *PacketValidator) validateSendUnitData(encap enip.ENIPEncapsulation) error {
	profile := CurrentProtocolProfile()
	if profile.UseCPF {
		if len(encap.Data) < 6 {
			return fmt.Errorf("SendUnitData data too short: %d bytes (minimum 6)", len(encap.Data))
		}
		items, err := enip.ParseCPFItems(encap.Data[6:])
		if err != nil {
			return fmt.Errorf("invalid CPF items: %w", err)
		}
		connID := uint32(0)
		for _, item := range items {
			if item.TypeID == enip.CPFItemConnectedAddress && len(item.Data) >= 4 {
				connID = currentENIPByteOrder().Uint32(item.Data[0:4])
				break
			}
		}
		if connID == 0 {
			return fmt.Errorf("SendUnitData Connection ID must be non-zero")
		}
	} else {
		if len(encap.Data) < 4 {
			return fmt.Errorf("SendUnitData data too short: %d bytes (minimum 4)", len(encap.Data))
		}
		// Connection ID should be non-zero
		connectionID := currentENIPByteOrder().Uint32(encap.Data[0:4])
		if connectionID == 0 {
			return fmt.Errorf("SendUnitData Connection ID must be non-zero")
		}
	}
	return nil
}

// validateCIPPath validates a CIP path
func (v *PacketValidator) validateCIPPath(path protocol.CIPPath) error {
	// Class 0 is typically invalid (reserved)
	if path.Class == 0 && path.Name == "" && v.strict {
		return fmt.Errorf("CIP class 0 is reserved")
	}

	// Instance validation (0 is often valid, but depends on class)
	// This is class-specific, so we'll be lenient here

	// Attribute validation (0 is often valid for instance-level operations)
	// This is also class/instance-specific

	return nil
}

// Helper functions

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
