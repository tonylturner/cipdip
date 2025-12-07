package cipclient

// CIP (Common Industrial Protocol) encoding and decoding

import (
	"encoding/binary"
	"fmt"
)

// CIPServiceCode represents a CIP service code
type CIPServiceCode uint8

// Common CIP service codes
const (
	CIPServiceGetAttributeAll    CIPServiceCode = 0x01
	CIPServiceSetAttributeAll    CIPServiceCode = 0x02
	CIPServiceGetAttributeList   CIPServiceCode = 0x03
	CIPServiceSetAttributeList   CIPServiceCode = 0x04
	CIPServiceReset              CIPServiceCode = 0x05
	CIPServiceStart              CIPServiceCode = 0x06
	CIPServiceStop               CIPServiceCode = 0x07
	CIPServiceCreate             CIPServiceCode = 0x08
	CIPServiceDelete             CIPServiceCode = 0x09
	CIPServiceMultipleService    CIPServiceCode = 0x0A
	CIPServiceApplyAttributes    CIPServiceCode = 0x0D
	CIPServiceGetAttributeSingle CIPServiceCode = 0x0E
	CIPServiceSetAttributeSingle CIPServiceCode = 0x10
	CIPServiceFindNextObjectInst CIPServiceCode = 0x11
	CIPServiceForwardOpen        CIPServiceCode = 0x54
	CIPServiceForwardClose       CIPServiceCode = 0x4E
)

// CIPPath represents a CIP logical path (class/instance/attribute)
type CIPPath struct {
	Class     uint16
	Instance  uint16
	Attribute uint8
	Name      string // from config, for logging
}

// CIPRequest represents a CIP service request
type CIPRequest struct {
	Service CIPServiceCode
	Path    CIPPath
	Payload []byte // raw CIP request body (no service/path)
}

// CIPResponse represents a CIP service response
type CIPResponse struct {
	Service   CIPServiceCode
	Path      CIPPath
	Status    uint8  // general status from CIP response
	ExtStatus []byte // optional additional status data
	Payload   []byte // raw response data
}

// EPATH segment types
const (
	EPathSegmentClassID     = 0x20
	EPathSegmentInstanceID  = 0x24
	EPathSegmentAttributeID = 0x30
)

// EncodeEPATH encodes a CIP path into EPATH format
// EPATH format: segment type (1 byte) + segment data (variable length)
func EncodeEPATH(path CIPPath) []byte {
	var epath []byte

	// Class segment (8-bit class ID)
	if path.Class <= 0xFF {
		epath = append(epath, EPathSegmentClassID|0x00) // 8-bit format
		epath = append(epath, uint8(path.Class))
	} else {
		// 16-bit class ID
		epath = append(epath, EPathSegmentClassID|0x01) // 16-bit format
		epath = binary.BigEndian.AppendUint16(epath, path.Class)
	}

	// Instance segment (8-bit instance ID)
	if path.Instance <= 0xFF {
		epath = append(epath, EPathSegmentInstanceID|0x00) // 8-bit format
		epath = append(epath, uint8(path.Instance))
	} else {
		// 16-bit instance ID
		epath = append(epath, EPathSegmentInstanceID|0x01) // 16-bit format
		epath = binary.BigEndian.AppendUint16(epath, path.Instance)
	}

	// Attribute segment (8-bit attribute ID)
	epath = append(epath, EPathSegmentAttributeID|0x00) // 8-bit format
	epath = append(epath, path.Attribute)

	return epath
}

// EncodeCIPRequest encodes a CIP request into bytes
func EncodeCIPRequest(req CIPRequest) ([]byte, error) {
	var data []byte

	// Service code
	data = append(data, uint8(req.Service))

	// EPATH
	epath := EncodeEPATH(req.Path)
	data = append(data, epath...)

	// Payload
	if len(req.Payload) > 0 {
		data = append(data, req.Payload...)
	}

	return data, nil
}

// DecodeCIPRequest decodes a CIP request from bytes
func DecodeCIPRequest(data []byte) (CIPRequest, error) {
	if len(data) < 1 {
		return CIPRequest{}, fmt.Errorf("request too short")
	}

	req := CIPRequest{
		Service: CIPServiceCode(data[0]),
	}

	// Decode EPATH (simplified - assumes standard 8-bit class/instance/attribute)
	offset := 1
	if len(data) < offset+6 {
		return req, fmt.Errorf("incomplete EPATH")
	}

	// Class (8-bit)
	if data[offset]&0xF0 != 0x20 {
		return req, fmt.Errorf("invalid class segment")
	}
	req.Path.Class = uint16(data[offset+1])
	offset += 2

	// Instance (8-bit)
	if data[offset]&0xF0 != 0x24 {
		return req, fmt.Errorf("invalid instance segment")
	}
	req.Path.Instance = uint16(data[offset+1])
	offset += 2

	// Attribute (8-bit)
	if data[offset]&0xF0 != 0x30 {
		return req, fmt.Errorf("invalid attribute segment")
	}
	req.Path.Attribute = data[offset+1]
	offset += 2

	// Remaining data is payload
	if len(data) > offset {
		req.Payload = data[offset:]
	}

	return req, nil
}

// EncodeCIPResponse encodes a CIP response into bytes
func EncodeCIPResponse(resp CIPResponse) ([]byte, error) {
	var data []byte

	// Service code (echoed from request)
	data = append(data, uint8(resp.Service))

	// Status
	data = append(data, resp.Status)

	// Extended status (if present)
	if len(resp.ExtStatus) > 0 {
		data = append(data, resp.ExtStatus...)
	}

	// Payload
	if len(resp.Payload) > 0 {
		data = append(data, resp.Payload...)
	}

	return data, nil
}

// DecodeCIPResponse decodes a CIP response from bytes
func DecodeCIPResponse(data []byte, path CIPPath) (CIPResponse, error) {
	if len(data) < 1 {
		return CIPResponse{}, fmt.Errorf("response too short")
	}

	resp := CIPResponse{
		Path: path,
	}

	// General status (first byte after service code in response)
	// Note: In actual CIP responses, the service code is echoed, then status
	// For now, assume the first byte is the status
	offset := 0
	if len(data) > offset {
		resp.Status = data[offset]
		offset++
	}

	// Extended status (if present, indicated by status code)
	// Status 0x00 = success, no extended status
	// Other statuses may have extended status bytes
	if resp.Status != 0x00 && len(data) > offset {
		// Extended status length (if applicable)
		// For now, take remaining bytes as extended status
		resp.ExtStatus = data[offset:]
	}

	// Payload is typically after status bytes
	// This is a simplified parser; full implementation would need to handle
	// the actual CIP response structure more carefully
	if resp.Status == 0x00 {
		// Success: payload follows status
		if len(data) > 1 {
			resp.Payload = data[1:]
		}
	}

	return resp, nil
}

// String returns a string representation of the service code
func (s CIPServiceCode) String() string {
	switch s {
	case CIPServiceGetAttributeAll:
		return "Get_Attribute_All"
	case CIPServiceSetAttributeAll:
		return "Set_Attribute_All"
	case CIPServiceGetAttributeList:
		return "Get_Attribute_List"
	case CIPServiceSetAttributeList:
		return "Set_Attribute_List"
	case CIPServiceReset:
		return "Reset"
	case CIPServiceStart:
		return "Start"
	case CIPServiceStop:
		return "Stop"
	case CIPServiceCreate:
		return "Create"
	case CIPServiceDelete:
		return "Delete"
	case CIPServiceMultipleService:
		return "Multiple_Service"
	case CIPServiceApplyAttributes:
		return "Apply_Attributes"
	case CIPServiceGetAttributeSingle:
		return "Get_Attribute_Single"
	case CIPServiceSetAttributeSingle:
		return "Set_Attribute_Single"
	case CIPServiceFindNextObjectInst:
		return "Find_Next_Object_Instance"
	case CIPServiceForwardOpen:
		return "Forward_Open"
	case CIPServiceForwardClose:
		return "Forward_Close"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(s))
	}
}
