package cipclient

// CIP (Common Industrial Protocol) encoding and decoding

import (
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
	Attribute uint16
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
	order := currentCIPByteOrder()

	// Class segment (8-bit class ID)
	if path.Class <= 0xFF {
		epath = append(epath, EPathSegmentClassID|0x00) // 8-bit format
		epath = append(epath, uint8(path.Class))
	} else {
		// 16-bit class ID
		epath = append(epath, EPathSegmentClassID|0x01) // 16-bit format
		epath = appendUint16(order, epath, path.Class)
	}

	// Instance segment (8-bit instance ID)
	if path.Instance <= 0xFF {
		epath = append(epath, EPathSegmentInstanceID|0x00) // 8-bit format
		epath = append(epath, uint8(path.Instance))
	} else {
		// 16-bit instance ID
		epath = append(epath, EPathSegmentInstanceID|0x01) // 16-bit format
		epath = appendUint16(order, epath, path.Instance)
	}

	// Attribute segment (8-bit or 16-bit attribute ID)
	if path.Attribute <= 0xFF {
		epath = append(epath, EPathSegmentAttributeID|0x00) // 8-bit format
		epath = append(epath, uint8(path.Attribute))
	} else {
		epath = append(epath, EPathSegmentAttributeID|0x01) // 16-bit format
		epath = appendUint16(order, epath, path.Attribute)
	}

	return epath
}

// EncodeCIPRequest encodes a CIP request into bytes
func EncodeCIPRequest(req CIPRequest) ([]byte, error) {
	var data []byte
	profile := CurrentProtocolProfile()

	// Service code
	data = append(data, uint8(req.Service))

	// EPATH
	epath := EncodeEPATH(req.Path)
	if profile.IncludeCIPPathSize {
		pathSizeWords := len(epath) / 2
		if len(epath)%2 != 0 {
			epath = append(epath, 0x00)
			pathSizeWords++
		}
		data = append(data, uint8(pathSizeWords))
	}
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

	profile := CurrentProtocolProfile()
	offset := 1
	if profile.IncludeCIPPathSize {
		if len(data) < 2 {
			return req, fmt.Errorf("missing path size")
		}
		pathSizeWords := int(data[1])
		offset++
		pathSizeBytes := pathSizeWords * 2
		if len(data) < offset+pathSizeBytes {
			return req, fmt.Errorf("incomplete EPATH")
		}
		pathBytes := data[offset : offset+pathSizeBytes]
		path, err := DecodeEPATH(pathBytes)
		if err != nil {
			return req, err
		}
		req.Path = path
		offset += pathSizeBytes
	} else {
		if len(data) < offset+6 {
			return req, fmt.Errorf("incomplete EPATH")
		}

		path, err := DecodeEPATH(data[offset:])
		if err != nil {
			return req, err
		}
		req.Path = path
		offset = len(data)
	}

	// Remaining data is payload
	if len(data) > offset {
		req.Payload = data[offset:]
	}

	return req, nil
}

// EncodeCIPResponse encodes a CIP response into bytes
func EncodeCIPResponse(resp CIPResponse) ([]byte, error) {
	var data []byte
	profile := CurrentProtocolProfile()

	// Service code (echoed from request)
	data = append(data, uint8(resp.Service))

	if profile.IncludeCIPRespReserved {
		// Reserved (1 byte) + status (1 byte) + ext status size (1 byte)
		data = append(data, 0x00)
		data = append(data, resp.Status)
		extSizeWords := uint8(0)
		if len(resp.ExtStatus) > 0 {
			extSizeWords = uint8((len(resp.ExtStatus) + 1) / 2)
		}
		data = append(data, extSizeWords)
		if len(resp.ExtStatus) > 0 {
			data = append(data, resp.ExtStatus...)
			if len(resp.ExtStatus)%2 != 0 {
				data = append(data, 0x00)
			}
		}
	} else {
		// Status
		data = append(data, resp.Status)

		// Extended status (if present)
		if len(resp.ExtStatus) > 0 {
			data = append(data, resp.ExtStatus...)
		}
	}

	// Payload
	if len(resp.Payload) > 0 {
		data = append(data, resp.Payload...)
	}

	return data, nil
}

// DecodeCIPResponse decodes a CIP response from bytes
// CIP response structure per ODVA spec:
// - Byte 0: Service code (echoed from request)
// - Byte 1: General status (0x00 = success)
// - Bytes 2+: Extended status (if status != 0x00) + Additional status size byte
// - Bytes N+: Response data (if status == 0x00)
func DecodeCIPResponse(data []byte, path CIPPath) (CIPResponse, error) {
	profile := CurrentProtocolProfile()
	if profile.IncludeCIPRespReserved {
		if len(data) < 4 {
			return CIPResponse{}, fmt.Errorf("response too short: %d bytes (minimum 4: service + reserved + status + ext size)", len(data))
		}
	} else if len(data) < 2 {
		return CIPResponse{}, fmt.Errorf("response too short: %d bytes (minimum 2: service + status)", len(data))
	}

	resp := CIPResponse{
		Path: path,
	}

	// Byte 0: Service code (echoed from request)
	serviceCode := CIPServiceCode(data[0])
	resp.Service = serviceCode

	offset := 1
	if profile.IncludeCIPRespReserved {
		// Byte 1: Reserved
		offset++
		// Byte 2: General status
		resp.Status = data[2]
		// Byte 3: Additional status size (in 16-bit words)
		extSizeWords := int(data[3])
		offset = 4
		extLen := extSizeWords * 2
		if extLen > 0 {
			if len(data) < offset+extLen {
				return resp, fmt.Errorf("extended status too short")
			}
			resp.ExtStatus = data[offset : offset+extLen]
			offset += extLen
		}
	} else {
		// Byte 1: General status
		resp.Status = data[1]
		offset = 2

		// Extended status (if status != 0x00)
		if resp.Status != 0x00 {
			if len(data) > offset {
				extStatusSize := int(data[offset])
				offset++
				if len(data) >= offset+extStatusSize {
					resp.ExtStatus = data[offset : offset+extStatusSize]
					offset += extStatusSize
				}
			}
		}
	}

	// Payload follows status bytes (if status == 0x00, payload is after status byte)
	if resp.Status == 0x00 {
		// Success: payload follows status byte
		if len(data) > offset {
			resp.Payload = data[offset:]
		}
	}

	return resp, nil
}

// DecodeEPATH decodes an EPATH into a CIPPath.
func DecodeEPATH(data []byte) (CIPPath, error) {
	order := currentCIPByteOrder()
	path := CIPPath{}
	offset := 0
	for offset < len(data) {
		seg := data[offset]
		if seg == 0x00 {
			offset++
			continue
		}
		switch seg {
		case 0x20: // 8-bit class
			if len(data) < offset+2 {
				return path, fmt.Errorf("incomplete class segment")
			}
			path.Class = uint16(data[offset+1])
			offset += 2
		case 0x21: // 16-bit class
			if len(data) < offset+3 {
				return path, fmt.Errorf("incomplete 16-bit class segment")
			}
			path.Class = order.Uint16(data[offset+1 : offset+3])
			offset += 3
		case 0x24: // 8-bit instance
			if len(data) < offset+2 {
				return path, fmt.Errorf("incomplete instance segment")
			}
			path.Instance = uint16(data[offset+1])
			offset += 2
		case 0x25: // 16-bit instance
			if len(data) < offset+3 {
				return path, fmt.Errorf("incomplete 16-bit instance segment")
			}
			path.Instance = order.Uint16(data[offset+1 : offset+3])
			offset += 3
		case 0x30: // 8-bit attribute
			if len(data) < offset+2 {
				return path, fmt.Errorf("incomplete attribute segment")
			}
			path.Attribute = uint16(data[offset+1])
			offset += 2
		case 0x31: // 16-bit attribute
			if len(data) < offset+3 {
				return path, fmt.Errorf("incomplete 16-bit attribute segment")
			}
			path.Attribute = order.Uint16(data[offset+1 : offset+3])
			offset += 3
		default:
			return path, fmt.Errorf("invalid EPATH segment: 0x%02X", seg)
		}
	}
	return path, nil
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
