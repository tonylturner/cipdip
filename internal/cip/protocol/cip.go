package protocol

// CIP (Common Industrial Protocol) Message Router encoding and decoding.

import "fmt"

// CIPServiceCode represents a CIP service code.
type CIPServiceCode uint8

// Common CIP service codes.
const (
	CIPServiceGetAttributeAll      CIPServiceCode = 0x01
	CIPServiceSetAttributeAll      CIPServiceCode = 0x02
	CIPServiceGetAttributeList     CIPServiceCode = 0x03
	CIPServiceSetAttributeList     CIPServiceCode = 0x04
	CIPServiceReset                CIPServiceCode = 0x05
	CIPServiceStart                CIPServiceCode = 0x06
	CIPServiceStop                 CIPServiceCode = 0x07
	CIPServiceCreate               CIPServiceCode = 0x08
	CIPServiceDelete               CIPServiceCode = 0x09
	CIPServiceMultipleService      CIPServiceCode = 0x0A
	CIPServiceApplyAttributes      CIPServiceCode = 0x0D
	CIPServiceGetAttributeSingle   CIPServiceCode = 0x0E
	CIPServiceSetAttributeSingle   CIPServiceCode = 0x10
	CIPServiceFindNextObjectInst   CIPServiceCode = 0x11
	CIPServiceErrorResponse        CIPServiceCode = 0x14
	CIPServiceRestore              CIPServiceCode = 0x15
	CIPServiceSave                 CIPServiceCode = 0x16
	CIPServiceNoOp                 CIPServiceCode = 0x17
	CIPServiceGetMember            CIPServiceCode = 0x18
	CIPServiceSetMember            CIPServiceCode = 0x19
	CIPServiceInsertMember         CIPServiceCode = 0x1A
	CIPServiceRemoveMember         CIPServiceCode = 0x1B
	CIPServiceGroupSync            CIPServiceCode = 0x1C
	CIPServiceExecutePCCC          CIPServiceCode = 0x4B
	CIPServiceReadTag              CIPServiceCode = 0x4C
	CIPServiceWriteTag             CIPServiceCode = 0x4D
	CIPServiceReadModifyWrite      CIPServiceCode = 0x4E
	CIPServiceUploadTransfer       CIPServiceCode = 0x4F
	CIPServiceDownloadTransfer     CIPServiceCode = 0x50
	CIPServiceClearFile            CIPServiceCode = 0x51
	CIPServiceReadTagFragmented    CIPServiceCode = 0x52
	CIPServiceWriteTagFragmented   CIPServiceCode = 0x53
	CIPServiceGetInstanceAttrList  CIPServiceCode = 0x55
	CIPServiceUnconnectedSend      CIPServiceCode = 0x52
	CIPServiceGetConnectionData    CIPServiceCode = 0x56
	CIPServiceSearchConnectionData CIPServiceCode = 0x57
	CIPServiceGetConnectionOwner   CIPServiceCode = 0x5A
	CIPServiceLargeForwardOpen     CIPServiceCode = 0x5B
	CIPServiceForwardOpen          CIPServiceCode = 0x54
	CIPServiceForwardClose         CIPServiceCode = 0x4E
)

// File Object service aliases (share values with existing service codes).
const (
	CIPServiceInitiateUpload       CIPServiceCode = CIPServiceExecutePCCC
	CIPServiceInitiateDownload     CIPServiceCode = CIPServiceReadTag
	CIPServiceInitiatePartialRead  CIPServiceCode = CIPServiceWriteTag
	CIPServiceInitiatePartialWrite CIPServiceCode = CIPServiceReadModifyWrite
)

// CIPPath represents a CIP logical path (class/instance/attribute).
type CIPPath struct {
	Class     uint16
	Instance  uint16
	Attribute uint16
	Name      string // from config, for logging
}

// CIPRequest represents a CIP service request.
type CIPRequest struct {
	Service CIPServiceCode
	Path    CIPPath
	RawPath []byte // Optional raw EPATH override (e.g., symbolic segments)
	Payload []byte // raw CIP request body (no service/path)
}

// CIPResponse represents a CIP service response.
type CIPResponse struct {
	Service   CIPServiceCode
	Path      CIPPath
	Status    uint8  // general status from CIP response
	ExtStatus []byte // optional additional status data
	Payload   []byte // raw response data
}

// EPATH segment types.
const (
	EPathSegmentClassID     = 0x20
	EPathSegmentInstanceID  = 0x24
	EPathSegmentAttributeID = 0x30
)

// EncodeEPATH encodes a CIP path into EPATH format.
func EncodeEPATH(path CIPPath) []byte {
	var epath []byte
	order := currentByteOrder()

	// Class segment (8-bit class ID).
	if path.Class <= 0xFF {
		epath = append(epath, EPathSegmentClassID|0x00)
		epath = append(epath, uint8(path.Class))
	} else {
		epath = append(epath, EPathSegmentClassID|0x01)
		epath = appendUint16(order, epath, path.Class)
	}

	// Instance segment (8-bit instance ID).
	if path.Instance <= 0xFF {
		epath = append(epath, EPathSegmentInstanceID|0x00)
		epath = append(epath, uint8(path.Instance))
	} else {
		epath = append(epath, EPathSegmentInstanceID|0x01)
		epath = appendUint16(order, epath, path.Instance)
	}

	// Attribute segment (8-bit or 16-bit attribute ID).
	if path.Attribute <= 0xFF {
		epath = append(epath, EPathSegmentAttributeID|0x00)
		epath = append(epath, uint8(path.Attribute))
	} else {
		epath = append(epath, EPathSegmentAttributeID|0x01)
		epath = appendUint16(order, epath, path.Attribute)
	}

	return epath
}

// EncodeCIPRequest encodes a CIP request into bytes.
func EncodeCIPRequest(req CIPRequest) ([]byte, error) {
	var data []byte
	opts := CurrentOptions()

	// Service code.
	data = append(data, uint8(req.Service))

	// EPATH.
	epath := req.RawPath
	if len(epath) == 0 {
		epath = EncodeEPATH(req.Path)
	}
	if opts.IncludePathSize {
		pathSizeWords := len(epath) / 2
		if len(epath)%2 != 0 {
			epath = append(epath, 0x00)
			pathSizeWords++
		}
		data = append(data, uint8(pathSizeWords))
	}
	data = append(data, epath...)

	// Payload.
	if len(req.Payload) > 0 {
		data = append(data, req.Payload...)
	}

	return data, nil
}

// DecodeCIPRequest decodes a CIP request from bytes.
func DecodeCIPRequest(data []byte) (CIPRequest, error) {
	if len(data) < 1 {
		return CIPRequest{}, fmt.Errorf("request too short")
	}

	req := CIPRequest{
		Service: CIPServiceCode(data[0]),
	}

	opts := CurrentOptions()
	offset := 1
	if opts.IncludePathSize {
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
		req.RawPath = append([]byte(nil), pathBytes...)
		path, err := DecodeEPATH(pathBytes)
		if err != nil {
			tagName, err := DecodeSymbolicEPATH(pathBytes)
			if err != nil {
				return req, err
			}
			req.Path = CIPPath{Name: tagName}
			offset += pathSizeBytes
			goto payload
		}
		req.Path = path
		offset += pathSizeBytes
	} else {
		if len(data) < offset+6 {
			return req, fmt.Errorf("incomplete EPATH")
		}

		req.RawPath = append([]byte(nil), data[offset:]...)
		path, err := DecodeEPATH(data[offset:])
		if err != nil {
			tagName, err := DecodeSymbolicEPATH(data[offset:])
			if err != nil {
				return req, err
			}
			req.Path = CIPPath{Name: tagName}
			offset = len(data)
			goto payload
		}
		req.Path = path
		offset = len(data)
	}

payload:
	if len(data) > offset {
		req.Payload = data[offset:]
	}

	return req, nil
}

// EncodeCIPResponse encodes a CIP response into bytes.
func EncodeCIPResponse(resp CIPResponse) ([]byte, error) {
	var data []byte
	opts := CurrentOptions()

	// Service code (echoed from request).
	data = append(data, uint8(resp.Service))

	if opts.IncludeRespReserved {
		// Reserved (1 byte) + status (1 byte) + ext status size (1 byte).
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
		data = append(data, resp.Status)
		if len(resp.ExtStatus) > 0 {
			data = append(data, resp.ExtStatus...)
		}
	}

	if len(resp.Payload) > 0 {
		data = append(data, resp.Payload...)
	}

	return data, nil
}

// DecodeCIPResponse decodes a CIP response from bytes.
func DecodeCIPResponse(data []byte, path CIPPath) (CIPResponse, error) {
	opts := CurrentOptions()
	if opts.IncludeRespReserved {
		if len(data) < 4 {
			return CIPResponse{}, fmt.Errorf("response too short: %d bytes (minimum 4: service + reserved + status + ext size)", len(data))
		}
	} else if len(data) < 2 {
		return CIPResponse{}, fmt.Errorf("response too short: %d bytes (minimum 2: service + status)", len(data))
	}

	resp := CIPResponse{
		Path: path,
	}

	resp.Service = CIPServiceCode(data[0])

	offset := 1
	if opts.IncludeRespReserved {
		offset++
		resp.Status = data[2]
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
		resp.Status = data[1]
		offset = 2
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

	if resp.Status == 0x00 {
		if len(data) > offset {
			resp.Payload = data[offset:]
		}
	}

	return resp, nil
}

// DecodeEPATH decodes an EPATH into a Path.
func DecodeEPATH(data []byte) (CIPPath, error) {
	info, err := ParseEPATH(data)
	if err != nil {
		return CIPPath{}, err
	}
	return info.Path, nil
}

// String returns a string representation of the service code.
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
	case CIPServiceErrorResponse:
		return "Error_Response"
	case CIPServiceRestore:
		return "Restore"
	case CIPServiceSave:
		return "Save"
	case CIPServiceNoOp:
		return "No_Op"
	case CIPServiceGetMember:
		return "Get_Member"
	case CIPServiceSetMember:
		return "Set_Member"
	case CIPServiceInsertMember:
		return "Insert_Member"
	case CIPServiceRemoveMember:
		return "Remove_Member"
	case CIPServiceGroupSync:
		return "Group_Sync"
	case CIPServiceExecutePCCC:
		return "Execute_PCCC"
	case CIPServiceReadTag:
		return "Read_Tag"
	case CIPServiceWriteTag:
		return "Write_Tag"
	case CIPServiceReadModifyWrite:
		return "Forward_Close/Read_Modify_Write"
	case CIPServiceUploadTransfer:
		return "Upload_Transfer"
	case CIPServiceDownloadTransfer:
		return "Download_Transfer"
	case CIPServiceClearFile:
		return "Clear_File"
	case CIPServiceReadTagFragmented:
		return "Read_Tag_Fragmented/Unconnected_Send"
	case CIPServiceWriteTagFragmented:
		return "Write_Tag_Fragmented"
	case CIPServiceGetInstanceAttrList:
		return "Get_Instance_Attribute_List"
	case CIPServiceGetConnectionData:
		return "Get_Connection_Data"
	case CIPServiceSearchConnectionData:
		return "Search_Connection_Data"
	case CIPServiceGetConnectionOwner:
		return "Get_Connection_Owner"
	case CIPServiceLargeForwardOpen:
		return "Large_Forward_Open"
	case CIPServiceForwardOpen:
		return "Forward_Open"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(s))
	}
}
