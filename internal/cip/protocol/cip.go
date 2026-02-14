package protocol

// CIP (Common Industrial Protocol) Message Router encoding and decoding.

import (
	"fmt"

	"github.com/tonylturner/cipdip/internal/cip/codec"
)

// CIPServiceCode represents a CIP service code.
type CIPServiceCode uint8

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
		epath = append(epath, EPathSegmentClassID)
		epath = append(epath, uint8(path.Class))
	} else {
		epath = append(epath, EPathSegmentClassID|0x01)
		epath = codec.AppendUint16(order, epath, path.Class)
	}

	// Instance segment (8-bit instance ID).
	if path.Instance <= 0xFF {
		epath = append(epath, EPathSegmentInstanceID)
		epath = append(epath, uint8(path.Instance))
	} else {
		epath = append(epath, EPathSegmentInstanceID|0x01)
		epath = codec.AppendUint16(order, epath, path.Instance)
	}

	// Attribute segment (8-bit or 16-bit attribute ID).
	if path.Attribute <= 0xFF {
		epath = append(epath, EPathSegmentAttributeID)
		epath = append(epath, uint8(path.Attribute))
	} else {
		epath = append(epath, EPathSegmentAttributeID|0x01)
		epath = codec.AppendUint16(order, epath, path.Attribute)
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

	var offset int
	if opts.IncludeRespReserved {
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
