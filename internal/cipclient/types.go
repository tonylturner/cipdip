package cipclient

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// CIPDataType encodes CIP primitive data types used by CIPDIP.
type CIPDataType uint16

const (
	CIPTypeBOOL  CIPDataType = 0x00C1
	CIPTypeSINT  CIPDataType = 0x00C2
	CIPTypeINT   CIPDataType = 0x00C3
	CIPTypeDINT  CIPDataType = 0x00C4
	CIPTypeLINT  CIPDataType = 0x00C5
	CIPTypeREAL  CIPDataType = 0x00CA
	CIPTypeLREAL CIPDataType = 0x00CB
	CIPTypeSTR   CIPDataType = 0x00D0
)

// CIPTypeName returns a display name for a CIP data type.
func CIPTypeName(dt CIPDataType) string {
	switch dt {
	case CIPTypeBOOL:
		return "BOOL"
	case CIPTypeSINT:
		return "SINT"
	case CIPTypeINT:
		return "INT"
	case CIPTypeDINT:
		return "DINT"
	case CIPTypeLINT:
		return "LINT"
	case CIPTypeREAL:
		return "REAL"
	case CIPTypeLREAL:
		return "LREAL"
	case CIPTypeSTR:
		return "STRING"
	default:
		return fmt.Sprintf("UNKNOWN(0x%04X)", uint16(dt))
	}
}

// CIPTypeCode returns a CIP data type code for a tag data type name.
func CIPTypeCode(tagType string) CIPDataType {
	switch tagType {
	case "BOOL":
		return CIPTypeBOOL
	case "SINT":
		return CIPTypeSINT
	case "INT":
		return CIPTypeINT
	case "DINT":
		return CIPTypeDINT
	case "LINT":
		return CIPTypeLINT
	case "REAL":
		return CIPTypeREAL
	case "LREAL":
		return CIPTypeLREAL
	case "STRING":
		return CIPTypeSTR
	default:
		return CIPTypeDINT
	}
}

// ParseCIPDataType parses a CIP data type from hex or alias name.
func ParseCIPDataType(input string) (CIPDataType, error) {
	clean := strings.TrimSpace(input)
	if clean == "" {
		return 0, fmt.Errorf("data type is required")
	}
	if val, err := strconv.ParseUint(clean, 0, 16); err == nil {
		return CIPDataType(val), nil
	}
	switch strings.ToUpper(clean) {
	case "BOOL":
		return CIPTypeBOOL, nil
	case "SINT":
		return CIPTypeSINT, nil
	case "INT":
		return CIPTypeINT, nil
	case "DINT":
		return CIPTypeDINT, nil
	case "LINT":
		return CIPTypeLINT, nil
	case "REAL":
		return CIPTypeREAL, nil
	case "LREAL":
		return CIPTypeLREAL, nil
	case "STRING":
		return CIPTypeSTR, nil
	default:
		return 0, fmt.Errorf("unsupported data type %q", input)
	}
}

// ParseCIPValue parses a string into a CIP value based on data type.
func ParseCIPValue(dt CIPDataType, input string) (any, error) {
	clean := strings.TrimSpace(input)
	if clean == "" {
		return nil, fmt.Errorf("value is required")
	}
	switch dt {
	case CIPTypeBOOL:
		switch strings.ToLower(clean) {
		case "true", "1", "yes", "on":
			return true, nil
		case "false", "0", "no", "off":
			return false, nil
		default:
			return nil, fmt.Errorf("invalid BOOL value %q", input)
		}
	case CIPTypeSINT, CIPTypeINT, CIPTypeDINT, CIPTypeLINT:
		val, err := strconv.ParseInt(clean, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid integer value %q", input)
		}
		switch dt {
		case CIPTypeSINT:
			return int8(val), nil
		case CIPTypeINT:
			return int16(val), nil
		case CIPTypeDINT:
			return int32(val), nil
		default:
			return val, nil
		}
	case CIPTypeREAL, CIPTypeLREAL:
		val, err := strconv.ParseFloat(clean, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid float value %q", input)
		}
		if dt == CIPTypeREAL {
			return float32(val), nil
		}
		return val, nil
	case CIPTypeSTR:
		return clean, nil
	default:
		return nil, fmt.Errorf("unsupported type 0x%04X", uint16(dt))
	}
}

// DecodeCIPValue decodes a single CIP value from bytes.
func DecodeCIPValue(dt CIPDataType, data []byte) (any, int, error) {
	order := CurrentProtocolProfile().CIPByteOrder
	switch dt {
	case CIPTypeBOOL:
		if len(data) < 1 {
			return nil, 0, fmt.Errorf("BOOL requires 1 byte")
		}
		return data[0] != 0, 1, nil
	case CIPTypeSINT:
		if len(data) < 1 {
			return nil, 0, fmt.Errorf("SINT requires 1 byte")
		}
		return int8(data[0]), 1, nil
	case CIPTypeINT:
		if len(data) < 2 {
			return nil, 0, fmt.Errorf("INT requires 2 bytes")
		}
		return int16(order.Uint16(data[:2])), 2, nil
	case CIPTypeDINT:
		if len(data) < 4 {
			return nil, 0, fmt.Errorf("DINT requires 4 bytes")
		}
		return int32(order.Uint32(data[:4])), 4, nil
	case CIPTypeLINT:
		if len(data) < 8 {
			return nil, 0, fmt.Errorf("LINT requires 8 bytes")
		}
		return int64(order.Uint64(data[:8])), 8, nil
	case CIPTypeREAL:
		if len(data) < 4 {
			return nil, 0, fmt.Errorf("REAL requires 4 bytes")
		}
		return math.Float32frombits(order.Uint32(data[:4])), 4, nil
	case CIPTypeLREAL:
		if len(data) < 8 {
			return nil, 0, fmt.Errorf("LREAL requires 8 bytes")
		}
		return math.Float64frombits(order.Uint64(data[:8])), 8, nil
	case CIPTypeSTR:
		if len(data) < 2 {
			return nil, 0, fmt.Errorf("STRING requires length prefix")
		}
		length := int(binary.LittleEndian.Uint16(data[:2]))
		if len(data) < 2+length {
			return nil, 0, fmt.Errorf("STRING length %d exceeds payload", length)
		}
		return string(data[2 : 2+length]), 2 + length, nil
	default:
		return nil, 0, fmt.Errorf("unsupported type 0x%04X", uint16(dt))
	}
}

// EncodeCIPValue encodes a single CIP value to bytes.
func EncodeCIPValue(dt CIPDataType, value any) ([]byte, error) {
	order := CurrentProtocolProfile().CIPByteOrder
	switch dt {
	case CIPTypeBOOL:
		switch v := value.(type) {
		case bool:
			if v {
				return []byte{0x01}, nil
			}
			return []byte{0x00}, nil
		case uint8:
			return []byte{v}, nil
		default:
			return nil, fmt.Errorf("BOOL expects bool")
		}
	case CIPTypeSINT:
		switch v := value.(type) {
		case int8:
			return []byte{byte(v)}, nil
		case int:
			return []byte{byte(v)}, nil
		default:
			return nil, fmt.Errorf("SINT expects int8")
		}
	case CIPTypeINT:
		switch v := value.(type) {
		case int16:
			buf := make([]byte, 2)
			order.PutUint16(buf, uint16(v))
			return buf, nil
		case int:
			buf := make([]byte, 2)
			order.PutUint16(buf, uint16(v))
			return buf, nil
		default:
			return nil, fmt.Errorf("INT expects int16")
		}
	case CIPTypeDINT:
		switch v := value.(type) {
		case int32:
			buf := make([]byte, 4)
			order.PutUint32(buf, uint32(v))
			return buf, nil
		case int:
			buf := make([]byte, 4)
			order.PutUint32(buf, uint32(v))
			return buf, nil
		default:
			return nil, fmt.Errorf("DINT expects int32")
		}
	case CIPTypeLINT:
		switch v := value.(type) {
		case int64:
			buf := make([]byte, 8)
			order.PutUint64(buf, uint64(v))
			return buf, nil
		case int:
			buf := make([]byte, 8)
			order.PutUint64(buf, uint64(v))
			return buf, nil
		default:
			return nil, fmt.Errorf("LINT expects int64")
		}
	case CIPTypeREAL:
		switch v := value.(type) {
		case float32:
			buf := make([]byte, 4)
			order.PutUint32(buf, math.Float32bits(v))
			return buf, nil
		case float64:
			buf := make([]byte, 4)
			order.PutUint32(buf, math.Float32bits(float32(v)))
			return buf, nil
		default:
			return nil, fmt.Errorf("REAL expects float32")
		}
	case CIPTypeLREAL:
		switch v := value.(type) {
		case float64:
			buf := make([]byte, 8)
			order.PutUint64(buf, math.Float64bits(v))
			return buf, nil
		case float32:
			buf := make([]byte, 8)
			order.PutUint64(buf, math.Float64bits(float64(v)))
			return buf, nil
		default:
			return nil, fmt.Errorf("LREAL expects float64")
		}
	case CIPTypeSTR:
		s, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("STRING expects string")
		}
		buf := make([]byte, 2+len(s))
		binary.LittleEndian.PutUint16(buf[0:2], uint16(len(s)))
		copy(buf[2:], []byte(s))
		return buf, nil
	default:
		return nil, fmt.Errorf("unsupported type 0x%04X", uint16(dt))
	}
}
