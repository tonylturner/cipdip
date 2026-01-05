package cipclient

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/tturner/cipdip/internal/cip/spec"
	"strconv"
	"strings"

	"github.com/tturner/cipdip/internal/cip/codec"
	"github.com/tturner/cipdip/internal/cip/protocol"
)

// PayloadSpec describes service-specific request payload metadata.
type PayloadSpec struct {
	Type   string
	Params map[string]any
}

// PayloadResult returns payload bytes plus optional raw EPATH override.
type PayloadResult struct {
	Payload []byte
	RawPath []byte
}

// PayloadParams provides typed access to payload params.
type PayloadParams struct {
	raw map[string]any
}

// PayloadType is a well-known payload type identifier.
type PayloadType string

const (
	PayloadNone             PayloadType = "none"
	PayloadForwardOpen      PayloadType = "forward_open"
	PayloadForwardClose     PayloadType = "forward_close"
	PayloadUnconnectedSend  PayloadType = "unconnected_send"
	PayloadRockwellTag      PayloadType = "rockwell_tag"
	PayloadRockwellTagFrag  PayloadType = "rockwell_tag_fragmented"
	PayloadRockwellTemplate PayloadType = "rockwell_template"
	PayloadRockwellPCCC     PayloadType = "rockwell_pccc"
	PayloadFileObject       PayloadType = "file_object"
	PayloadModbusObject     PayloadType = "modbus_object"
	PayloadSafetyReset      PayloadType = "safety_reset"
	PayloadEnergyMetering   PayloadType = "energy_metering"
	PayloadMotionAxis       PayloadType = "motion_axis"
)

// BuildServicePayload builds a payload (and optional raw EPATH) for a CIP request.
func BuildServicePayload(req protocol.CIPRequest, spec PayloadSpec) (PayloadResult, error) {
	payloadType := strings.ToLower(strings.TrimSpace(spec.Type))
	if payloadType == "" {
		payloadType = string(inferPayloadType(req))
	}
	if payloadType == "" || payloadType == string(PayloadNone) {
		return PayloadResult{}, nil
	}

	params := PayloadParams{raw: spec.Params}
	switch PayloadType(payloadType) {
	case PayloadForwardOpen:
		payload, rawPath, err := buildForwardOpenPayload(req, params)
		return PayloadResult{Payload: payload, RawPath: rawPath}, err
	case PayloadForwardClose:
		payload, rawPath, err := buildForwardClosePayload(req, params)
		return PayloadResult{Payload: payload, RawPath: rawPath}, err
	case PayloadUnconnectedSend:
		payload, rawPath, err := buildUnconnectedSendPayload(req, params)
		return PayloadResult{Payload: payload, RawPath: rawPath}, err
	case PayloadRockwellTag:
		payload, rawPath, err := buildRockwellTagPayload(req, params, false)
		return PayloadResult{Payload: payload, RawPath: rawPath}, err
	case PayloadRockwellTagFrag:
		payload, rawPath, err := buildRockwellTagPayload(req, params, true)
		return PayloadResult{Payload: payload, RawPath: rawPath}, err
	case PayloadRockwellTemplate:
		payload, rawPath, err := buildTemplatePayload(req, params)
		return PayloadResult{Payload: payload, RawPath: rawPath}, err
	case PayloadRockwellPCCC:
		payload, rawPath, err := buildPCCCPayload(req, params)
		return PayloadResult{Payload: payload, RawPath: rawPath}, err
	case PayloadFileObject:
		payload, err := buildFileObjectPayload(req, params)
		return PayloadResult{Payload: payload}, err
	case PayloadModbusObject:
		payload, err := buildModbusPayload(req, params)
		return PayloadResult{Payload: payload}, err
	case PayloadSafetyReset:
		payload, err := buildSafetyResetPayload(params)
		return PayloadResult{Payload: payload}, err
	case PayloadEnergyMetering, PayloadMotionAxis:
		// Most energy/motion profile services in this harness are explicit requests
		// without a defined payload. Keep empty for now.
		return PayloadResult{}, nil
	default:
		return PayloadResult{}, fmt.Errorf("unsupported payload type %q", payloadType)
	}
}

func inferPayloadType(req protocol.CIPRequest) PayloadType {
	switch req.Path.Class {
	case spec.CIPClassConnectionManager:
		switch req.Service {
		case spec.CIPServiceForwardOpen:
			return PayloadForwardOpen
		case spec.CIPServiceForwardClose:
			return PayloadForwardClose
		case spec.CIPServiceUnconnectedSend:
			return PayloadUnconnectedSend
		}
	case spec.CIPClassSymbolObject:
		switch req.Service {
		case spec.CIPServiceReadTag, spec.CIPServiceWriteTag:
			return PayloadRockwellTag
		case spec.CIPServiceReadTagFragmented, spec.CIPServiceWriteTagFragmented:
			return PayloadRockwellTagFrag
		}
	case spec.CIPClassTemplateObject:
		if req.Service == spec.CIPServiceReadTag {
			return PayloadRockwellTemplate
		}
	case spec.CIPClassFileObject:
		return PayloadFileObject
	case spec.CIPClassModbus:
		return PayloadModbusObject
	case spec.CIPClassSafetySupervisor, spec.CIPClassSafetyValidator:
		return PayloadSafetyReset
	}
	if req.Service == spec.CIPServiceExecutePCCC && req.Path.Class == spec.CIPClassPCCCObject {
		return PayloadRockwellPCCC
	}
	return PayloadNone
}

func buildForwardOpenPayload(req protocol.CIPRequest, params PayloadParams) ([]byte, []byte, error) {
	connParams := ConnectionParams{
		Priority:              params.getStringDefault("priority", "scheduled"),
		OToTRPIMs:             params.getIntDefault("o_to_t_rpi_ms", 20),
		TToORPIMs:             params.getIntDefault("t_to_o_rpi_ms", 20),
		OToTSizeBytes:         params.getIntDefault("o_to_t_size_bytes", 32),
		TToOSizeBytes:         params.getIntDefault("t_to_o_size_bytes", 32),
		TransportClassTrigger: params.getIntDefault("transport_class_trigger", 3),
		Class:                 uint16(params.getUintDefault("connection_class", uint64(spec.CIPClassAssembly))),
		Instance:              uint16(params.getUintDefault("connection_instance", 0x65)),
	}
	connParams.ConnectionPathHex = params.getStringDefault("connection_path_hex", "")

	payload, err := BuildForwardOpenPayload(connParams)
	if err != nil {
		return nil, nil, err
	}
	rawPath := []byte{0x20, 0x06, 0x24, 0x01}
	return payload, rawPath, nil
}

func buildForwardClosePayload(req protocol.CIPRequest, params PayloadParams) ([]byte, []byte, error) {
	connID := uint32(params.getUintDefault("connection_id", 0))
	if connID == 0 {
		return nil, nil, fmt.Errorf("forward_close requires connection_id")
	}
	payload, err := BuildForwardClosePayload(connID)
	if err != nil {
		return nil, nil, err
	}
	rawPath := []byte{0x20, 0x06, 0x24, 0x01}
	return payload, rawPath, nil
}

func buildUnconnectedSendPayload(req protocol.CIPRequest, params PayloadParams) ([]byte, []byte, error) {
	message := params.getBytesHex("embedded_request_hex")
	if len(message) == 0 {
		message = params.getBytesHex("message_request_hex")
	}
	if len(message) == 0 {
		return nil, nil, fmt.Errorf("unconnected_send requires embedded_request_hex or message_request_hex")
	}
	routeSlot := params.getIntDefault("route_slot", 0)
	routePath := params.getBytesHex("route_path_hex")
	if len(routePath) == 0 && routeSlot > 0 {
		routePath = []byte{0x01, byte(routeSlot)}
	}
	opts := UnconnectedSendOptions{
		PriorityTick: uint8(params.getUintDefault("priority_tick", 0)),
		TimeoutTicks: uint8(params.getUintDefault("timeout_ticks", 0)),
		RoutePath:    routePath,
	}
	payload, err := BuildUnconnectedSendPayload(message, opts)
	if err != nil {
		return nil, nil, err
	}
	rawPath := []byte{0x20, 0x06, 0x24, 0x01}
	return payload, rawPath, nil
}

func buildRockwellTagPayload(req protocol.CIPRequest, params PayloadParams, fragmented bool) ([]byte, []byte, error) {
	tagPath := params.getStringDefault("tag_path", "")
	if tagPath == "" {
		tagPath = params.getStringDefault("tag", "")
	}
	if tagPath == "" {
		tagPath = "Tag1"
	}
	rawPath := protocol.BuildSymbolicEPATH(tagPath)

	elements := uint16(params.getUintDefault("elements", 1))
	offset := uint32(params.getUintDefault("offset", 0))
	typeCode := params.getTypeCodeDefault("type", protocol.CIPTypeDINT)
	valueBytes, err := params.getValueBytes(typeCode, elements)
	if err != nil {
		return nil, nil, err
	}

	switch req.Service {
	case spec.CIPServiceReadTag:
		return BuildReadTagPayload(elements), rawPath, nil
	case spec.CIPServiceWriteTag:
		return BuildWriteTagPayload(uint16(typeCode), elements, valueBytes), rawPath, nil
	case spec.CIPServiceReadTagFragmented:
		return BuildReadTagFragmentedPayload(elements, offset), rawPath, nil
	case spec.CIPServiceWriteTagFragmented:
		return BuildWriteTagFragmentedPayload(uint16(typeCode), elements, offset, valueBytes), rawPath, nil
	default:
		if fragmented {
			return BuildReadTagFragmentedPayload(elements, offset), rawPath, nil
		}
		return BuildReadTagPayload(elements), rawPath, nil
	}
}

func buildTemplatePayload(req protocol.CIPRequest, params PayloadParams) ([]byte, []byte, error) {
	offset := uint32(params.getUintDefault("offset", 0))
	length := uint16(params.getUintDefault("length", 0x40))
	buf := make([]byte, 6)
	codec.PutUint32(binary.LittleEndian, buf[0:4], offset)
	codec.PutUint16(binary.LittleEndian, buf[4:6], length)
	rawPath := []byte{0x20, 0x6C, 0x24, byte(req.Path.Instance)}
	return buf, rawPath, nil
}

func buildPCCCPayload(req protocol.CIPRequest, params PayloadParams) ([]byte, []byte, error) {
	if hexPayload := params.getBytesHex("pccc_hex"); len(hexPayload) > 0 {
		return hexPayload, nil, nil
	}
	example := strings.ToLower(strings.TrimSpace(params.getStringDefault("pccc_example", "")))
	switch example {
	case "status":
		return []byte{0x0F, 0x00}, nil, nil
	case "noop":
		return []byte{0x00}, nil, nil
	}
	// Minimal PCCC frame: command, status, TNS (2 bytes), function.
	return []byte{0x0F, 0x00, 0x00, 0x00, 0x00}, nil, nil
}

func buildFileObjectPayload(req protocol.CIPRequest, params PayloadParams) ([]byte, error) {
	order := currentCIPByteOrder()
	switch req.Service {
	case spec.CIPServiceInitiateUpload:
		size := uint32(params.getUintDefault("file_size", 0))
		buf := make([]byte, 4)
		codec.PutUint32(order, buf, size)
		return buf, nil
	case spec.CIPServiceInitiateDownload:
		total := uint32(params.getUintDefault("file_size", 0))
		format := uint16(params.getUintDefault("format_version", 0))
		rev := uint16(params.getUintDefault("file_revision", 0))
		name := params.getStringDefault("file_name", "")
		nameBytes := []byte(name)
		if len(nameBytes) > 255 {
			nameBytes = nameBytes[:255]
		}
		buf := make([]byte, 9+len(nameBytes))
		codec.PutUint32(order, buf[0:4], total)
		codec.PutUint16(order, buf[4:6], format)
		codec.PutUint16(order, buf[6:8], rev)
		buf[8] = uint8(len(nameBytes))
		copy(buf[9:], nameBytes)
		return buf, nil
	case spec.CIPServiceInitiatePartialRead:
		offset := uint32(params.getUintDefault("file_offset", 0))
		length := uint16(params.getUintDefault("chunk", 0x40))
		buf := make([]byte, 6)
		codec.PutUint32(order, buf[0:4], offset)
		codec.PutUint16(order, buf[4:6], length)
		return buf, nil
	case spec.CIPServiceInitiatePartialWrite:
		offset := uint32(params.getUintDefault("file_offset", 0))
		data := params.getBytesHex("data_hex")
		buf := make([]byte, 6+len(data))
		codec.PutUint32(order, buf[0:4], offset)
		codec.PutUint16(order, buf[4:6], uint16(len(data)))
		copy(buf[6:], data)
		return buf, nil
	case spec.CIPServiceUploadTransfer:
		transfer := uint16(params.getUintDefault("transfer_number", 0))
		buf := make([]byte, 2)
		codec.PutUint16(order, buf, transfer)
		return buf, nil
	case spec.CIPServiceDownloadTransfer:
		transfer := uint16(params.getUintDefault("transfer_number", 0))
		transferType := uint8(params.getUintDefault("transfer_type", 0))
		data := params.getBytesHex("data_hex")
		buf := make([]byte, 3+len(data))
		codec.PutUint16(order, buf[0:2], transfer)
		buf[2] = transferType
		copy(buf[3:], data)
		return buf, nil
	case spec.CIPServiceClearFile:
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported file object service 0x%02X", req.Service)
	}
}

func buildModbusPayload(req protocol.CIPRequest, params PayloadParams) ([]byte, error) {
	order := currentCIPByteOrder()
	addr := uint16(params.getUintDefault("modbus_addr", 0))
	qty := uint16(params.getUintDefault("modbus_qty", 1))
	switch req.Service {
	case 0x4B, 0x4C, 0x4D, 0x4E:
		buf := make([]byte, 4)
		codec.PutUint16(order, buf[0:2], addr)
		codec.PutUint16(order, buf[2:4], qty)
		return buf, nil
	case 0x4F, 0x50:
		data := params.getBytesHex("modbus_data_hex")
		if req.Service == 0x4F && len(data) == 0 && qty > 0 {
			byteCount := int((qty + 7) / 8)
			data = make([]byte, byteCount)
		}
		if req.Service == 0x50 && len(data) == 0 && qty > 0 {
			data = make([]byte, int(qty)*2)
		}
		if len(data) > 255 {
			data = data[:255]
		}
		buf := make([]byte, 5+len(data))
		codec.PutUint16(order, buf[0:2], addr)
		codec.PutUint16(order, buf[2:4], qty)
		buf[4] = uint8(len(data))
		copy(buf[5:], data)
		return buf, nil
	case 0x51:
		pdu := params.getBytesHex("modbus_pdu_hex")
		if len(pdu) == 0 {
			fc := uint8(params.getUintDefault("modbus_fc", 0))
			if fc == 0 {
				return nil, fmt.Errorf("modbus passthrough requires modbus_pdu_hex or modbus_fc")
			}
			return []byte{fc}, nil
		}
		return pdu, nil
	default:
		return nil, fmt.Errorf("unsupported modbus service 0x%02X", req.Service)
	}
}

func buildSafetyResetPayload(params PayloadParams) ([]byte, error) {
	resetType := uint8(params.getUintDefault("reset_type", 0))
	password := params.getBytesHex("password_hex")
	if len(password) == 0 {
		password = make([]byte, 16)
	}
	if len(password) < 16 {
		padded := make([]byte, 16)
		copy(padded, password)
		password = padded
	}
	tunid := params.getBytesHex("tunid_hex")
	if len(tunid) == 0 {
		tunid = make([]byte, 10)
	}
	if len(tunid) < 10 {
		padded := make([]byte, 10)
		copy(padded, tunid)
		tunid = padded
	}
	payload := make([]byte, 0, 1+16+10+1)
	payload = append(payload, resetType)
	payload = append(payload, password[:16]...)
	payload = append(payload, tunid[:10]...)
	if resetType == 2 {
		payload = append(payload, byte(params.getUintDefault("attr_bitmap", 0)))
	}
	return payload, nil
}

func (p PayloadParams) getStringDefault(key, def string) string {
	if p.raw == nil {
		return def
	}
	if value, ok := p.raw[key]; ok {
		switch v := value.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return v
			}
		}
	}
	return def
}

func (p PayloadParams) getUintDefault(key string, def uint64) uint64 {
	if p.raw == nil {
		return def
	}
	value, ok := p.raw[key]
	if !ok {
		return def
	}
	return coerceUint(value, def)
}

func (p PayloadParams) getIntDefault(key string, def int) int {
	return int(p.getUintDefault(key, uint64(def)))
}

func (p PayloadParams) getBytesHex(key string) []byte {
	if p.raw == nil {
		return nil
	}
	value, ok := p.raw[key]
	if !ok {
		return nil
	}
	switch v := value.(type) {
	case string:
		decoded, _ := decodeHexString(v)
		return decoded
	case []byte:
		return v
	}
	return nil
}

func (p PayloadParams) getTypeCodeDefault(key string, def protocol.CIPDataType) protocol.CIPDataType {
	if p.raw == nil {
		return def
	}
	value, ok := p.raw[key]
	if !ok {
		return def
	}
	switch v := value.(type) {
	case string:
		if v == "" {
			return def
		}
		if dt, err := protocol.ParseCIPDataType(v); err == nil {
			return dt
		}
	case int:
		return protocol.CIPDataType(v)
	case uint16:
		return protocol.CIPDataType(v)
	case uint32:
		return protocol.CIPDataType(v)
	}
	return def
}

func (p PayloadParams) getValueBytes(dt protocol.CIPDataType, elements uint16) ([]byte, error) {
	if p.raw == nil {
		return []byte{}, nil
	}
	value := p.getStringDefault("value", "")
	if value == "" {
		return []byte{}, nil
	}
	values := splitCSV(value)
	if len(values) == 0 {
		return []byte{}, nil
	}
	if elements <= 1 || len(values) == 1 {
		v, err := protocol.ParseCIPValue(dt, values[0])
		if err != nil {
			return nil, err
		}
		return protocol.EncodeCIPValue(dt, v)
	}
	buf := make([]byte, 0)
	for i := 0; i < int(elements); i++ {
		val := values[i%len(values)]
		parsed, err := protocol.ParseCIPValue(dt, val)
		if err != nil {
			return nil, err
		}
		enc, err := protocol.EncodeCIPValue(dt, parsed)
		if err != nil {
			return nil, err
		}
		buf = append(buf, enc...)
	}
	return buf, nil
}

func decodeHexString(input string) ([]byte, error) {
	cleaned := strings.ReplaceAll(strings.TrimSpace(input), " ", "")
	cleaned = strings.TrimPrefix(cleaned, "0x")
	if cleaned == "" {
		return nil, nil
	}
	if len(cleaned)%2 != 0 {
		return nil, fmt.Errorf("hex payload must have even length")
	}
	decoded := make([]byte, len(cleaned)/2)
	if _, err := hex.Decode(decoded, []byte(cleaned)); err != nil {
		return nil, fmt.Errorf("decode hex payload: %w", err)
	}
	return decoded, nil
}

func coerceUint(value any, def uint64) uint64 {
	switch v := value.(type) {
	case int:
		return uint64(v)
	case int64:
		return uint64(v)
	case uint64:
		return v
	case uint32:
		return uint64(v)
	case uint16:
		return uint64(v)
	case float64:
		return uint64(v)
	case string:
		parsed, err := strconv.ParseUint(strings.TrimSpace(v), 0, 64)
		if err == nil {
			return parsed
		}
	}
	return def
}

func splitCSV(input string) []string {
	parts := strings.Split(input, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		val := strings.TrimSpace(part)
		if val != "" {
			out = append(out, val)
		}
	}
	return out
}
