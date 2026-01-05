package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/ui"
	"github.com/tturner/cipdip/internal/validation"
)

type emitBytesFlags struct {
	catalogRoot   string
	catalogKeys   []string
	allCatalog    bool
	outputPath    string
	profileName   string
	responsesOnly bool
}

func newEmitBytesCmd() *cobra.Command {
	flags := &emitBytesFlags{}

	cmd := &cobra.Command{
		Use:   "emit-bytes",
		Short: "Emit ENIP request bytes for catalog operations",
		Long: `Emit ENIP bytes for catalog-defined operations without sending
traffic on the network. Output is JSON for validate-bytes consumption.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if handleHelpArg(cmd, args) {
				return nil
			}
			return runEmitBytes(flags)
		},
	}

	cmd.Flags().StringVar(&flags.catalogRoot, "catalog-root", "", "Workspace root containing catalogs/ for catalog-key resolution")
	cmd.Flags().StringArrayVar(&flags.catalogKeys, "catalog-key", nil, "Catalog key to emit (repeatable)")
	cmd.Flags().BoolVar(&flags.allCatalog, "all", false, "Emit all catalog entries")
	cmd.Flags().StringVar(&flags.outputPath, "output", "", "Write JSON to file (default stdout)")
	cmd.Flags().StringVar(&flags.profileName, "protocol-profile", "strict_odva", "Protocol profile for encoding (strict_odva, legacy_compat, vendor name)")
	cmd.Flags().BoolVar(&flags.responsesOnly, "responses-only", false, "Emit response packets only (subset of supported services)")

	return cmd
}

func runEmitBytes(flags *emitBytesFlags) error {
	root, err := resolveCatalogRoot(flags.catalogRoot)
	if err != nil {
		return err
	}
	entries, err := ui.ListCatalogEntries(root)
	if err != nil {
		return fmt.Errorf("load catalog entries: %w", err)
	}

	keys := normalizeKeys(flags.catalogKeys)
	if !flags.allCatalog && len(keys) == 0 {
		return fmt.Errorf("required flag --catalog-key or --all not set")
	}

	selected := make([]ui.CatalogEntry, 0)
	if flags.allCatalog {
		selected = append(selected, entries...)
	} else {
		for _, key := range keys {
			entry := ui.FindCatalogEntry(entries, key)
			if entry == nil {
				return fmt.Errorf("catalog key %q not found", key)
			}
			selected = append(selected, *entry)
		}
	}

	prevProfile := cipclient.CurrentProtocolProfile()
	cipclient.SetProtocolProfile(resolveProtocolProfile(flags.profileName))
	defer cipclient.SetProtocolProfile(prevProfile)

	output := validation.NewBytesOutput()
	for _, entry := range selected {
		req, err := buildBaseRequest(entry)
		if err != nil {
			return fmt.Errorf("build catalog request %s: %w", entry.Key, err)
		}
		if flags.responsesOnly {
			if !supportsResponse(req) {
				continue
			}
			resp, err := buildResponse(req, entry.Payload.Params)
			if err != nil {
				return fmt.Errorf("build response %s: %w", entry.Key, err)
			}
			cipBytes, err := cipclient.EncodeCIPResponse(resp)
			if err != nil {
				return fmt.Errorf("encode CIP response %s: %w", entry.Key, err)
			}
			enipBytes := cipclient.BuildSendRRData(0x12345678, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, cipBytes)
			expect := buildResponseExpectation(entry, req)
			output.Packets = append(output.Packets, validation.BytesPacket{
				Expect:  expect,
				ENIPHex: fmt.Sprintf("%x", enipBytes),
			})
			continue
		}

		payloadType := strings.TrimSpace(entry.Payload.Type)
		result, err := cipclient.BuildServicePayload(req, cipclient.PayloadSpec{
			Type:   payloadType,
			Params: entry.Payload.Params,
		})
		if err != nil {
			params := mergePayloadParams(entry.Payload.Params, defaultPayloadParams(entry, req))
			result, err = cipclient.BuildServicePayload(req, cipclient.PayloadSpec{
				Type:   payloadType,
				Params: params,
			})
			if err != nil {
				return fmt.Errorf("build payload %s: %w", entry.Key, err)
			}
		}
		req.Payload = result.Payload
		if len(result.RawPath) > 0 {
			req.RawPath = result.RawPath
		}

		cipBytes, err := cipclient.EncodeCIPRequest(req)
		if err != nil {
			return fmt.Errorf("encode CIP request %s: %w", entry.Key, err)
		}
		enipBytes := cipclient.BuildSendRRData(0x12345678, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, cipBytes)
		expect := buildExpectationFromCatalog(entry, req)
		output.Packets = append(output.Packets, validation.BytesPacket{
			Expect:  expect,
			ENIPHex: fmt.Sprintf("%x", enipBytes),
		})
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal output: %w", err)
	}
	if flags.outputPath == "" {
		_, err = os.Stdout.Write(data)
		if err == nil {
			_, err = fmt.Fprintln(os.Stdout, "")
		}
		return err
	}
	if err := os.WriteFile(flags.outputPath, data, 0644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	fmt.Fprintf(os.Stdout, "Wrote %d packet(s) to %s\n", len(output.Packets), flags.outputPath)
	return nil
}

func normalizeKeys(values []string) []string {
	keys := make([]string, 0)
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				keys = append(keys, trimmed)
			}
		}
	}
	return keys
}

func resolveProtocolProfile(name string) cipclient.ProtocolProfile {
	name = strings.TrimSpace(strings.ToLower(name))
	switch name {
	case "strict_odva", "":
		return cipclient.StrictODVAProfile
	case "legacy_compat":
		return cipclient.LegacyCompatProfile
	default:
		if profile, ok := cipclient.VendorProfiles[name]; ok {
			return profile
		}
	}
	return cipclient.StrictODVAProfile
}

func buildExpectationFromCatalog(entry ui.CatalogEntry, req cipclient.CIPRequest) validation.PacketExpectation {
	payloadType := entry.Payload.Type
	if strings.TrimSpace(payloadType) == "" {
		payloadType = inferPayloadType(req)
	}
	shape := serviceShapeFromPayload(payloadType)
	if req.Path.Class == cipclient.CIPClassFileObject && req.Service == cipclient.CIPServiceClearFile {
		shape = validation.ServiceShapeNone
	}
	expect := validation.PacketExpectation{
		ID:           entry.Key + "/request",
		Outcome:      "valid",
		Direction:    "request",
		PacketType:   "explicit_request",
		ServiceShape: shape,
		TrafficMode:  "client_only",
		ExpectLayers: []string{"eth", "ip", "tcp", "enip", "cip"},
		ExpectENIP:   true,
		ExpectCPF:    true,
		ExpectCIP:    true,
	}
	if shape == validation.ServiceShapeRockwellTag || shape == validation.ServiceShapeRockwellTagFrag {
		expect.ExpectSymbol = true
		expect.ExpectCIPPath = false
	} else {
		expect.ExpectCIPPath = true
	}
	return expect
}

func buildResponseExpectation(entry ui.CatalogEntry, req cipclient.CIPRequest) validation.PacketExpectation {
	shape := responseShapeFromRequest(req)
	expect := validation.PacketExpectation{
		ID:           entry.Key + "/response",
		Outcome:      "valid",
		Direction:    "response",
		PacketType:   "explicit_response",
		ServiceShape: shape,
		TrafficMode:  "server_only",
		ExpectLayers: []string{"eth", "ip", "tcp", "enip", "cip"},
		ExpectENIP:   true,
		ExpectCPF:    true,
		ExpectCIP:    true,
		ExpectStatus: true,
	}
	return expect
}

func serviceShapeFromPayload(payloadType string) string {
	switch strings.ToLower(strings.TrimSpace(payloadType)) {
	case "forward_open":
		return validation.ServiceShapeForwardOpen
	case "forward_close":
		return validation.ServiceShapeForwardClose
	case "unconnected_send":
		return validation.ServiceShapeUnconnectedSend
	case "rockwell_tag":
		return validation.ServiceShapeRockwellTag
	case "rockwell_tag_fragmented":
		return validation.ServiceShapeRockwellTagFrag
	case "rockwell_template":
		return validation.ServiceShapeTemplate
	case "rockwell_pccc":
		return validation.ServiceShapePCCC
	case "file_object":
		return validation.ServiceShapeFileObject
	case "modbus_object":
		return validation.ServiceShapeModbus
	case "safety_reset":
		return validation.ServiceShapeSafetyReset
	default:
		return validation.ServiceShapeNone
	}
}

func responseShapeFromRequest(req cipclient.CIPRequest) string {
	switch req.Path.Class {
	case cipclient.CIPClassConnectionManager:
		switch req.Service {
		case cipclient.CIPServiceForwardOpen:
			return validation.ServiceShapeForwardOpen
		case cipclient.CIPServiceForwardClose:
			return validation.ServiceShapeForwardClose
		}
	case cipclient.CIPClassSymbolObject:
		switch req.Service {
		case cipclient.CIPServiceReadTag:
			return validation.ServiceShapeRead
		case cipclient.CIPServiceWriteTag:
			return validation.ServiceShapeNone
		}
	case cipclient.CIPClassModbus:
		return validation.ServiceShapeModbus
	case cipclient.CIPClassFileObject:
		if req.Service == cipclient.CIPServiceInitiateDownload {
			return validation.ServiceShapeFileObject
		}
	}
	return validation.ServiceShapeNone
}

func buildBaseRequest(entry ui.CatalogEntry) (cipclient.CIPRequest, error) {
	service, err := parseServiceValue(entry.Service)
	if err != nil {
		return cipclient.CIPRequest{}, err
	}
	classID, err := parseClassValue(entry.Class)
	if err != nil {
		return cipclient.CIPRequest{}, err
	}
	instanceID, err := parseUintValue(entry.Instance, 16)
	if err != nil {
		return cipclient.CIPRequest{}, err
	}
	attributeID := uint64(0)
	if entry.Attribute != "" {
		attributeID, err = parseUintValue(entry.Attribute, 16)
		if err != nil {
			return cipclient.CIPRequest{}, err
		}
	}
	return cipclient.CIPRequest{
		Service: cipclient.CIPServiceCode(service),
		Path: cipclient.CIPPath{
			Class:     uint16(classID),
			Instance:  uint16(instanceID),
			Attribute: uint16(attributeID),
			Name:      entry.Key,
		},
	}, nil
}

func supportsResponse(req cipclient.CIPRequest) bool {
	switch req.Path.Class {
	case cipclient.CIPClassConnectionManager:
		return req.Service == cipclient.CIPServiceForwardOpen || req.Service == cipclient.CIPServiceForwardClose
	case cipclient.CIPClassSymbolObject:
		return req.Service == cipclient.CIPServiceReadTag || req.Service == cipclient.CIPServiceWriteTag
	case cipclient.CIPClassModbus:
		switch req.Service {
		case 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50:
			return true
		}
	case cipclient.CIPClassFileObject:
		return req.Service == cipclient.CIPServiceInitiateDownload
	}
	return false
}

func buildResponse(req cipclient.CIPRequest, params map[string]any) (cipclient.CIPResponse, error) {
	profile := cipclient.CurrentProtocolProfile()
	order := profile.CIPByteOrder
	replyService := cipclient.CIPServiceCode(uint8(req.Service) | 0x80)
	payload, err := buildResponsePayload(req, params, order)
	if err != nil {
		return cipclient.CIPResponse{}, err
	}
	return cipclient.CIPResponse{
		Service: replyService,
		Path:    req.Path,
		Status:  0x00,
		Payload: payload,
	}, nil
}

func buildResponsePayload(req cipclient.CIPRequest, params map[string]any, order binary.ByteOrder) ([]byte, error) {
	switch req.Path.Class {
	case cipclient.CIPClassConnectionManager:
		if req.Service == cipclient.CIPServiceForwardOpen {
			payload := make([]byte, 17)
			order.PutUint32(payload[0:4], 0x12345678)
			order.PutUint32(payload[4:8], 0x9ABCDEF0)
			order.PutUint16(payload[8:10], 0x0001)
			order.PutUint16(payload[10:12], 0x0001)
			order.PutUint32(payload[12:16], 0x01020304)
			payload[16] = 0x03
			return payload, nil
		}
		if req.Service == cipclient.CIPServiceForwardClose {
			return nil, nil
		}
	case cipclient.CIPClassSymbolObject:
		if req.Service == cipclient.CIPServiceReadTag {
			value, _ := cipclient.EncodeCIPValue(cipclient.CIPTypeDINT, int32(0))
			payload := make([]byte, 2+len(value))
			order.PutUint16(payload[0:2], uint16(cipclient.CIPTypeDINT))
			copy(payload[2:], value)
			return payload, nil
		}
		if req.Service == cipclient.CIPServiceWriteTag {
			return nil, nil
		}
	case cipclient.CIPClassModbus:
		addr := uint16(getUintParam(params, "modbus_addr", 0))
		qty := uint16(getUintParam(params, "modbus_qty", 1))
		switch req.Service {
		case 0x4B, 0x4C:
			payload := []byte{0x01, 0x00}
			return append([]byte{byte(len(payload))}, payload...), nil
		case 0x4D, 0x4E:
			payload := []byte{0x00, 0x00}
			return append([]byte{byte(len(payload))}, payload...), nil
		case 0x4F, 0x50:
			payload := make([]byte, 4)
			order.PutUint16(payload[0:2], addr)
			order.PutUint16(payload[2:4], qty)
			return payload, nil
		}
	case cipclient.CIPClassFileObject:
		if req.Service == cipclient.CIPServiceInitiateDownload {
			payload := make([]byte, 12)
			order.PutUint32(payload[0:4], 512)
			order.PutUint32(payload[4:8], 100)
			order.PutUint32(payload[8:12], 128)
			return payload, nil
		}
	}
	return nil, fmt.Errorf("unsupported response payload for %s", req.Path)
}

func getUintParam(params map[string]any, key string, def uint64) uint64 {
	if params == nil {
		return def
	}
	value, ok := params[key]
	if !ok {
		return def
	}
	return coerceUintValue(value, def)
}

func coerceUintValue(value any, def uint64) uint64 {
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

func parseServiceValue(value string) (uint64, error) {
	if parsed, err := parseUintValue(value, 8); err == nil {
		return parsed, nil
	}
	if code, ok := cipclient.ParseServiceAlias(value); ok {
		return uint64(code), nil
	}
	return 0, fmt.Errorf("unknown service alias '%s'", value)
}

func parseClassValue(value string) (uint64, error) {
	if parsed, err := parseUintValue(value, 16); err == nil {
		return parsed, nil
	}
	if code, ok := cipclient.ParseClassAlias(value); ok {
		return uint64(code), nil
	}
	return 0, fmt.Errorf("unknown class alias '%s'", value)
}

func parseUintValue(input string, bits int) (uint64, error) {
	value, err := strconv.ParseUint(strings.TrimSpace(input), 0, bits)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric value '%s'", input)
	}
	return value, nil
}

func mergePayloadParams(base, defaults map[string]any) map[string]any {
	params := map[string]any{}
	for key, val := range defaults {
		params[key] = val
	}
	for key, val := range base {
		params[key] = val
	}
	return params
}

func defaultPayloadParams(entry ui.CatalogEntry, req cipclient.CIPRequest) map[string]any {
	params := map[string]any{}
	payloadType := entry.Payload.Type
	if strings.TrimSpace(payloadType) == "" {
		payloadType = inferPayloadType(req)
	}
	switch strings.ToLower(strings.TrimSpace(payloadType)) {
	case "forward_close":
		params["connection_id"] = uint64(0x11223344)
	case "unconnected_send":
		req := cipclient.CIPRequest{
			Service: cipclient.CIPServiceGetAttributeSingle,
			Path: cipclient.CIPPath{
				Class:     cipclient.CIPClassIdentityObject,
				Instance:  0x01,
				Attribute: 0x01,
			},
		}
		if encoded, err := cipclient.EncodeCIPRequest(req); err == nil {
			params["embedded_request_hex"] = encoded
		}
		params["route_slot"] = uint64(1)
	case "rockwell_pccc":
		params["pccc_hex"] = "0f00000000"
	case "modbus_object":
		switch req.Service {
		case 0x4F:
			params["modbus_qty"] = uint64(1)
			params["modbus_data_hex"] = "01"
		case 0x50:
			params["modbus_qty"] = uint64(1)
			params["modbus_data_hex"] = "0001"
		case 0x51:
			params["modbus_pdu_hex"] = "030000000001"
		}
	case "file_object":
		switch req.Service {
		case cipclient.CIPServiceInitiateUpload:
			params["file_size"] = uint64(1024)
		case cipclient.CIPServiceInitiateDownload:
			params["file_size"] = uint64(512)
			params["format_version"] = uint64(1)
			params["file_revision"] = uint64(1)
			params["file_name"] = "test.bin"
		case cipclient.CIPServiceInitiatePartialRead:
			params["file_offset"] = uint64(0)
			params["chunk"] = uint64(32)
		case cipclient.CIPServiceInitiatePartialWrite:
			params["file_offset"] = uint64(0)
			params["data_hex"] = "01020304"
		case cipclient.CIPServiceUploadTransfer:
			params["transfer_number"] = uint64(1)
		case cipclient.CIPServiceDownloadTransfer:
			params["transfer_number"] = uint64(1)
			params["transfer_type"] = uint64(1)
			params["data_hex"] = "0102"
		}
	}
	return params
}

func inferPayloadType(req cipclient.CIPRequest) string {
	switch req.Path.Class {
	case cipclient.CIPClassConnectionManager:
		switch req.Service {
		case cipclient.CIPServiceForwardOpen:
			return "forward_open"
		case cipclient.CIPServiceForwardClose:
			return "forward_close"
		case cipclient.CIPServiceUnconnectedSend:
			return "unconnected_send"
		}
	case cipclient.CIPClassSymbolObject:
		switch req.Service {
		case cipclient.CIPServiceReadTag, cipclient.CIPServiceWriteTag:
			return "rockwell_tag"
		case cipclient.CIPServiceReadTagFragmented, cipclient.CIPServiceWriteTagFragmented:
			return "rockwell_tag_fragmented"
		}
	case cipclient.CIPClassTemplateObject:
		if req.Service == cipclient.CIPServiceReadTag {
			return "rockwell_template"
		}
	case cipclient.CIPClassFileObject:
		return "file_object"
	case cipclient.CIPClassModbus:
		return "modbus_object"
	case cipclient.CIPClassSafetySupervisor, cipclient.CIPClassSafetyValidator:
		return "safety_reset"
	}
	if req.Service == cipclient.CIPServiceExecutePCCC && req.Path.Class == cipclient.CIPClassPCCCObject {
		return "rockwell_pccc"
	}
	return ""
}
