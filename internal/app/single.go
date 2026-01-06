package app

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	cipclient "github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
)

type SingleOptions struct {
	IP            string
	Port          int
	Service       string
	ClassID       string
	InstanceID    string
	AttributeID   string
	PayloadHex    string
	PayloadType   string
	PayloadParams []string
	Tag           string
	TagPath       string
	Elements      string
	Offset        string
	DataType      string
	Value         string
	FileOffset    string
	Chunk         string
	ModbusFC      string
	ModbusAddr    string
	ModbusQty     string
	ModbusDataHex string
	PCCCHex       string
	RouteSlot     string
	UCMMWrap      string
	CatalogRoot   string
	CatalogKey    string
	DryRun        bool
	Mutate        string
	MutateSeed    int64
}

func RunSingle(opts SingleOptions) error {
	entry, err := resolveCatalogEntry(opts)
	if err != nil {
		return err
	}

	serviceInput := firstNonEmpty(opts.Service, entry.Service)
	classInput := firstNonEmpty(opts.ClassID, entry.Class)
	instanceInput := firstNonEmpty(opts.InstanceID, entry.Instance)
	attributeInput := firstNonEmpty(opts.AttributeID, entry.Attribute)

	if serviceInput == "" {
		return fmt.Errorf("required flag --service or --catalog-key not set")
	}
	if classInput == "" {
		return fmt.Errorf("required flag --class or --catalog-key not set")
	}
	if instanceInput == "" {
		return fmt.Errorf("required flag --instance or --catalog-key not set")
	}

	serviceCode, err := parseServiceInput(serviceInput)
	if err != nil {
		return fmt.Errorf("parse service: %w", err)
	}
	classID, err := parseClassInput(classInput)
	if err != nil {
		return fmt.Errorf("parse class: %w", err)
	}
	instanceID, err := parseUint(instanceInput, 16)
	if err != nil {
		return fmt.Errorf("parse instance: %w", err)
	}
	attributeID := uint64(0)
	if attributeInput != "" {
		attributeID, err = parseUint(attributeInput, 16)
		if err != nil {
			return fmt.Errorf("parse attribute: %w", err)
		}
	}

	req := protocol.CIPRequest{
		Service: protocol.CIPServiceCode(serviceCode),
		Path: protocol.CIPPath{
			Class:     uint16(classID),
			Instance:  uint16(instanceID),
			Attribute: uint16(attributeID),
			Name:      "single",
		},
	}
	req, err = applySinglePayload(req, entry, opts)
	if err != nil {
		return err
	}
	if opts.DryRun {
		return printCIPRequest(req)
	}

	client := cipclient.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Connect(ctx, opts.IP, opts.Port); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Disconnect(ctx)

	start := time.Now()
	resp, err := client.InvokeService(ctx, req)
	rtt := time.Since(start).Seconds() * 1000

	if err != nil {
		return fmt.Errorf("invoke: %w", err)
	}

	fmt.Fprintf(os.Stdout, "CIP Response: status=0x%02X payload=%d bytes RTT=%.2fms\n", resp.Status, len(resp.Payload), rtt)
	return nil
}

func parseServiceInput(input string) (uint64, error) {
	if value, err := parseUint(input, 8); err == nil {
		return value, nil
	}
	if code, ok := spec.ParseServiceAlias(input); ok {
		return uint64(code), nil
	}
	return 0, fmt.Errorf("unknown service alias '%s'", input)
}

func parseClassInput(input string) (uint64, error) {
	if value, err := parseUint(input, 16); err == nil {
		return value, nil
	}
	if code, ok := spec.ParseClassAlias(input); ok {
		return uint64(code), nil
	}
	return 0, fmt.Errorf("unknown class alias '%s'", input)
}

func parseUint(input string, bits int) (uint64, error) {
	value, err := parseUintValue(input, bits)
	if err != nil {
		return 0, err
	}
	return value, nil
}

func parseHexPayload(input string) ([]byte, error) {
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

type catalogEntry struct {
	Service    string
	Class      string
	Instance   string
	Attribute  string
	Payload    CatalogPayload
	PayloadHex string
}

func resolveCatalogEntry(opts SingleOptions) (catalogEntry, error) {
	if opts.CatalogKey == "" {
		return catalogEntry{}, nil
	}
	root, err := ResolveCatalogRoot(opts.CatalogRoot)
	if err != nil {
		return catalogEntry{}, err
	}
	entries, err := ListCatalogEntries(root)
	if err != nil {
		return catalogEntry{}, fmt.Errorf("load catalog entries: %w", err)
	}
	entry := FindCatalogEntry(entries, opts.CatalogKey)
	if entry == nil {
		return catalogEntry{}, fmt.Errorf("catalog key %q not found", opts.CatalogKey)
	}
	return catalogEntry{
		Service:    entry.Service,
		Class:      entry.Class,
		Instance:   entry.Instance,
		Attribute:  entry.Attribute,
		Payload:    entry.Payload,
		PayloadHex: entry.PayloadHex,
	}, nil
}

func applySinglePayload(req protocol.CIPRequest, entry catalogEntry, opts SingleOptions) (protocol.CIPRequest, error) {
	if opts.PayloadHex != "" {
		payload, err := parseHexPayload(opts.PayloadHex)
		if err != nil {
			return req, fmt.Errorf("parse payload: %w", err)
		}
		req.Payload = payload
		return req, nil
	}
	if entry.PayloadHex != "" {
		payload, err := parseHexPayload(entry.PayloadHex)
		if err != nil {
			return req, fmt.Errorf("parse payload: %w", err)
		}
		req.Payload = payload
		return req, nil
	}

	payloadType := firstNonEmpty(opts.PayloadType, entry.Payload.Type)
	payloadParams := buildPayloadParams(entry, opts)
	if payloadType == "" && len(payloadParams) == 0 {
		return req, nil
	}
	result, err := cipclient.BuildServicePayload(req, cipclient.PayloadSpec{
		Type:   payloadType,
		Params: payloadParams,
	})
	if err != nil {
		return req, err
	}
	req.Payload = result.Payload
	if len(result.RawPath) > 0 {
		req.RawPath = result.RawPath
	}
	if opts.Mutate != "" {
		req.Payload = cipclient.ApplyPayloadMutation(req.Payload, cipclient.PayloadMutation{
			Kind: opts.Mutate,
			Seed: opts.MutateSeed,
		})
	}
	return req, nil
}

func buildPayloadParams(entry catalogEntry, opts SingleOptions) map[string]any {
	params := map[string]any{}
	for key, value := range entry.Payload.Params {
		params[key] = value
	}
	for _, pair := range opts.PayloadParams {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			params[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	if opts.Tag != "" {
		params["tag"] = opts.Tag
	}
	if opts.TagPath != "" {
		params["tag_path"] = opts.TagPath
	}
	if opts.Elements != "" {
		params["elements"] = opts.Elements
	}
	if opts.Offset != "" {
		params["offset"] = opts.Offset
	}
	if opts.DataType != "" {
		params["type"] = opts.DataType
	}
	if opts.Value != "" {
		params["value"] = opts.Value
	}
	if opts.FileOffset != "" {
		params["file_offset"] = opts.FileOffset
	}
	if opts.Chunk != "" {
		params["chunk"] = opts.Chunk
	}
	if opts.ModbusFC != "" {
		params["modbus_fc"] = opts.ModbusFC
	}
	if opts.ModbusAddr != "" {
		params["modbus_addr"] = opts.ModbusAddr
	}
	if opts.ModbusQty != "" {
		params["modbus_qty"] = opts.ModbusQty
	}
	if opts.ModbusDataHex != "" {
		params["modbus_data_hex"] = opts.ModbusDataHex
	}
	if opts.PCCCHex != "" {
		params["pccc_hex"] = opts.PCCCHex
	}
	if opts.RouteSlot != "" {
		params["route_slot"] = opts.RouteSlot
	}

	if opts.UCMMWrap != "" {
		root, err := ResolveCatalogRoot(opts.CatalogRoot)
		if err == nil {
			entries, err := ListCatalogEntries(root)
			if err == nil {
				if wrap := FindCatalogEntry(entries, opts.UCMMWrap); wrap != nil {
					embeddedReq, err := buildCatalogRequest(*wrap)
					if err == nil {
						if encoded, err := protocol.EncodeCIPRequest(embeddedReq); err == nil {
							params["embedded_request_hex"] = encoded
						}
					}
				}
			}
		}
		params["ucmm_wrap"] = opts.UCMMWrap
	}
	return params
}

func buildCatalogRequest(entry CatalogEntry) (protocol.CIPRequest, error) {
	service, err := parseServiceInput(entry.Service)
	if err != nil {
		return protocol.CIPRequest{}, err
	}
	classID, err := parseClassInput(entry.Class)
	if err != nil {
		return protocol.CIPRequest{}, err
	}
	instanceID, err := parseUint(entry.Instance, 16)
	if err != nil {
		return protocol.CIPRequest{}, err
	}
	attributeID := uint64(0)
	if entry.Attribute != "" {
		attributeID, err = parseUint(entry.Attribute, 16)
		if err != nil {
			return protocol.CIPRequest{}, err
		}
	}
	req := protocol.CIPRequest{
		Service: protocol.CIPServiceCode(service),
		Path: protocol.CIPPath{
			Class:     uint16(classID),
			Instance:  uint16(instanceID),
			Attribute: uint16(attributeID),
			Name:      entry.Key,
		},
	}
	if entry.PayloadHex != "" {
		payload, err := parseHexPayload(entry.PayloadHex)
		if err != nil {
			return protocol.CIPRequest{}, err
		}
		req.Payload = payload
		return req, nil
	}
	result, err := cipclient.BuildServicePayload(req, cipclient.PayloadSpec{
		Type:   entry.Payload.Type,
		Params: entry.Payload.Params,
	})
	if err != nil {
		return protocol.CIPRequest{}, err
	}
	req.Payload = result.Payload
	if len(result.RawPath) > 0 {
		req.RawPath = result.RawPath
	}
	return req, nil
}

func printCIPRequest(req protocol.CIPRequest) error {
	encoded, err := protocol.EncodeCIPRequest(req)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	fmt.Fprintf(os.Stdout, "CIP Request: service=0x%02X class=0x%04X instance=0x%04X attribute=0x%04X\n",
		uint8(req.Service), req.Path.Class, req.Path.Instance, req.Path.Attribute)
	fmt.Fprintf(os.Stdout, "Payload: %d bytes\n", len(req.Payload))
	fmt.Fprintf(os.Stdout, "Bytes: %s\n", hex.EncodeToString(encoded))
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
