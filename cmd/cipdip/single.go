package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/ui"
)

type singleFlags struct {
	ip            string
	port          int
	service       string
	classID       string
	instanceID    string
	attributeID   string
	payloadHex    string
	payloadType   string
	payloadParams []string
	tag           string
	tagPath       string
	elements      string
	offset        string
	dataType      string
	value         string
	fileOffset    string
	chunk         string
	modbusFC      string
	modbusAddr    string
	modbusQty     string
	modbusDataHex string
	pcccHex       string
	routeSlot     string
	ucmmWrap      string
	catalogRoot   string
	catalogKey    string
	dryRun        bool
	mutate        string
	mutateSeed    int64
}

func newSingleCmd() *cobra.Command {
	flags := &singleFlags{}

	cmd := &cobra.Command{
		Use:   "single",
		Short: "Send a single CIP service request (one-off check)",
		Long: `Send a single CIP service request without editing YAML configs.
Use this for quick firewall/DPI checks on a specific service/class/instance/attribute.`,
		Example: `  # Get_Attribute_Single (0x0E) for Identity Vendor ID
  cipdip single --ip 10.0.0.50 --service 0x0E --class 0x01 --instance 0x01 --attribute 0x01

  # Execute PCCC (0x4B) to PCCC object (class 0x67)
  cipdip single --ip 10.0.0.50 --service 0x4B --class 0x0067 --instance 0x0001 --attribute 0x0000`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if handleHelpArg(cmd, args) {
				return nil
			}
			if flags.ip == "" {
				return missingFlagError(cmd, "--ip")
			}
			return runSingle(flags)
		},
	}

	cmd.Flags().StringVar(&flags.ip, "ip", "", "Target CIP adapter IP address (required)")
	cmd.Flags().IntVar(&flags.port, "port", 44818, "CIP TCP port (default 44818)")
	cmd.Flags().StringVar(&flags.service, "service", "", "CIP service code (hex/decimal) or alias (required)")
	cmd.Flags().StringVar(&flags.classID, "class", "", "CIP class ID (hex/decimal) or alias (required)")
	cmd.Flags().StringVar(&flags.instanceID, "instance", "", "CIP instance ID (hex or decimal, required)")
	cmd.Flags().StringVar(&flags.attributeID, "attribute", "0x0000", "CIP attribute ID (hex or decimal, default 0)")
	cmd.Flags().StringVar(&flags.payloadHex, "payload-hex", "", "Optional hex payload for the request body")
	cmd.Flags().StringVar(&flags.payloadType, "payload-type", "", "Payload type to build (forward_open, unconnected_send, rockwell_tag, file_object, modbus_object, rockwell_pccc)")
	cmd.Flags().StringArrayVar(&flags.payloadParams, "payload-param", nil, "Payload param key=value (repeatable)")
	cmd.Flags().StringVar(&flags.tag, "tag", "", "Symbolic tag name (e.g., MyTag)")
	cmd.Flags().StringVar(&flags.tagPath, "tag-path", "", "Symbolic tag path (e.g., Program:Main.MyTag)")
	cmd.Flags().StringVar(&flags.elements, "elements", "", "Element count for tag operations")
	cmd.Flags().StringVar(&flags.offset, "offset", "", "Byte offset for fragmented tag operations")
	cmd.Flags().StringVar(&flags.dataType, "type", "", "CIP data type (BOOL, INT, DINT, REAL, 0x00C4)")
	cmd.Flags().StringVar(&flags.value, "value", "", "Value for write/tag payloads (comma-separated allowed)")
	cmd.Flags().StringVar(&flags.fileOffset, "file-offset", "", "File offset for file object operations")
	cmd.Flags().StringVar(&flags.chunk, "chunk", "", "Chunk size for file object operations")
	cmd.Flags().StringVar(&flags.modbusFC, "modbus-fc", "", "Modbus function code for passthrough payload")
	cmd.Flags().StringVar(&flags.modbusAddr, "modbus-addr", "", "Modbus start address")
	cmd.Flags().StringVar(&flags.modbusQty, "modbus-qty", "", "Modbus quantity")
	cmd.Flags().StringVar(&flags.modbusDataHex, "modbus-data-hex", "", "Modbus data bytes (hex)")
	cmd.Flags().StringVar(&flags.pcccHex, "pccc-hex", "", "Execute PCCC payload hex")
	cmd.Flags().StringVar(&flags.routeSlot, "route-slot", "", "UCMM route slot (backplane port 1)")
	cmd.Flags().StringVar(&flags.ucmmWrap, "ucmm-wrap", "", "Catalog key for embedded UCMM request")
	cmd.Flags().StringVar(&flags.catalogRoot, "catalog-root", "", "Workspace root containing catalogs/ for catalog-key resolution")
	cmd.Flags().StringVar(&flags.catalogKey, "catalog-key", "", "Catalog key to populate service/class/instance/attribute")
	cmd.Flags().BoolVar(&flags.dryRun, "dry-run", false, "Print constructed CIP request bytes and exit")
	cmd.Flags().StringVar(&flags.mutate, "mutate", "", "Mutate payload (missing_fields, wrong_length, invalid_offsets, wrong_datatype, flip_bits)")
	cmd.Flags().Int64Var(&flags.mutateSeed, "mutate-seed", 0, "Seed for payload mutation")

	return cmd
}

func runSingle(flags *singleFlags) error {
	entry, err := resolveCatalogEntry(flags)
	if err != nil {
		return err
	}

	serviceInput := firstNonEmpty(flags.service, entry.Service)
	classInput := firstNonEmpty(flags.classID, entry.Class)
	instanceInput := firstNonEmpty(flags.instanceID, entry.Instance)
	attributeInput := firstNonEmpty(flags.attributeID, entry.Attribute)

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

	req := cipclient.CIPRequest{
		Service: cipclient.CIPServiceCode(serviceCode),
		Path: cipclient.CIPPath{
			Class:     uint16(classID),
			Instance:  uint16(instanceID),
			Attribute: uint16(attributeID),
			Name:      "single",
		},
	}
	req, err = applySinglePayload(req, entry, flags)
	if err != nil {
		return err
	}
	if flags.dryRun {
		return printCIPRequest(req)
	}

	client := cipclient.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Connect(ctx, flags.ip, flags.port); err != nil {
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
	if code, ok := cipclient.ParseServiceAlias(input); ok {
		return uint64(code), nil
	}
	return 0, fmt.Errorf("unknown service alias '%s'", input)
}

func parseClassInput(input string) (uint64, error) {
	if value, err := parseUint(input, 16); err == nil {
		return value, nil
	}
	if code, ok := cipclient.ParseClassAlias(input); ok {
		return uint64(code), nil
	}
	return 0, fmt.Errorf("unknown class alias '%s'", input)
}

func parseUint(input string, bits int) (uint64, error) {
	value, err := strconv.ParseUint(strings.TrimSpace(input), 0, bits)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric value '%s'", input)
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
	Payload    ui.CatalogPayload
	PayloadHex string
}

func resolveCatalogEntry(flags *singleFlags) (catalogEntry, error) {
	if flags.catalogKey == "" {
		return catalogEntry{}, nil
	}
	root, err := resolveCatalogRoot(flags.catalogRoot)
	if err != nil {
		return catalogEntry{}, err
	}
	entries, err := ui.ListCatalogEntries(root)
	if err != nil {
		return catalogEntry{}, fmt.Errorf("load catalog entries: %w", err)
	}
	entry := ui.FindCatalogEntry(entries, flags.catalogKey)
	if entry == nil {
		return catalogEntry{}, fmt.Errorf("catalog key %q not found", flags.catalogKey)
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

func resolveCatalogRoot(root string) (string, error) {
	if root != "" {
		return root, nil
	}
	if _, err := os.Stat(filepath.Join("workspace", "catalogs")); err == nil {
		return "workspace", nil
	}
	if _, err := os.Stat("catalogs"); err == nil {
		return ".", nil
	}
	return "", fmt.Errorf("catalog root not found (use --catalog-root)")
}

func applySinglePayload(req cipclient.CIPRequest, entry catalogEntry, flags *singleFlags) (cipclient.CIPRequest, error) {
	if flags.payloadHex != "" {
		payload, err := parseHexPayload(flags.payloadHex)
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

	payloadType := firstNonEmpty(flags.payloadType, entry.Payload.Type)
	payloadParams := buildPayloadParams(entry, flags)
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
	if flags.mutate != "" {
		req.Payload = cipclient.ApplyPayloadMutation(req.Payload, cipclient.PayloadMutation{
			Kind: flags.mutate,
			Seed: flags.mutateSeed,
		})
	}
	return req, nil
}

func buildPayloadParams(entry catalogEntry, flags *singleFlags) map[string]any {
	params := map[string]any{}
	for key, value := range entry.Payload.Params {
		params[key] = value
	}
	for _, pair := range flags.payloadParams {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			params[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	if flags.tag != "" {
		params["tag"] = flags.tag
	}
	if flags.tagPath != "" {
		params["tag_path"] = flags.tagPath
	}
	if flags.elements != "" {
		params["elements"] = flags.elements
	}
	if flags.offset != "" {
		params["offset"] = flags.offset
	}
	if flags.dataType != "" {
		params["type"] = flags.dataType
	}
	if flags.value != "" {
		params["value"] = flags.value
	}
	if flags.fileOffset != "" {
		params["file_offset"] = flags.fileOffset
	}
	if flags.chunk != "" {
		params["chunk"] = flags.chunk
	}
	if flags.modbusFC != "" {
		params["modbus_fc"] = flags.modbusFC
	}
	if flags.modbusAddr != "" {
		params["modbus_addr"] = flags.modbusAddr
	}
	if flags.modbusQty != "" {
		params["modbus_qty"] = flags.modbusQty
	}
	if flags.modbusDataHex != "" {
		params["modbus_data_hex"] = flags.modbusDataHex
	}
	if flags.pcccHex != "" {
		params["pccc_hex"] = flags.pcccHex
	}
	if flags.routeSlot != "" {
		params["route_slot"] = flags.routeSlot
	}

	if flags.ucmmWrap != "" {
		root, err := resolveCatalogRoot(flags.catalogRoot)
		if err == nil {
			entries, err := ui.ListCatalogEntries(root)
			if err == nil {
				if wrap := ui.FindCatalogEntry(entries, flags.ucmmWrap); wrap != nil {
					embeddedReq, err := buildCatalogRequest(*wrap)
					if err == nil {
						if encoded, err := cipclient.EncodeCIPRequest(embeddedReq); err == nil {
							params["embedded_request_hex"] = encoded
						}
					}
				}
			}
		}
		params["ucmm_wrap"] = flags.ucmmWrap
	}
	return params
}

func buildCatalogRequest(entry ui.CatalogEntry) (cipclient.CIPRequest, error) {
	service, err := parseServiceInput(entry.Service)
	if err != nil {
		return cipclient.CIPRequest{}, err
	}
	classID, err := parseClassInput(entry.Class)
	if err != nil {
		return cipclient.CIPRequest{}, err
	}
	instanceID, err := parseUint(entry.Instance, 16)
	if err != nil {
		return cipclient.CIPRequest{}, err
	}
	attributeID := uint64(0)
	if entry.Attribute != "" {
		attributeID, err = parseUint(entry.Attribute, 16)
		if err != nil {
			return cipclient.CIPRequest{}, err
		}
	}
	req := cipclient.CIPRequest{
		Service: cipclient.CIPServiceCode(service),
		Path: cipclient.CIPPath{
			Class:     uint16(classID),
			Instance:  uint16(instanceID),
			Attribute: uint16(attributeID),
			Name:      entry.Key,
		},
	}
	if entry.PayloadHex != "" {
		payload, err := parseHexPayload(entry.PayloadHex)
		if err != nil {
			return cipclient.CIPRequest{}, err
		}
		req.Payload = payload
		return req, nil
	}
	result, err := cipclient.BuildServicePayload(req, cipclient.PayloadSpec{
		Type:   entry.Payload.Type,
		Params: entry.Payload.Params,
	})
	if err != nil {
		return cipclient.CIPRequest{}, err
	}
	req.Payload = result.Payload
	if len(result.RawPath) > 0 {
		req.RawPath = result.RawPath
	}
	return req, nil
}

func printCIPRequest(req cipclient.CIPRequest) error {
	encoded, err := cipclient.EncodeCIPRequest(req)
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
