package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/app"
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
		Short: "Send a single CIP service request (DEPRECATED: use 'catalog test')",
		Long: `DEPRECATED: Use 'cipdip catalog test <key>' instead.

Send a single CIP service request without editing YAML configs.
Use this for quick firewall/DPI checks on a specific service/class/instance/attribute.

Migration examples:
  OLD: cipdip single --ip 10.0.0.50 --service 0x0E --class 0x01 --instance 0x01 --attribute 0x01
  NEW: cipdip catalog test identity.vendor_id --ip 10.0.0.50`,
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
	cmd.Flags().StringVar(&flags.attributeID, "attribute", "", "CIP attribute ID (hex or decimal)")
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
	if flags.service == "" && flags.catalogKey == "" {
		return fmt.Errorf("required flag --service or --catalog-key not set")
	}
	if flags.classID == "" && flags.catalogKey == "" {
		return fmt.Errorf("required flag --class or --catalog-key not set")
	}
	if flags.instanceID == "" && flags.catalogKey == "" {
		return fmt.Errorf("required flag --instance or --catalog-key not set")
	}
	return app.RunSingle(app.SingleOptions{
		IP:            flags.ip,
		Port:          flags.port,
		Service:       flags.service,
		ClassID:       flags.classID,
		InstanceID:    flags.instanceID,
		AttributeID:   flags.attributeID,
		PayloadHex:    flags.payloadHex,
		PayloadType:   flags.payloadType,
		PayloadParams: flags.payloadParams,
		Tag:           flags.tag,
		TagPath:       flags.tagPath,
		Elements:      flags.elements,
		Offset:        flags.offset,
		DataType:      flags.dataType,
		Value:         flags.value,
		FileOffset:    flags.fileOffset,
		Chunk:         flags.chunk,
		ModbusFC:      flags.modbusFC,
		ModbusAddr:    flags.modbusAddr,
		ModbusQty:     flags.modbusQty,
		ModbusDataHex: flags.modbusDataHex,
		PCCCHex:       flags.pcccHex,
		RouteSlot:     flags.routeSlot,
		UCMMWrap:      flags.ucmmWrap,
		CatalogRoot:   flags.catalogRoot,
		CatalogKey:    flags.catalogKey,
		DryRun:        flags.dryRun,
		Mutate:        flags.mutate,
		MutateSeed:    flags.mutateSeed,
	})
}
