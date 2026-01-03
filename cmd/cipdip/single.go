package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/cipclient"
)

type singleFlags struct {
	ip          string
	port        int
	service     string
	classID     string
	instanceID  string
	attributeID string
	payloadHex  string
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
			if flags.service == "" {
				return missingFlagError(cmd, "--service")
			}
			if flags.classID == "" {
				return missingFlagError(cmd, "--class")
			}
			if flags.instanceID == "" {
				return missingFlagError(cmd, "--instance")
			}
			return runSingle(flags)
		},
	}

	cmd.Flags().StringVar(&flags.ip, "ip", "", "Target CIP adapter IP address (required)")
	cmd.Flags().IntVar(&flags.port, "port", 44818, "CIP TCP port (default 44818)")
	cmd.Flags().StringVar(&flags.service, "service", "", "CIP service code (hex or decimal, required)")
	cmd.Flags().StringVar(&flags.classID, "class", "", "CIP class ID (hex or decimal, required)")
	cmd.Flags().StringVar(&flags.instanceID, "instance", "", "CIP instance ID (hex or decimal, required)")
	cmd.Flags().StringVar(&flags.attributeID, "attribute", "0x0000", "CIP attribute ID (hex or decimal, default 0)")
	cmd.Flags().StringVar(&flags.payloadHex, "payload-hex", "", "Optional hex payload for the request body")

	return cmd
}

func runSingle(flags *singleFlags) error {
	serviceCode, err := parseUint(flags.service, 8)
	if err != nil {
		return fmt.Errorf("parse service: %w", err)
	}
	classID, err := parseUint(flags.classID, 16)
	if err != nil {
		return fmt.Errorf("parse class: %w", err)
	}
	instanceID, err := parseUint(flags.instanceID, 16)
	if err != nil {
		return fmt.Errorf("parse instance: %w", err)
	}
	attributeID, err := parseUint(flags.attributeID, 16)
	if err != nil {
		return fmt.Errorf("parse attribute: %w", err)
	}
	payload, err := parseHexPayload(flags.payloadHex)
	if err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}

	client := cipclient.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Connect(ctx, flags.ip, flags.port); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Disconnect(ctx)

	req := cipclient.CIPRequest{
		Service: cipclient.CIPServiceCode(serviceCode),
		Path: cipclient.CIPPath{
			Class:     uint16(classID),
			Instance:  uint16(instanceID),
			Attribute: uint16(attributeID),
			Name:      "single",
		},
		Payload: payload,
	}

	start := time.Now()
	resp, err := client.InvokeService(ctx, req)
	rtt := time.Since(start).Seconds() * 1000

	if err != nil {
		return fmt.Errorf("invoke: %w", err)
	}

	fmt.Fprintf(os.Stdout, "CIP Response: status=0x%02X payload=%d bytes RTT=%.2fms\n", resp.Status, len(resp.Payload), rtt)
	return nil
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
