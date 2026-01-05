package main

import (
	"encoding/hex"
	"fmt"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/cipclient"
)

type pcapDumpFlags struct {
	inputFile   string
	serviceHex  string
	maxEntries  int
	showPayload bool
}

func newPcapDumpCmd() *cobra.Command {
	flags := &pcapDumpFlags{}

	cmd := &cobra.Command{
		Use:   "pcap-dump",
		Short: "Dump CIP service samples from a PCAP",
		Long: `Dump matching CIP packets from a PCAP by service code.

This is intended for targeted investigation of unknown services.`,
		Example: `  # Dump first 10 packets with service 0x51
  cipdip pcap-dump --input pcaps/stress/ENIP.pcap --service 0x51 --max 10`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if handleHelpArg(cmd, args) {
				return nil
			}
			if flags.inputFile == "" && len(args) > 0 {
				flags.inputFile = args[0]
			}
			if flags.inputFile == "" {
				return missingFlagError(cmd, "--input")
			}
			if flags.serviceHex == "" {
				return missingFlagError(cmd, "--service")
			}
			return runPcapDump(flags)
		},
	}

	cmd.Flags().StringVar(&flags.inputFile, "input", "", "Input PCAP file (required)")
	cmd.Flags().StringVar(&flags.serviceHex, "service", "", "CIP service code (hex, e.g. 0x51)")
	cmd.Flags().IntVar(&flags.maxEntries, "max", 10, "Maximum number of entries to dump")
	cmd.Flags().BoolVar(&flags.showPayload, "payload", false, "Include a hex dump of the CIP payload")

	return cmd
}

func runPcapDump(flags *pcapDumpFlags) error {
	service, err := parseHexByte(flags.serviceHex)
	if err != nil {
		return fmt.Errorf("parse service code: %w", err)
	}

	packets, err := cipclient.ExtractENIPFromPCAP(flags.inputFile)
	if err != nil {
		return err
	}

	count := 0
	for idx, pkt := range packets {
		cipData, _, dataType := cipclient.ExtractCIPFromENIPPacket(pkt)
		if dataType != "unconnected" || len(cipData) == 0 {
			continue
		}
		info, err := protocol.ParseCIPMessage(cipData)
		if err != nil {
			continue
		}
		if info.BaseService != service {
			continue
		}
		count++
		fmt.Fprintf(os.Stdout, "Entry %d (packet index %d):\n", count, idx)
		fmt.Fprintf(os.Stdout, "  Service: 0x%02X\n", info.BaseService)
		fmt.Fprintf(os.Stdout, "  Response: %v\n", info.IsResponse)
		if info.GeneralStatus != nil {
			fmt.Fprintf(os.Stdout, "  General Status: 0x%02X\n", *info.GeneralStatus)
		}
		if info.PathInfo.HasClassSegment {
			fmt.Fprintf(os.Stdout, "  Path: class=0x%04X instance=0x%04X attribute=0x%04X\n",
				info.PathInfo.Path.Class, info.PathInfo.Path.Instance, info.PathInfo.Path.Attribute)
		}
		if flags.showPayload {
			fmt.Fprintf(os.Stdout, "  CIP Payload: %s\n", hex.EncodeToString(cipData))
		}
		fmt.Fprint(os.Stdout, "\n")
		if flags.maxEntries > 0 && count >= flags.maxEntries {
			break
		}
	}

	if count == 0 {
		fmt.Fprintf(os.Stdout, "No matching CIP service 0x%02X found.\n", service)
	}
	return nil
}

func parseHexByte(value string) (uint8, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(strings.ToLower(value), "0x")
	parsed, err := strconv.ParseUint(value, 16, 8)
	if err != nil {
		return 0, err
	}
	return uint8(parsed), nil
}
