package app

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/pcap"
)

type PCAPDumpOptions struct {
	InputFile   string
	ServiceHex  string
	MaxEntries  int
	ShowPayload bool
}

func RunPCAPDump(opts PCAPDumpOptions) error {
	service, err := parseHexByte(opts.ServiceHex)
	if err != nil {
		return fmt.Errorf("parse service code: %w", err)
	}

	packets, err := pcap.ExtractENIPFromPCAP(opts.InputFile)
	if err != nil {
		return err
	}

	count := 0
	for idx, pkt := range packets {
		cipData, _, dataType := pcap.ExtractCIPFromENIPPacket(pkt)
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
		if opts.ShowPayload {
			fmt.Fprintf(os.Stdout, "  CIP Payload: %s\n", hex.EncodeToString(cipData))
		}
		fmt.Fprint(os.Stdout, "\n")
		if opts.MaxEntries > 0 && count >= opts.MaxEntries {
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
