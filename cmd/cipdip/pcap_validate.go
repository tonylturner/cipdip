package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/validation"
)

type pcapValidateFlags struct {
	inputFile         string
	pcapDir           string
	generateTestPcaps bool
	outputDir         string
	verbose           bool
	json              bool
}

func newPcapValidateCmd() *cobra.Command {
	flags := &pcapValidateFlags{}

	cmd := &cobra.Command{
		Use:   "pcap-validate",
		Short: "Validate PCAPs with tshark",
		Long: `Validate ENIP/CIP PCAPs by running tshark and reporting
packet-level parse results. Optionally generate synthetic validation PCAPs.`,
		Example: `  # Validate a single PCAP
  cipdip pcap-validate --input pcaps/stress/ENIP.pcap

  # Validate all PCAPs under a directory
  cipdip pcap-validate --pcap-dir pcaps

  # Generate synthetic validation PCAPs and validate them
  cipdip pcap-validate --generate-test-pcaps --output pcaps/validation_generated`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if handleHelpArg(cmd, args) {
				return nil
			}
			if flags.inputFile == "" && len(args) > 0 {
				flags.inputFile = args[0]
			}
			return runPcapValidate(flags)
		},
	}

	cmd.Flags().StringVar(&flags.inputFile, "input", "", "Input PCAP file")
	cmd.Flags().StringVar(&flags.pcapDir, "pcap-dir", "", "Directory containing PCAP files")
	cmd.Flags().BoolVar(&flags.generateTestPcaps, "generate-test-pcaps", false, "Generate synthetic validation PCAPs")
	cmd.Flags().StringVar(&flags.outputDir, "output", "pcaps/validation_generated", "Output directory for generated PCAPs")
	cmd.Flags().BoolVar(&flags.verbose, "verbose", false, "Print per-packet tshark fields")
	cmd.Flags().BoolVar(&flags.json, "json", false, "Print raw tshark JSON output")

	return cmd
}

func runPcapValidate(flags *pcapValidateFlags) error {
	var pcaps []string
	switch {
	case flags.generateTestPcaps:
		generated, err := validation.GenerateValidationPCAPs(flags.outputDir)
		if err != nil {
			return fmt.Errorf("generate validation pcaps: %w", err)
		}
		pcaps = append(pcaps, generated...)
	case flags.inputFile != "":
		pcaps = append(pcaps, flags.inputFile)
	case flags.pcapDir != "":
		found, err := collectPcapFiles(flags.pcapDir)
		if err != nil {
			return err
		}
		pcaps = append(pcaps, found...)
	default:
		return fmt.Errorf("required flag --input or --pcap-dir not set")
	}

	validator := validation.NewWiresharkValidator("")
	totalFiles := 0
	totalPackets := 0
	totalInvalid := 0

	for _, pcapPath := range pcaps {
		var results []validation.ValidateResult
		var raw []byte
		var err error
		if flags.json {
			raw, results, err = validator.ValidatePCAPRaw(pcapPath)
		} else {
			results, err = validator.ValidatePCAP(pcapPath)
		}
		if err != nil {
			return fmt.Errorf("validate pcap %s: %w", pcapPath, err)
		}
		totalFiles++
		totalPackets += len(results)
		fileInvalid := 0
		for _, result := range results {
			if !result.Valid {
				fileInvalid++
			}
		}
		totalInvalid += fileInvalid

		fmt.Fprintf(os.Stdout, "%s: %d packets, %d invalid\n", pcapPath, len(results), fileInvalid)
		if flags.verbose {
			printVerboseResults(results)
		}
		if flags.json {
			if len(pcaps) > 1 {
				fmt.Fprintf(os.Stdout, "tshark JSON (%s):\n", pcapPath)
			}
			os.Stdout.Write(raw)
			if len(raw) > 0 && raw[len(raw)-1] != '\n' {
				fmt.Fprint(os.Stdout, "\n")
			}
		}
		if fileInvalid > 0 {
			for i, result := range results {
				if result.Valid {
					continue
				}
				fmt.Fprintf(os.Stdout, "  invalid #%d: %v %v\n", i+1, result.Errors, result.Warnings)
				break
			}
		}
	}

	fmt.Fprintf(os.Stdout, "Validated %d file(s): %d packets, %d invalid\n", totalFiles, totalPackets, totalInvalid)
	return nil
}

func printVerboseResults(results []validation.ValidateResult) {
	for i, result := range results {
		status := "invalid"
		if result.Valid {
			status = "valid"
		}
		ports := []string{}
		if val, ok := result.Fields["tcp.port"]; ok {
			ports = append(ports, "tcp="+val)
		}
		if val, ok := result.Fields["udp.port"]; ok {
			ports = append(ports, "udp="+val)
		}
		proto := result.Fields["frame.protocols"]
		fmt.Fprintf(os.Stdout, "  #%d %s ports=%s protocols=%s\n", i+1, status, strings.Join(ports, ","), proto)
		if len(result.Warnings) > 0 {
			fmt.Fprintf(os.Stdout, "    warnings: %s\n", strings.Join(result.Warnings, "; "))
		}
		if len(result.Errors) > 0 {
			fmt.Fprintf(os.Stdout, "    errors: %s\n", strings.Join(result.Errors, "; "))
		}
	}
}
