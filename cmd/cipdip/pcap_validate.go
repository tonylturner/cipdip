package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

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
	reportJSON        string
	mode              string
	negativePolicy    string
	tsharkPath        string
	noTshark          bool
	includeRawHex     bool
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
	cmd.Flags().StringVar(&flags.reportJSON, "report-json", "", "Write validation report JSON to file")
	cmd.Flags().StringVar(&flags.mode, "mode", "structural", "Validation mode: structural, tshark-only, internal-only")
	cmd.Flags().StringVar(&flags.negativePolicy, "negative-policy", "tshark", "Negative validation policy: tshark, internal, either")
	cmd.Flags().StringVar(&flags.tsharkPath, "tshark", "", "Path to tshark binary")
	cmd.Flags().BoolVar(&flags.noTshark, "no-tshark", false, "Disable tshark (internal-only validation)")
	cmd.Flags().BoolVar(&flags.includeRawHex, "include-raw-hex", false, "Include raw ENIP hex in verbose output")

	return cmd
}

func runPcapValidate(flags *pcapValidateFlags) error {
	mode := strings.ToLower(strings.TrimSpace(flags.mode))
	if flags.noTshark {
		mode = "internal-only"
	}
	switch mode {
	case "structural", "tshark-only", "internal-only":
	default:
		return fmt.Errorf("invalid mode %q (expected structural, tshark-only, internal-only)", flags.mode)
	}

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

	validator := validation.NewWiresharkValidator(flags.tsharkPath)
	totalFiles := 0
	totalPackets := 0
	totalInvalid := 0
	report := validation.ValidationReport{
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		CIPDIPVersion: version,
		CIPDIPCommit:  commit,
		CIPDIPDate:    date,
	}
	if mode != "internal-only" {
		if tsharkPath, err := validation.ResolveTsharkPath(flags.tsharkPath); err == nil {
			report.TsharkPath = tsharkPath
		}
		if tsharkVersion, err := validation.GetTsharkVersion(flags.tsharkPath); err == nil {
			report.TsharkVersion = tsharkVersion
		}
	}

	for _, pcapPath := range pcaps {
		var results []validation.ValidateResult
		var raw []byte
		var err error
		if mode == "internal-only" {
			results, err = validation.ValidatePCAPInternalOnly(pcapPath)
		} else if flags.json {
			raw, results, err = validator.ValidatePCAPRaw(pcapPath)
		} else {
			results, err = validator.ValidatePCAP(pcapPath)
		}
		if err != nil {
			return fmt.Errorf("validate pcap %s: %w", pcapPath, err)
		}

		if mode == "tshark-only" {
			for i := range results {
				results[i].Internal = nil
			}
		}

		manifest, err := validation.LoadValidationManifest(validation.ValidationManifestPath(pcapPath))
		if err != nil {
			return fmt.Errorf("load validation manifest: %w", err)
		}
		evaluations := []validation.PacketEvaluation{}
		if manifest != nil {
			if len(manifest.Packets) != len(results) {
				return fmt.Errorf("validation manifest packet count mismatch for %s: manifest=%d results=%d", pcapPath, len(manifest.Packets), len(results))
			}
			for i, expect := range manifest.Packets {
				eval := validation.EvaluatePacket(expect, results[i], flags.negativePolicy)
				eval.PacketIndex = i + 1
				evaluations = append(evaluations, eval)
			}
		}

		fileInvalid := 0
		if len(evaluations) > 0 {
			for _, eval := range evaluations {
				if !eval.Pass {
					fileInvalid++
				}
			}
		} else {
			for _, result := range results {
				if result.Malformed || len(result.Errors) > 0 {
					fileInvalid++
				}
			}
		}

		totalFiles++
		totalPackets += len(results)
		totalInvalid += fileInvalid

		fmt.Fprintf(os.Stdout, "%s: %d packets, %d invalid\n", pcapPath, len(results), fileInvalid)
		if flags.verbose {
			if len(evaluations) > 0 {
				printVerboseEvaluations(results, evaluations, flags.includeRawHex)
			} else {
				printVerboseResults(results)
			}
		}
		if flags.json && mode != "internal-only" {
			if len(pcaps) > 1 {
				fmt.Fprintf(os.Stdout, "tshark JSON (%s):\n", pcapPath)
			}
			os.Stdout.Write(raw)
			if len(raw) > 0 && raw[len(raw)-1] != '\n' {
				fmt.Fprint(os.Stdout, "\n")
			}
		}
		if fileInvalid > 0 && len(evaluations) == 0 {
			for i, result := range results {
				if !(result.Malformed || len(result.Errors) > 0) {
					continue
				}
				fmt.Fprintf(os.Stdout, "  invalid #%d: %v %v\n", i+1, result.Errors, result.Warnings)
				break
			}
		}

		report.PCAPs = append(report.PCAPs, validation.PCAPReport{
			PCAP:         pcapPath,
			PacketCount:  len(results),
			Pass:         fileInvalid == 0,
			InvalidCount: fileInvalid,
			Packets:      evaluations,
		})
	}

	fmt.Fprintf(os.Stdout, "Validated %d file(s): %d packets, %d invalid\n", totalFiles, totalPackets, totalInvalid)
	if flags.reportJSON != "" {
		if err := writeReportJSON(flags.reportJSON, report); err != nil {
			return err
		}
	}
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

func printVerboseEvaluations(results []validation.ValidateResult, evals []validation.PacketEvaluation, includeRawHex bool) {
	for i, eval := range evals {
		result := results[i]
		status := "FAIL"
		if eval.Pass {
			status = "PASS"
		}
		fmt.Fprintf(os.Stdout, "  #%d %s test=%s dir=%s\n", i+1, status, eval.Expected.ID, eval.Expected.Direction)
		if len(result.Layers) > 0 {
			fmt.Fprintf(os.Stdout, "    layers: %s\n", strings.Join(result.Layers, ":"))
		}
		if len(result.ExpertMessages) > 0 || result.Malformed {
			fmt.Fprintf(os.Stdout, "    tshark: malformed=%t experts=%d\n", result.Malformed, len(result.ExpertMessages))
			if len(result.ExpertMessages) > 0 {
				fmt.Fprintf(os.Stdout, "    tshark-expert: %s\n", strings.Join(result.ExpertMessages, "; "))
			}
		}
		fmt.Fprintf(os.Stdout, "    enip: command=%s length=%s session=%s status=%s\n",
			result.Fields["enip.command"], result.Fields["enip.length"], result.Fields["enip.session"], result.Fields["enip.status"])
		if val := result.Fields["cpf.item_count"]; val != "" {
			fmt.Fprintf(os.Stdout, "    cpf: items=%s\n", val)
		}
		if val := result.Fields["cip.service"]; val != "" {
			fmt.Fprintf(os.Stdout, "    cip: service=%s class=%s instance=%s attribute=%s symbol=%s\n",
				val, result.Fields["cip.path.class"], result.Fields["cip.path.instance"], result.Fields["cip.path.attribute"], result.Fields["cip.path.symbol"])
		}
		if result.Internal != nil && len(result.Internal.CIPData) > 0 {
			fmt.Fprintf(os.Stdout, "    svc-data: shape=%s payload_len=%d\n", eval.Expected.ServiceShape, internalPayloadLength(result, eval))
		}
		if includeRawHex && result.Internal != nil && len(result.Internal.CIPData) > 0 {
			fmt.Fprintf(os.Stdout, "    cip-hex: %X\n", result.Internal.CIPData)
		}
		for _, scenario := range eval.Scenarios {
			if !scenario.Pass {
				fmt.Fprintf(os.Stdout, "    failed: %s %s\n", scenario.Name, scenario.Details)
			}
		}
	}
}

func internalPayloadLength(result validation.ValidateResult, eval validation.PacketEvaluation) int {
	if result.Internal == nil || len(result.Internal.CIPData) == 0 {
		return 0
	}
	if eval.Expected.Direction == "response" {
		resp, err := validation.DecodeResponseForReport(result.Internal.CIPData)
		if err != nil {
			return 0
		}
		return len(resp.Payload)
	}
	req, err := validation.DecodeRequestForReport(result.Internal.CIPData)
	if err != nil {
		return 0
	}
	return len(req.Payload)
}

func writeReportJSON(path string, report validation.ValidationReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal validation report: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write validation report: %w", err)
	}
	return nil
}
