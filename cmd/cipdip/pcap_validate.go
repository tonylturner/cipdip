package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/pcap"
	"github.com/tonylturner/cipdip/internal/report"
	"github.com/tonylturner/cipdip/internal/validation"
	"github.com/tonylturner/cipdip/internal/validation/fixtures"
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
	expertPolicy      string
	conversationMode  string
	profile           string
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
	cmd.Flags().StringVar(&flags.expertPolicy, "expert-policy", "balanced", "Expert policy: strict, balanced, off")
	cmd.Flags().StringVar(&flags.conversationMode, "conversation-mode", "basic", "Conversation mode: off, basic, strict")
	cmd.Flags().StringVar(&flags.profile, "profile", "client_wire", "Validation profile: client_wire, server_wire, pairing")
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
	switch strings.ToLower(strings.TrimSpace(flags.expertPolicy)) {
	case "strict", "balanced", "off":
	default:
		return fmt.Errorf("invalid expert-policy %q (expected strict, balanced, off)", flags.expertPolicy)
	}
	switch strings.ToLower(strings.TrimSpace(flags.conversationMode)) {
	case "off", "basic", "strict":
	default:
		return fmt.Errorf("invalid conversation-mode %q (expected off, basic, strict)", flags.conversationMode)
	}
	switch strings.ToLower(strings.TrimSpace(flags.profile)) {
	case "client_wire", "server_wire", "pairing":
	default:
		return fmt.Errorf("invalid profile %q (expected client_wire, server_wire, pairing)", flags.profile)
	}

	var pcaps []string
	switch {
	case flags.generateTestPcaps:
		generated, err := fixtures.GenerateValidationPCAPs(flags.outputDir)
		if err != nil {
			return fmt.Errorf("generate validation pcaps: %w", err)
		}
		pcaps = append(pcaps, generated...)
	case flags.inputFile != "":
		pcaps = append(pcaps, flags.inputFile)
	case flags.pcapDir != "":
		found, err := pcap.CollectPcapFiles(flags.pcapDir)
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
	totalPassClean := 0
	totalPassExpected := 0
	totalPassTransport := 0
	totalPassWarn := 0
	totalExpectedInvalid := 0
	totalGradePass := 0
	totalGradeFail := 0
	totalGradeExpected := 0
	validationReport := report.ValidationReport{
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		CIPDIPVersion:    version,
		CIPDIPCommit:     commit,
		CIPDIPDate:       date,
		ExpertPolicy:     flags.expertPolicy,
		ConversationMode: flags.conversationMode,
		Profile:          flags.profile,
	}
	if mode != "internal-only" {
		if tsharkPath, err := validation.ResolveTsharkPath(flags.tsharkPath); err == nil {
			validationReport.TsharkPath = tsharkPath
		}
		if tsharkVersion, err := validation.GetTsharkVersion(flags.tsharkPath); err == nil {
			validationReport.TsharkVersion = tsharkVersion
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
			pairingMap := validation.BuildPairingResults(*manifest, results)
			for i, expect := range manifest.Packets {
				baseID := strings.TrimSuffix(strings.TrimSuffix(expect.ID, "/request"), "/response")
				eval := validation.EvaluatePacket(expect, results[i], flags.negativePolicy, flags.expertPolicy, flags.conversationMode, flags.profile, pairingMap[baseID])
				eval.PacketIndex = i + 1
				evaluations = append(evaluations, eval)
			}
		}

		fileInvalid := 0
		filePassClean := 0
		filePassExpected := 0
		filePassTransport := 0
		filePassWarn := 0
		fileExpectedInvalid := 0
		fileGradePass := 0
		fileGradeFail := 0
		fileGradeExpected := 0
		if len(evaluations) > 0 {
			for _, eval := range evaluations {
				switch eval.PassCategory {
				case "pass_clean":
					filePassClean++
				case "pass_with_expected_experts":
					filePassExpected++
				case "pass_with_transport_warnings":
					filePassTransport++
				case "pass_with_warnings":
					filePassWarn++
				case "expected_invalid_passed":
					fileExpectedInvalid++
				}
				switch eval.Grade {
				case validation.GradePass:
					fileGradePass++
				case validation.GradeFail:
					fileGradeFail++
				case validation.GradeExpectedInvalid:
					fileGradeExpected++
				}
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
		totalPassClean += filePassClean
		totalPassExpected += filePassExpected
		totalPassTransport += filePassTransport
		totalPassWarn += filePassWarn
		totalExpectedInvalid += fileExpectedInvalid
		totalGradePass += fileGradePass
		totalGradeFail += fileGradeFail
		totalGradeExpected += fileGradeExpected

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

		validationReport.PCAPs = append(validationReport.PCAPs, report.PCAPReport{
			PCAP:         pcapPath,
			PacketCount:  len(results),
			Pass:         fileInvalid == 0,
			InvalidCount: fileInvalid,
			Packets:      evaluations,
		})
	}

	fmt.Fprintf(os.Stdout, "Validated %d file(s): %d packets, %d invalid\n", totalFiles, totalPackets, totalInvalid)
	fmt.Fprintf(os.Stdout, "Summary: pass_clean=%d pass_with_expected_experts=%d pass_with_transport_warnings=%d pass_with_warnings=%d expected_invalid_passed=%d fail=%d\n",
		totalPassClean, totalPassExpected, totalPassTransport, totalPassWarn, totalExpectedInvalid, totalInvalid)
	if totalGradePass+totalGradeFail+totalGradeExpected > 0 {
		fmt.Fprintf(os.Stdout, "Grade A: A_pass=%d A_fail=%d expected_invalid=%d\n",
			totalGradePass, totalGradeFail, totalGradeExpected)
	}
	reportPath, err := resolveReportPath(flags.reportJSON)
	if err != nil {
		return err
	}
	if reportPath != "" {
		if err := report.WriteJSONFile(reportPath, validationReport); err != nil {
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
		if eval.Grade != "" {
			fmt.Fprintf(os.Stdout, "    grade: %s\n", eval.Grade)
		}
		if len(eval.FailureLabels) > 0 {
			fmt.Fprintf(os.Stdout, "    failures: %s\n", strings.Join(eval.FailureLabels, ", "))
		}
		if len(result.ExpertMessages) > 0 || result.Malformed {
			fmt.Fprintf(os.Stdout, "    tshark: malformed=%t experts=%d\n", result.Malformed, len(result.ExpertMessages))
			if len(result.ExpertMessages) > 0 {
				fmt.Fprintf(os.Stdout, "    tshark-expert: %s\n", strings.Join(result.ExpertMessages, "; "))
			}
		}
		if len(result.Experts) > 0 {
			fmt.Fprintf(os.Stdout, "    experts:\n")
			for _, expert := range result.Experts {
				layer := expert.Layer
				if layer == "" {
					layer = "unknown"
				}
				group := expert.Group
				if group != "" {
					group = " group=" + group
				}
				fmt.Fprintf(os.Stdout, "      - %s [%s]%s %s\n", layer, expert.Severity, group, expert.Message)
			}
		}
		if eval.ExpertSummary.ExpectedCount > 0 || eval.ExpertSummary.UnexpectedCount > 0 || eval.ExpertSummary.TransportCount > 0 {
			fmt.Fprintf(os.Stdout, "    experts_expected=%d experts_unexpected=%d experts_transport=%d\n",
				eval.ExpertSummary.ExpectedCount, eval.ExpertSummary.UnexpectedCount, eval.ExpertSummary.TransportCount)
		}
		fmt.Fprintf(os.Stdout, "    enip: command=%s length=%s session=%s status=%s\n",
			result.Fields["enip.command"], result.Fields["enip.length"], result.Fields["enip.session"], result.Fields["enip.status"])
		if val := result.Fields["cpf.item_count"]; val != "" {
			fmt.Fprintf(os.Stdout, "    cpf: items=%s\n", val)
		}
		if len(result.CPFItems) > 0 {
			items := make([]string, 0, len(result.CPFItems))
			for _, item := range result.CPFItems {
				items = append(items, fmt.Sprintf("%s:%d", item.TypeID, item.Length))
			}
			fmt.Fprintf(os.Stdout, "    cpf-items: %s\n", strings.Join(items, ", "))
		}
		if val := result.Fields["cip.service"]; val != "" {
			fmt.Fprintf(os.Stdout, "    cip: service=%s class=%s instance=%s attribute=%s symbol=%s\n",
				val, result.Fields["cip.path.class"], result.Fields["cip.path.instance"], result.Fields["cip.path.attribute"], result.Fields["cip.path.symbol"])
		}
		if eval.Expected.ExpectCIPPath && result.Internal != nil && len(result.Internal.CIPData) > 0 {
			req, err := validation.DecodeRequestForReport(result.Internal.CIPData)
			if err == nil {
				fmt.Fprintf(os.Stdout, "    cip(internal): class=0x%04X instance=0x%04X attribute=0x%04X symbol=%s\n",
					req.Path.Class, req.Path.Instance, req.Path.Attribute, req.Path.Name)
			}
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
		if eval.Pairing != nil && eval.Pairing.Required {
			status := "pass"
			if !eval.Pairing.Pass {
				status = "fail"
			}
			fmt.Fprintf(os.Stdout, "    pairing: %s %s\n", status, eval.Pairing.Reason)
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
