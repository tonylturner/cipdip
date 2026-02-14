package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/report"
	"github.com/tonylturner/cipdip/internal/validation"
	"github.com/tonylturner/cipdip/internal/validation/fixtures"
)

type validateBytesFlags struct {
	inputFile        string
	verbose          bool
	reportJSON       string
	mode             string
	negativePolicy   string
	expertPolicy     string
	conversationMode string
	profile          string
	tsharkPath       string
	noTshark         bool
	includeRawHex    bool
}

func newValidateBytesCmd() *cobra.Command {
	flags := &validateBytesFlags{}

	cmd := &cobra.Command{
		Use:   "validate-bytes",
		Short: "Validate ENIP bytes using Grade A rules",
		Long: `Validate ENIP request bytes emitted by cipclient without network I/O.
Input is a JSON payload produced by the emit-bytes command.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if handleHelpArg(cmd, args) {
				return nil
			}
			if flags.inputFile == "" && len(args) > 0 {
				flags.inputFile = args[0]
			}
			return runValidateBytes(flags)
		},
	}

	cmd.Flags().StringVar(&flags.inputFile, "input", "", "Input JSON file from emit-bytes (required)")
	cmd.Flags().BoolVar(&flags.verbose, "verbose", false, "Print per-packet validation details")
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

func runValidateBytes(flags *validateBytesFlags) error {
	if flags.inputFile == "" {
		return fmt.Errorf("required flag --input not set")
	}
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

	data, err := os.ReadFile(flags.inputFile)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	var payload validation.BytesOutput
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("parse input JSON: %w", err)
	}
	if len(payload.Packets) == 0 {
		return fmt.Errorf("no packets in input")
	}

	packets := make([]fixtures.ValidationPacket, 0, len(payload.Packets))
	expectations := make([]validation.PacketExpectation, 0, len(payload.Packets))
	for i, pkt := range payload.Packets {
		decoded, err := validation.DecodeHexBytes(pkt.ENIPHex)
		if err != nil {
			return fmt.Errorf("decode packet %d: %w", i+1, err)
		}
		expect := ensureExpectationDefaults(pkt.Expect, i)
		packets = append(packets, fixtures.ValidationPacket{Data: decoded, Expect: expect})
		expectations = append(expectations, expect)
	}

	tempDir, err := os.MkdirTemp("", "cipdip_validate_bytes_*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	pcapPath := filepath.Join(tempDir, "emit_bytes.pcap")
	if err := fixtures.WriteENIPPCAP(pcapPath, packets); err != nil {
		return fmt.Errorf("write pcap: %w", err)
	}
	manifestPath := validation.ValidationManifestPath(pcapPath)
	if err := validation.WriteValidationManifest(manifestPath, validation.ValidationManifest{
		PCAP:    filepath.Base(pcapPath),
		Packets: expectations,
	}); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	validator := validation.NewWiresharkValidator(flags.tsharkPath)
	var results []validation.ValidateResult
	if mode == "internal-only" {
		results, err = validation.ValidatePCAPInternalOnly(pcapPath)
	} else {
		results, err = validator.ValidatePCAP(pcapPath)
	}
	if err != nil {
		return fmt.Errorf("validate pcap: %w", err)
	}
	if mode == "tshark-only" {
		for i := range results {
			results[i].Internal = nil
		}
	}

	manifest, err := validation.LoadValidationManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}
	pairingMap := validation.BuildPairingResults(*manifest, results)
	evaluations := make([]validation.PacketEvaluation, 0, len(results))
	for i, expect := range manifest.Packets {
		baseID := strings.TrimSuffix(strings.TrimSuffix(expect.ID, "/request"), "/response")
		eval := validation.EvaluatePacket(expect, results[i], flags.negativePolicy, flags.expertPolicy, flags.conversationMode, flags.profile, pairingMap[baseID])
		eval.PacketIndex = i + 1
		evaluations = append(evaluations, eval)
	}

	if flags.verbose {
		printVerboseEvaluations(results, evaluations, flags.includeRawHex)
	}

	validationReport := report.ValidationReport{
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		CIPDIPVersion:    version,
		CIPDIPCommit:     commit,
		CIPDIPDate:       date,
		ExpertPolicy:     flags.expertPolicy,
		ConversationMode: flags.conversationMode,
		Profile:          flags.profile,
		PCAPs: []report.PCAPReport{{
			PCAP:         filepath.Base(pcapPath),
			PacketCount:  len(results),
			Pass:         true,
			InvalidCount: 0,
			Packets:      evaluations,
		}},
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
	fmt.Fprintf(os.Stdout, "Validated %d packet(s)\n", len(results))
	return nil
}

func ensureExpectationDefaults(expect validation.PacketExpectation, idx int) validation.PacketExpectation {
	if strings.TrimSpace(expect.ID) == "" {
		expect.ID = fmt.Sprintf("packet_%d/request", idx+1)
	}
	if strings.TrimSpace(expect.Direction) == "" {
		expect.Direction = "request"
	}
	if strings.TrimSpace(expect.Outcome) == "" {
		expect.Outcome = "valid"
	}
	if strings.TrimSpace(expect.PacketType) == "" {
		expect.PacketType = "explicit_request"
	}
	if strings.TrimSpace(expect.TrafficMode) == "" {
		expect.TrafficMode = "client_only"
	}
	if len(expect.ExpectLayers) == 0 {
		expect.ExpectLayers = []string{"eth", "ip", "tcp", "enip", "cip"}
	}
	if !expect.ExpectENIP {
		expect.ExpectENIP = true
	}
	if !expect.ExpectCPF {
		expect.ExpectCPF = true
	}
	if !expect.ExpectCIP {
		expect.ExpectCIP = true
	}
	if expect.Direction == "response" {
		expect.ExpectStatus = true
	}
	if !expect.ExpectSymbol && !expect.ExpectCIPPath && expect.Direction != "response" {
		expect.ExpectCIPPath = true
	}
	return expect
}
