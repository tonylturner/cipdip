package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

type pcapClassifyFlags struct {
	pcapDir          string
	tsharkPath       string
	outCSV           string
	outTxt           string
	maxTcpRst        int
	maxTcpRetrans    int
	maxTcpLostSeg    int
	maxCipErrorRate  float64
	maxMalformed     int
	maxExpertErrors  int
}

type expertSummary struct {
	errors   int
	warnings int
	notes    int
	chats    int
}

type pcapClassifyRow struct {
	file              string
	path              string
	enipHits          int
	cipHits           int
	listIdentity      int
	udp2222IO         int
	malformed         int
	expertErrors      int
	expertWarnings    int
	badChecksums      int
	tcpRst            int
	tcpRetrans        int
	tcpLostSeg        int
	cipResponses      int
	cipErrorResponses int
	cipErrorRate      float64
	integrity         string
	integrityReasons  string
	flags             string
}

func newPcapClassifyCmd() *cobra.Command {
	flags := &pcapClassifyFlags{}

	cmd := &cobra.Command{
		Use:   "pcap-classify",
		Short: "Classify PCAPs with tshark-derived integrity signals",
		Long: `Classify PCAPs using tshark filters for ENIP/CIP presence,
transport noise, malformed frames, and CIP error rates.`,
		Example: `  # Classify all PCAPs under ./pcaps
  cipdip pcap-classify --pcap-dir pcaps`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPcapClassify(flags)
		},
	}

	cmd.Flags().StringVar(&flags.pcapDir, "pcap-dir", "pcaps", "Directory containing PCAP files")
	cmd.Flags().StringVar(&flags.tsharkPath, "tshark", "", "Optional path to tshark (defaults to PATH or Windows install)")
	cmd.Flags().StringVar(&flags.outCSV, "out-csv", "cip_pcap_summary.csv", "CSV output path")
	cmd.Flags().StringVar(&flags.outTxt, "out-txt", "cip_pcap_summary.txt", "Summary output path")
	cmd.Flags().IntVar(&flags.maxTcpRst, "max-tcp-rst", 5, "RST threshold for transport noise")
	cmd.Flags().IntVar(&flags.maxTcpRetrans, "max-tcp-retrans", 500, "Retransmission threshold for transport noise")
	cmd.Flags().IntVar(&flags.maxTcpLostSeg, "max-tcp-lostseg", 5, "Lost segment threshold for transport noise")
	cmd.Flags().Float64Var(&flags.maxCipErrorRate, "max-cip-error-rate", 0.05, "CIP error rate threshold")
	cmd.Flags().IntVar(&flags.maxMalformed, "max-malformed", 0, "Malformed frame threshold")
	cmd.Flags().IntVar(&flags.maxExpertErrors, "max-expert-errors", 0, "tshark expert error threshold")

	return cmd
}

func runPcapClassify(flags *pcapClassifyFlags) error {
	pcaps, err := collectPcapFiles(flags.pcapDir)
	if err != nil {
		return err
	}
	if len(pcaps) == 0 {
		return fmt.Errorf("no .pcap/.pcapng files found under %s", flags.pcapDir)
	}

	tsharkPath, err := resolveTsharkPath(flags.tsharkPath)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Found %d capture(s) under %s\n", len(pcaps), flags.pcapDir)
	fmt.Fprintf(os.Stdout, "Using tshark: %s\n", tsharkPath)
	fmt.Fprintf(os.Stdout, "Noise thresholds: RST>%d, Retrans>%d, LostSeg>%d\n",
		flags.maxTcpRst, flags.maxTcpRetrans, flags.maxTcpLostSeg)
	fmt.Fprintf(os.Stdout, "Fuzz thresholds: CipErrorRate>%.2f, Malformed>%d, ExpertErrors>%d\n\n",
		flags.maxCipErrorRate, flags.maxMalformed, flags.maxExpertErrors)

	rows := make([]pcapClassifyRow, 0, len(pcaps))
	for _, pcapPath := range pcaps {
		row, err := classifyPcap(tsharkPath, pcapPath, flags)
		if err != nil {
			return err
		}
		rows = append(rows, row)
	}

	if err := writePcapClassifyCSV(flags.outCSV, rows); err != nil {
		return err
	}
	if err := writePcapClassifySummary(flags.outTxt, flags.outCSV, flags.pcapDir, tsharkPath, rows); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\nWrote:\n  %s\n  %s\n", flags.outCSV, flags.outTxt)
	return nil
}

func resolveTsharkPath(explicit string) (string, error) {
	if explicit != "" {
		if filepath.Base(explicit) == explicit {
			path, err := exec.LookPath(explicit)
			if err != nil {
				return "", fmt.Errorf("tshark not found in PATH: %w", err)
			}
			return path, nil
		}
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("tshark path not found: %w", err)
		}
		return explicit, nil
	}

	if path, err := exec.LookPath("tshark"); err == nil {
		return path, nil
	}
	if runtime.GOOS == "windows" {
		defaultWin := filepath.Join(os.Getenv("ProgramFiles"), "Wireshark", "tshark.exe")
		if defaultWin != "Wireshark\\tshark.exe" {
			if _, err := os.Stat(defaultWin); err == nil {
				return defaultWin, nil
			}
		}
	}

	return "", fmt.Errorf("tshark not found in PATH and default locations")
}

func classifyPcap(tsharkPath, pcapPath string, flags *pcapClassifyFlags) (pcapClassifyRow, error) {
	enipHits, err := countTshark(tsharkPath, pcapPath, "enip || tcp.port==44818 || udp.port==44818 || udp.port==2222")
	if err != nil {
		return pcapClassifyRow{}, err
	}
	cipHits, err := countTshark(tsharkPath, pcapPath, "cip")
	if err != nil {
		return pcapClassifyRow{}, err
	}
	listId, err := countTshark(tsharkPath, pcapPath, "enip.command==0x0063")
	if err != nil {
		return pcapClassifyRow{}, err
	}
	io2222, err := countTshark(tsharkPath, pcapPath, "udp.port==2222")
	if err != nil {
		return pcapClassifyRow{}, err
	}
	malformed, err := countTshark(tsharkPath, pcapPath, "_ws.malformed")
	if err != nil {
		return pcapClassifyRow{}, err
	}
	expert, err := getExpertSummary(tsharkPath, pcapPath)
	if err != nil {
		return pcapClassifyRow{}, err
	}
	tcpRst, err := countTshark(tsharkPath, pcapPath, "tcp.flags.reset==1")
	if err != nil {
		return pcapClassifyRow{}, err
	}
	tcpRetrans, err := countTshark(tsharkPath, pcapPath, "tcp.analysis.retransmission")
	if err != nil {
		return pcapClassifyRow{}, err
	}
	tcpLostSeg, err := countTshark(tsharkPath, pcapPath, "tcp.analysis.lost_segment")
	if err != nil {
		return pcapClassifyRow{}, err
	}
	cipResponses, err := countTshark(tsharkPath, pcapPath, "cip.genstat")
	if err != nil {
		return pcapClassifyRow{}, err
	}
	cipErrorResp, err := countTshark(tsharkPath, pcapPath, "cip.genstat != 0")
	if err != nil {
		return pcapClassifyRow{}, err
	}
	badChecksum, err := countTsharkOptional(tsharkPath, pcapPath, "ip.checksum_bad==1 || tcp.checksum_bad==1 || udp.checksum_bad==1")
	if err != nil {
		return pcapClassifyRow{}, err
	}

	cipErrorRate := 0.0
	if cipResponses > 0 {
		cipErrorRate = math.Round((float64(cipErrorResp)/float64(cipResponses))*10000) / 10000
	}

	integrity := "PROTOCOL_NORMAL"
	integrityReasons := make([]string, 0)
	if enipHits == 0 && cipHits == 0 {
		integrity = "NOT_CIP_ENIP"
		integrityReasons = append(integrityReasons, "no_enip_or_cip_detected")
	} else if malformed > 0 || expert.errors > 0 {
		integrity = "PROTOCOL_ANOMALOUS"
		if malformed > 0 {
			integrityReasons = append(integrityReasons, fmt.Sprintf("malformed=%d", malformed))
		}
		if expert.errors > 0 {
			integrityReasons = append(integrityReasons, fmt.Sprintf("expertErrors=%d", expert.errors))
		}
	} else if tcpRst > flags.maxTcpRst || tcpRetrans > flags.maxTcpRetrans || tcpLostSeg > flags.maxTcpLostSeg {
		integrity = "TRANSPORT_NOISY"
		if tcpRst > flags.maxTcpRst {
			integrityReasons = append(integrityReasons, fmt.Sprintf("tcpRst=%d", tcpRst))
		}
		if tcpRetrans > flags.maxTcpRetrans {
			integrityReasons = append(integrityReasons, fmt.Sprintf("retrans=%d", tcpRetrans))
		}
		if tcpLostSeg > flags.maxTcpLostSeg {
			integrityReasons = append(integrityReasons, fmt.Sprintf("lostSeg=%d", tcpLostSeg))
		}
	}

	flagsList := make([]string, 0)
	if malformed > flags.maxMalformed {
		flagsList = append(flagsList, "deformation:malformed")
	}
	if expert.errors > flags.maxExpertErrors {
		flagsList = append(flagsList, "deformation:expert_error")
	}
	if badChecksum > 0 {
		flagsList = append(flagsList, "deformation:bad_checksum")
	}
	if cipResponses > 0 && cipErrorRate > flags.maxCipErrorRate {
		flagsList = append(flagsList, "fuzz_or_invalid:high_cip_error_rate")
	}
	if tcpRetrans > (flags.maxTcpRetrans * 10) {
		flagsList = append(flagsList, "ops_bad:extreme_retrans")
	}
	if tcpLostSeg > (flags.maxTcpLostSeg * 5) {
		flagsList = append(flagsList, "ops_bad:extreme_loss")
	}
	if tcpRst > (flags.maxTcpRst * 10) {
		flagsList = append(flagsList, "ops_bad:extreme_resets")
	}
	if listId > 0 {
		flagsList = append(flagsList, "has_discovery:list_identity")
	}
	if io2222 > 0 {
		flagsList = append(flagsList, "has_io:udp2222")
	}

	flagText := strings.Join(flagsList, ",")
	reasonText := strings.Join(integrityReasons, "; ")

	name := filepath.Base(pcapPath)
	switch {
	case flagText != "" && reasonText != "":
		fmt.Fprintf(os.Stdout, "[%s] %s :: %s :: %s\n", integrity, name, reasonText, flagText)
	case reasonText != "":
		fmt.Fprintf(os.Stdout, "[%s] %s :: %s\n", integrity, name, reasonText)
	case flagText != "":
		fmt.Fprintf(os.Stdout, "[%s] %s :: %s\n", integrity, name, flagText)
	default:
		fmt.Fprintf(os.Stdout, "[%s] %s\n", integrity, name)
	}

	return pcapClassifyRow{
		file:              name,
		path:              pcapPath,
		enipHits:          enipHits,
		cipHits:           cipHits,
		listIdentity:      listId,
		udp2222IO:         io2222,
		malformed:         malformed,
		expertErrors:      expert.errors,
		expertWarnings:    expert.warnings,
		badChecksums:      badChecksum,
		tcpRst:            tcpRst,
		tcpRetrans:        tcpRetrans,
		tcpLostSeg:        tcpLostSeg,
		cipResponses:      cipResponses,
		cipErrorResponses: cipErrorResp,
		cipErrorRate:      cipErrorRate,
		integrity:         integrity,
		integrityReasons:  reasonText,
		flags:             flagText,
	}, nil
}

func countTshark(tsharkPath, pcapPath, filter string) (int, error) {
	cmd := exec.Command(tsharkPath, "-r", pcapPath, "-Y", filter)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				return countLines(stdout.Bytes()), nil
			}
		}
		return 0, fmt.Errorf("tshark filter failed (%s): %s", filter, strings.TrimSpace(stderr.String()))
	}
	return countLines(stdout.Bytes()), nil
}

func countTsharkOptional(tsharkPath, pcapPath, filter string) (int, error) {
	cmd := exec.Command(tsharkPath, "-r", pcapPath, "-Y", filter)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		errText := strings.TrimSpace(stderr.String())
		if strings.Contains(errText, "not a valid protocol or protocol field") {
			return 0, nil
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				return countLines(stdout.Bytes()), nil
			}
		}
		return 0, fmt.Errorf("tshark filter failed (%s): %s", filter, errText)
	}
	return countLines(stdout.Bytes()), nil
}

func countLines(data []byte) int {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return 0
	}
	return bytes.Count(trimmed, []byte{'\n'}) + 1
}

func getExpertSummary(tsharkPath, pcapPath string) (expertSummary, error) {
	cmd := exec.Command(tsharkPath, "-r", pcapPath, "-q", "-z", "expert")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return expertSummary{}, fmt.Errorf("tshark expert failed: %s", strings.TrimSpace(stderr.String()))
	}

	text := stdout.String()
	return expertSummary{
		errors:   findExpertCount(text, `(?im)^\s*Error\s+(\d+)\s*$`),
		warnings: findExpertCount(text, `(?im)^\s*Warn(?:ing)?\s+(\d+)\s*$`),
		notes:    findExpertCount(text, `(?im)^\s*Note\s+(\d+)\s*$`),
		chats:    findExpertCount(text, `(?im)^\s*Chat\s+(\d+)\s*$`),
	}, nil
}

func findExpertCount(text, pattern string) int {
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(text)
	if len(match) != 2 {
		return 0
	}
	val, err := strconv.Atoi(match[1])
	if err != nil {
		return 0
	}
	return val
}

func writePcapClassifyCSV(path string, rows []pcapClassifyRow) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return fmt.Errorf("create csv directory: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create csv file: %w", err)
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	header := []string{
		"File", "Path", "ENIP_Hits", "CIP_Hits", "ListIdentity", "UDP2222_IO",
		"Malformed", "ExpertErrors", "ExpertWarnings", "BadChecksums",
		"TCP_RST", "TCP_Retrans", "TCP_LostSeg",
		"CIP_Responses", "CIP_ErrorResponses", "CIP_ErrorRate",
		"Integrity", "IntegrityReasons", "Flags",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("write csv header: %w", err)
	}

	for _, row := range rows {
		record := []string{
			row.file,
			row.path,
			strconv.Itoa(row.enipHits),
			strconv.Itoa(row.cipHits),
			strconv.Itoa(row.listIdentity),
			strconv.Itoa(row.udp2222IO),
			strconv.Itoa(row.malformed),
			strconv.Itoa(row.expertErrors),
			strconv.Itoa(row.expertWarnings),
			strconv.Itoa(row.badChecksums),
			strconv.Itoa(row.tcpRst),
			strconv.Itoa(row.tcpRetrans),
			strconv.Itoa(row.tcpLostSeg),
			strconv.Itoa(row.cipResponses),
			strconv.Itoa(row.cipErrorResponses),
			fmt.Sprintf("%.4f", row.cipErrorRate),
			row.integrity,
			row.integrityReasons,
			row.flags,
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("write csv row: %w", err)
		}
	}

	return writer.Error()
}

func writePcapClassifySummary(path, outCSV, pcapDir, tsharkPath string, rows []pcapClassifyRow) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return fmt.Errorf("create summary directory: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create summary file: %w", err)
	}
	defer f.Close()

	var normal, noisy, anomalous, none int
	var fuzz, deform, opsbad int
	for _, row := range rows {
		switch row.integrity {
		case "PROTOCOL_NORMAL":
			normal++
		case "TRANSPORT_NOISY":
			noisy++
		case "PROTOCOL_ANOMALOUS":
			anomalous++
		case "NOT_CIP_ENIP":
			none++
		}
		if strings.Contains(row.flags, "fuzz_or_invalid") {
			fuzz++
		}
		if strings.Contains(row.flags, "deformation") {
			deform++
		}
		if strings.Contains(row.flags, "ops_bad") {
			opsbad++
		}
	}

	_, err = fmt.Fprintf(f, `CIP/ENIP PCAP Classification Summary
Generated: %s
PCAP directory: %s
tshark: %s

Integrity buckets:
  PROTOCOL_NORMAL
  TRANSPORT_NOISY
  PROTOCOL_ANOMALOUS
  NOT_CIP_ENIP

Counts:
  PROTOCOL_NORMAL:     %d
  TRANSPORT_NOISY:     %d
  PROTOCOL_ANOMALOUS:  %d
  NOT_CIP_ENIP:        %d

Additional flags:
  deformation:*         = malformed/expert errors/bad checksum signals
  fuzz_or_invalid:*     = high CIP error rate (unsupported/invalid/fuzz-like)
  ops_bad:*             = extreme transport conditions not conducive to normal ops
  has_discovery:*       = discovery present
  has_io:*              = UDP 2222 I/O present

Flagged sets:
  Deformation: %d
  Fuzz/Invalid: %d
  Ops bad: %d

CSV: %s
`, formatTimestamp(), pcapDir, tsharkPath, normal, noisy, anomalous, none, deform, fuzz, opsbad, outCSV)
	if err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	return nil
}
