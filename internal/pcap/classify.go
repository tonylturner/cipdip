package pcap

import (
	"bytes"
	"fmt"
	"math"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type ClassifyOptions struct {
	MaxTcpRst       int
	MaxTcpRetrans   int
	MaxTcpLostSeg   int
	MaxCipErrorRate float64
	MaxMalformed    int
	MaxExpertErrors int
}

type ClassifyRow struct {
	File              string
	Path              string
	EnipHits          int
	CipHits           int
	ListIdentity      int
	UDP2222IO         int
	Malformed         int
	ExpertErrors      int
	ExpertWarnings    int
	BadChecksums      int
	TcpRst            int
	TcpRetrans        int
	TcpLostSeg        int
	CipResponses      int
	CipErrorResponses int
	CipErrorRate      float64
	Integrity         string
	IntegrityReasons  string
	Flags             string
}

type expertSummary struct {
	errors   int
	warnings int
	notes    int
	chats    int
}

func ClassifyPCAPs(tsharkPath string, paths []string, opts ClassifyOptions) ([]ClassifyRow, error) {
	rows := make([]ClassifyRow, 0, len(paths))
	for _, pcapPath := range paths {
		row, err := ClassifyPCAP(tsharkPath, pcapPath, opts)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func ClassifyPCAP(tsharkPath, pcapPath string, opts ClassifyOptions) (ClassifyRow, error) {
	enipHits, err := countTshark(tsharkPath, pcapPath, "enip || tcp.port==44818 || udp.port==44818 || udp.port==2222")
	if err != nil {
		return ClassifyRow{}, err
	}
	cipHits, err := countTshark(tsharkPath, pcapPath, "cip")
	if err != nil {
		return ClassifyRow{}, err
	}
	listId, err := countTshark(tsharkPath, pcapPath, "enip.command==0x0063")
	if err != nil {
		return ClassifyRow{}, err
	}
	io2222, err := countTshark(tsharkPath, pcapPath, "udp.port==2222")
	if err != nil {
		return ClassifyRow{}, err
	}
	malformed, err := countTshark(tsharkPath, pcapPath, "_ws.malformed")
	if err != nil {
		return ClassifyRow{}, err
	}
	expert, err := getExpertSummary(tsharkPath, pcapPath)
	if err != nil {
		return ClassifyRow{}, err
	}
	tcpRst, err := countTshark(tsharkPath, pcapPath, "tcp.flags.reset==1")
	if err != nil {
		return ClassifyRow{}, err
	}
	tcpRetrans, err := countTshark(tsharkPath, pcapPath, "tcp.analysis.retransmission")
	if err != nil {
		return ClassifyRow{}, err
	}
	tcpLostSeg, err := countTshark(tsharkPath, pcapPath, "tcp.analysis.lost_segment")
	if err != nil {
		return ClassifyRow{}, err
	}
	cipResponses, err := countTshark(tsharkPath, pcapPath, "cip.genstat")
	if err != nil {
		return ClassifyRow{}, err
	}
	cipErrorResp, err := countTshark(tsharkPath, pcapPath, "cip.genstat != 0")
	if err != nil {
		return ClassifyRow{}, err
	}
	badChecksum, err := countTsharkOptional(tsharkPath, pcapPath, "ip.checksum_bad==1 || tcp.checksum_bad==1 || udp.checksum_bad==1")
	if err != nil {
		return ClassifyRow{}, err
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
	} else if tcpRst > opts.MaxTcpRst || tcpRetrans > opts.MaxTcpRetrans || tcpLostSeg > opts.MaxTcpLostSeg {
		integrity = "TRANSPORT_NOISY"
		if tcpRst > opts.MaxTcpRst {
			integrityReasons = append(integrityReasons, fmt.Sprintf("tcpRst=%d", tcpRst))
		}
		if tcpRetrans > opts.MaxTcpRetrans {
			integrityReasons = append(integrityReasons, fmt.Sprintf("retrans=%d", tcpRetrans))
		}
		if tcpLostSeg > opts.MaxTcpLostSeg {
			integrityReasons = append(integrityReasons, fmt.Sprintf("lostSeg=%d", tcpLostSeg))
		}
	}

	flagsList := make([]string, 0)
	if malformed > opts.MaxMalformed {
		flagsList = append(flagsList, "deformation:malformed")
	}
	if expert.errors > opts.MaxExpertErrors {
		flagsList = append(flagsList, "deformation:expert_error")
	}
	if badChecksum > 0 {
		flagsList = append(flagsList, "deformation:bad_checksum")
	}
	if cipResponses > 0 && cipErrorRate > opts.MaxCipErrorRate {
		flagsList = append(flagsList, "fuzz_or_invalid:high_cip_error_rate")
	}
	if tcpRetrans > (opts.MaxTcpRetrans * 10) {
		flagsList = append(flagsList, "ops_bad:extreme_retrans")
	}
	if tcpLostSeg > (opts.MaxTcpLostSeg * 5) {
		flagsList = append(flagsList, "ops_bad:extreme_loss")
	}
	if tcpRst > (opts.MaxTcpRst * 10) {
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

	return ClassifyRow{
		File:              filepath.Base(pcapPath),
		Path:              pcapPath,
		EnipHits:          enipHits,
		CipHits:           cipHits,
		ListIdentity:      listId,
		UDP2222IO:         io2222,
		Malformed:         malformed,
		ExpertErrors:      expert.errors,
		ExpertWarnings:    expert.warnings,
		BadChecksums:      badChecksum,
		TcpRst:            tcpRst,
		TcpRetrans:        tcpRetrans,
		TcpLostSeg:        tcpLostSeg,
		CipResponses:      cipResponses,
		CipErrorResponses: cipErrorResp,
		CipErrorRate:      cipErrorRate,
		Integrity:         integrity,
		IntegrityReasons:  reasonText,
		Flags:             flagText,
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
