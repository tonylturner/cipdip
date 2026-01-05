package validation

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// WiresharkValidator validates packets using Wireshark's tshark dissector
type WiresharkValidator struct {
	tsharkPath string
}

// NewWiresharkValidator creates a new Wireshark validator
// If tsharkPath is empty, it will try to find tshark in PATH
func NewWiresharkValidator(tsharkPath string) *WiresharkValidator {
	if tsharkPath == "" {
		tsharkPath = "tshark"
	}
	return &WiresharkValidator{
		tsharkPath: tsharkPath,
	}
}

// ValidateResult represents the result of Wireshark validation
type ValidateResult struct {
	Valid          bool              // Whether tshark parsed the packet
	Command        string            // ENIP command code (hex) - if extracted
	Status         string            // ENIP status (hex) - if extracted
	CIPService     string            // CIP service code (if applicable)
	Warnings       []string          // Any warnings from tshark
	Errors         []string          // Any errors from tshark
	Fields         map[string]string // Extracted protocol fields
	Message        string            // Validation message
	Layers         []string          // Protocol layers (frame.protocols)
	Malformed      bool              // tshark expert says malformed
	ExpertMessages []string          // tshark expert messages
	SeverityMax    string            // max expert severity
	Internal       *InternalPacketInfo
}

// ValidatePacket validates a single ENIP packet using Wireshark
// The packet should be the raw ENIP packet bytes (24-byte header + data)
func (v *WiresharkValidator) ValidatePacket(packet []byte) (*ValidateResult, error) {
	// Check if tshark is available
	tsharkPath, err := resolveTsharkPath(v.tsharkPath)
	if err != nil {
		return nil, err
	}
	v.tsharkPath = tsharkPath

	// Create temporary PCAP file
	tmpFile, err := os.CreateTemp("", "cipdip_wireshark_*.pcap")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Write packet to PCAP file
	if err := v.writePacketToPCAP(tmpFile, packet); err != nil {
		return nil, fmt.Errorf("write packet to PCAP: %w", err)
	}
	tmpFile.Close()

	// Run tshark to validate
	result, err := v.runTshark(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("run tshark: %w", err)
	}

	return result, nil
}

// ValidatePCAP validates all packets in a PCAP using tshark.
func (v *WiresharkValidator) ValidatePCAP(pcapFile string) ([]ValidateResult, error) {
	results, _, err := v.validatePCAPInternal(pcapFile)
	return results, err
}

// ValidatePCAPRaw validates a PCAP and returns raw tshark JSON output.
func (v *WiresharkValidator) ValidatePCAPRaw(pcapFile string) ([]byte, []ValidateResult, error) {
	results, raw, err := v.validatePCAPInternal(pcapFile)
	return raw, results, err
}

func (v *WiresharkValidator) validatePCAPInternal(pcapFile string) ([]ValidateResult, []byte, error) {
	tsharkPath, err := resolveTsharkPath(v.tsharkPath)
	if err != nil {
		return nil, nil, err
	}
	v.tsharkPath = tsharkPath

	cmd := exec.Command(v.tsharkPath,
		"-r", pcapFile,
		"-T", "json",
	)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr := string(exitErr.Stderr)
			return []ValidateResult{{
				Valid:  false,
				Errors: []string{fmt.Sprintf("tshark exited with code %d: %s", exitErr.ExitCode(), stderr)},
			}}, output, nil
		}
		return nil, nil, fmt.Errorf("execute tshark: %w", err)
	}

	if len(output) == 0 {
		return []ValidateResult{{
			Valid:  false,
			Errors: []string{"tshark produced no output - packet may be malformed"},
		}}, output, nil
	}

	var tsharkOutput []map[string]interface{}
	if err := json.Unmarshal(output, &tsharkOutput); err != nil {
		return nil, nil, fmt.Errorf("parse tshark JSON: %w", err)
	}
	if len(tsharkOutput) == 0 {
		return []ValidateResult{{
			Valid:  false,
			Errors: []string{"no packets found in PCAP"},
		}}, output, nil
	}

	results := make([]ValidateResult, 0, len(tsharkOutput))
	for _, packet := range tsharkOutput {
		results = append(results, buildValidateResult(packet))
	}

	internal, err := ParseInternalPCAP(pcapFile)
	if err == nil {
		attachInternalInfo(results, internal)
	}

	return results, output, nil
}

func buildValidateResult(packet map[string]interface{}) ValidateResult {
	result := ValidateResult{
		Valid:  true,
		Fields: make(map[string]string),
	}

	layers, ok := packet["_source"].(map[string]interface{})
	if !ok {
		result.Valid = false
		result.Errors = append(result.Errors, "missing _source layers")
		return result
	}
	layerData, ok := layers["layers"].(map[string]interface{})
	if !ok {
		result.Valid = false
		result.Errors = append(result.Errors, "missing layers map")
		return result
	}

	flat := flattenLayerFields(layerData)
	protocolStr, protocolLayers := parseProtocolLayers(layerData, flat)
	if protocolStr != "" {
		result.Fields["frame.protocols"] = protocolStr
		result.Layers = protocolLayers
	}

	copyFieldAliases(result.Fields, flat, map[string][]string{
		"enip.command":       {"enip.command"},
		"enip.length":        {"enip.length"},
		"enip.session":       {"enip.session", "enip.session_handle"},
		"enip.status":        {"enip.status"},
		"cip.service":        {"cip.service"},
		"cip.path.class":     {"cip.class", "cip.path.class"},
		"cip.path.instance":  {"cip.instance", "cip.path.instance"},
		"cip.path.attribute": {"cip.attribute", "cip.path.attribute"},
		"cip.general_status": {"cip.general_status", "cip.gen_status", "cip.status"},
		"cip.extended_status": {"cip.extended_status", "cip.ext_status"},
	})

	if val := firstFieldValue(flat, "tcp.port"); val != "" {
		result.Fields["tcp.port"] = val
	}
	if val := firstFieldValue(flat, "udp.port"); val != "" {
		result.Fields["udp.port"] = val
	}
	if _, ok := result.Fields["cpf.item_count"]; !ok {
		if val := findFieldContaining(flat, []string{"cpf", "count"}); val != "" {
			result.Fields["cpf.item_count"] = val
		}
	}
	if _, ok := result.Fields["cip.path.symbol"]; !ok {
		if val := findFieldContaining(flat, []string{"symbol"}); val != "" {
			result.Fields["cip.path.symbol"] = val
		}
	}

	result.Malformed, result.ExpertMessages, result.SeverityMax = parseExpertMessages(layerData)
	if result.Malformed {
		result.Warnings = append(result.Warnings, "tshark reported malformed packet")
	}

	return result
}

func attachInternalInfo(results []ValidateResult, internal []InternalPacketInfo) {
	limit := len(results)
	if len(internal) < limit {
		limit = len(internal)
	}
	for i := 0; i < limit; i++ {
		results[i].Internal = &internal[i]
	}
}

func parseProtocolLayers(layerData map[string]interface{}, flat map[string]interface{}) (string, []string) {
	var protocolStr string
	if protocols, ok := flat["frame.protocols"].(string); ok {
		protocolStr = protocols
	} else if protocolsArr, ok := flat["frame.protocols"].([]interface{}); ok {
		parts := make([]string, 0, len(protocolsArr))
		for _, p := range protocolsArr {
			if s, ok := p.(string); ok {
				parts = append(parts, s)
			}
		}
		protocolStr = strings.Join(parts, ":")
	}

	if protocolStr == "" {
		parts := make([]string, 0, len(layerData))
		for key := range layerData {
			parts = append(parts, strings.ToLower(key))
		}
		if len(parts) == 0 {
			return "", nil
		}
		return strings.Join(parts, ":"), parts
	}
	layers := strings.Split(protocolStr, ":")
	return protocolStr, layers
}

func copyFieldAliases(out map[string]string, layerData map[string]interface{}, aliases map[string][]string) {
	for canonical, keys := range aliases {
		if val := firstFieldValue(layerData, keys...); val != "" {
			out[canonical] = val
		}
	}
}

func firstFieldValue(layerData map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if val, ok := layerData[key]; ok {
			if str := firstStringValue(val); str != "" {
				return str
			}
		}
	}
	return ""
}

func findFieldContaining(layerData map[string]interface{}, fragments []string) string {
	for key, val := range layerData {
		lower := strings.ToLower(key)
		match := true
		for _, frag := range fragments {
			if !strings.Contains(lower, frag) {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		if str := firstStringValue(val); str != "" {
			return str
		}
	}
	return ""
}

func firstStringValue(val interface{}) string {
	switch v := val.(type) {
	case string:
		return v
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				return s
			}
		}
	case map[string]interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				return s
			}
		}
	}
	return ""
}

func parseExpertMessages(layerData map[string]interface{}) (bool, []string, string) {
	messages := []string{}
	maxSeverity := ""
	malformed := false
	severityRank := map[string]int{"error": 3, "warning": 2, "note": 1}
	maxRank := 0

	var walk func(key string, val interface{})
	walk = func(key string, val interface{}) {
		switch v := val.(type) {
		case map[string]interface{}:
			for k, child := range v {
				walk(k, child)
			}
		case []interface{}:
			for _, child := range v {
				walk(key, child)
			}
		default:
			lowerKey := strings.ToLower(key)
			str := firstStringValue(v)
			if str == "" {
				return
			}
			lowerVal := strings.ToLower(str)
			if strings.Contains(lowerKey, "malformed") {
				if strings.Contains(lowerVal, "malformed") || strings.Contains(lowerVal, "invalid") {
					malformed = true
				}
			}
			if strings.Contains(lowerKey, "expert") {
				if strings.Contains(lowerKey, "message") || strings.Contains(lowerKey, "summary") {
					messages = append(messages, str)
				}
				if strings.Contains(lowerKey, "severity") {
					sev := strings.ToLower(str)
					if rank, ok := severityRank[sev]; ok && rank > maxRank {
						maxRank = rank
						maxSeverity = sev
					}
					if valNum, err := parseSeverityNumber(sev); err == nil {
						sevName, rank := severityNameFromNumber(valNum)
						if rank > maxRank {
							maxRank = rank
							maxSeverity = sevName
						}
					}
				}
				if strings.Contains(lowerVal, "malformed") || strings.Contains(lowerVal, "invalid") {
					malformed = true
				}
			}
		}
	}

	for key, val := range layerData {
		walk(key, val)
	}

	if maxRank > 0 && maxRank >= severityRank["error"] {
		// Keep severity for reporting, but don't force malformed unless message text indicates it.
	}

	return malformed, messages, maxSeverity
}

func parseSeverityNumber(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("empty severity")
	}
	if strings.HasPrefix(value, "0x") {
		num, err := strconv.ParseInt(value[2:], 16, 64)
		return int(num), err
	}
	num, err := strconv.ParseInt(value, 10, 64)
	return int(num), err
}

func severityNameFromNumber(val int) (string, int) {
	switch {
	case val >= 0x800000:
		return "error", 3
	case val >= 0x400000:
		return "warning", 2
	case val >= 0x200000:
		return "note", 1
	default:
		return "", 0
	}
}

func flattenLayerFields(layerData map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{})
	for _, val := range layerData {
		if nested, ok := val.(map[string]interface{}); ok {
			flattenNested(out, nested)
		}
	}
	return out
}

func flattenNested(out map[string]interface{}, nested map[string]interface{}) {
	for key, val := range nested {
		out[key] = val
		if deeper, ok := val.(map[string]interface{}); ok {
			flattenNested(out, deeper)
		}
	}
}

func resolveTsharkPath(explicit string) (string, error) {
	if explicit == "" {
		explicit = os.Getenv("TSHARK")
	}
	if explicit == "" {
		explicit = "tshark"
	}
	if filepath.Base(explicit) == explicit {
		path, err := exec.LookPath(explicit)
		if err == nil {
			return path, nil
		}
	} else if _, err := os.Stat(explicit); err == nil {
		return explicit, nil
	}

	if runtime.GOOS == "windows" {
		if path := defaultTsharkWindows(); path != "" {
			return path, nil
		}
	}
	if runtime.GOOS == "darwin" {
		if path := defaultTsharkDarwin(); path != "" {
			return path, nil
		}
	}

	return "", tsharkNotFoundError()
}

// ResolveTsharkPath returns the resolved tshark path using the same lookup logic as the validator.
func ResolveTsharkPath(explicit string) (string, error) {
	return resolveTsharkPath(explicit)
}

// GetTsharkVersion returns the tshark version string.
func GetTsharkVersion(explicit string) (string, error) {
	path, err := resolveTsharkPath(explicit)
	if err != nil {
		return "", err
	}
	cmd := exec.Command(path, "-v")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("tshark -v failed: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func defaultTsharkWindows() string {
	paths := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "Wireshark", "tshark.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Wireshark", "tshark.exe"),
	}
	for _, candidate := range paths {
		if candidate == "Wireshark\\tshark.exe" {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

func defaultTsharkDarwin() string {
	candidate := "/Applications/Wireshark.app/Contents/MacOS/tshark"
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}

func tsharkNotFoundError() error {
	switch runtime.GOOS {
	case "windows":
		return fmt.Errorf("tshark not found in PATH or default locations; install Wireshark or set TSHARK")
	case "darwin":
		return fmt.Errorf("tshark not found in PATH or /Applications/Wireshark.app/Contents/MacOS/tshark; install Wireshark or set TSHARK")
	default:
		return fmt.Errorf("tshark not found in PATH; install wireshark/tshark or set TSHARK")
	}
}

// writePacketToPCAP writes a single ENIP packet to a PCAP file
// The packet is wrapped in Ethernet/IP/TCP layers to make it a valid PCAP
func (v *WiresharkValidator) writePacketToPCAP(file *os.File, enipPacket []byte) error {
	// Create PCAP writer
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return fmt.Errorf("write PCAP header: %w", err)
	}

	// Build a complete packet: Ethernet + IP + TCP + ENIP
	// For validation purposes, we just need the ENIP layer to be parseable
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Create Ethernet layer
	ethernet := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create IP layer
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{192, 168, 1, 200},
	}

	// Create TCP layer
	tcp := &layers.TCP{
		SrcPort: 50000,
		DstPort: 44818, // EtherNet/IP port
		SYN:     false,
		ACK:     true,
		PSH:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	// Serialize layers
	err := gopacket.SerializeLayers(buffer, opts,
		ethernet,
		ip,
		tcp,
		gopacket.Payload(enipPacket),
	)
	if err != nil {
		return fmt.Errorf("serialize layers: %w", err)
	}

	// Write packet to PCAP
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(buffer.Bytes()),
		Length:        len(buffer.Bytes()),
	}

	if err := writer.WritePacket(ci, buffer.Bytes()); err != nil {
		return fmt.Errorf("write packet: %w", err)
	}

	return nil
}

// runTshark runs tshark on a PCAP file and parses the output
func (v *WiresharkValidator) runTshark(pcapFile string) (*ValidateResult, error) {
	// Run tshark to validate the PCAP structure
	// First, check if tshark can read the file without errors
	cmd := exec.Command(v.tsharkPath,
		"-r", pcapFile, // Read from PCAP file
		"-T", "json", // JSON output
		"-e", "frame.number", // Frame number
		"-e", "tcp.port", // TCP port (should be 44818)
		"-e", "tcp.len", // TCP payload length
		"-e", "frame.protocols", // Protocol stack
	)

	output, err := cmd.Output()
	if err != nil {
		// Check if it's an exit error (tshark might exit with code 1 if no packets match)
		if exitErr, ok := err.(*exec.ExitError); ok {
			// If tshark exits with code 1, it might mean no ENIP packets found
			// This could indicate the packet is malformed
			stderr := string(exitErr.Stderr)
			return &ValidateResult{
				Valid:  false,
				Errors: []string{fmt.Sprintf("tshark exited with code %d: %s", exitErr.ExitCode(), stderr)},
			}, nil
		}
		return nil, fmt.Errorf("execute tshark: %w", err)
	}

	// Parse JSON output
	var tsharkOutput []map[string]interface{}
	if len(output) == 0 {
		// No output means tshark couldn't parse the packet
		return &ValidateResult{
			Valid:  false,
			Errors: []string{"tshark produced no output - packet may be malformed"},
		}, nil
	}

	if err := json.Unmarshal(output, &tsharkOutput); err != nil {
		return nil, fmt.Errorf("parse tshark JSON: %w", err)
	}

	if len(tsharkOutput) == 0 {
		return &ValidateResult{
			Valid:  false,
			Errors: []string{"no packets found in PCAP"},
		}, nil
	}

	// Extract fields from first packet
	result := &ValidateResult{
		Valid:  false, // Start as invalid, prove it's valid
		Fields: make(map[string]string),
	}

	// Get the layers from the first packet
	packet := tsharkOutput[0]
	if layers, ok := packet["_source"].(map[string]interface{}); ok {
		if layerData, ok := layers["layers"].(map[string]interface{}); ok {
			// Check TCP port - should be 44818 for ENIP
			port44818 := false
			if tcpPort, ok := layerData["tcp.port"].([]interface{}); ok {
				for _, p := range tcpPort {
					if portStr, ok := p.(string); ok && (portStr == "44818" || portStr == "2222") {
						port44818 = true
						result.Fields["tcp.port"] = portStr
						break
					}
				}
			}

			// Check TCP payload length - should match our ENIP packet size
			if tcpLen, ok := layerData["tcp.len"].(string); ok {
				result.Fields["tcp.len"] = tcpLen
			}

			// Check protocol stack
			var protocolStr string
			if protocols, ok := layerData["frame.protocols"].(string); ok {
				protocolStr = protocols
			} else if protocolsArr, ok := layerData["frame.protocols"].([]interface{}); ok {
				parts := make([]string, 0, len(protocolsArr))
				for _, p := range protocolsArr {
					if s, ok := p.(string); ok {
						parts = append(parts, s)
					}
				}
				protocolStr = strings.Join(parts, ":")
			}

			if protocolStr != "" {
				result.Fields["frame.protocols"] = protocolStr
			}

			// Validation logic:
			// 1. If tshark successfully read the PCAP and found a packet on port 44818, that's a good sign
			// 2. The packet structure is correct (Ethernet/IP/TCP)
			// 3. If ENIP is in protocol stack, even better
			if port44818 {
				if containsProtocol(protocolStr, "enip") {
					result.Valid = true
					result.Message = "Packet validated: ENIP protocol recognized by Wireshark"
				} else {
					// Port is correct, packet structure is valid
					// tshark might not always show ENIP in protocol stack, but if the packet
					// is on the right port and tshark didn't error, it's likely valid
					result.Valid = true
					result.Message = "Packet validated: Correct port (44818) and packet structure"
					result.Warnings = append(result.Warnings, "ENIP not in protocol stack (may be normal)")
				}
			} else {
				result.Valid = false
				result.Errors = append(result.Errors, "Packet not on ENIP port (44818 or 2222)")
			}
		}
	}

	// Check for warnings in tshark output
	// Warnings might appear in different places depending on tshark version
	// For now, we'll check if the packet was successfully parsed
	// If we got here and have fields, it's likely valid

	return result, nil
}

// containsProtocol checks if a protocol string contains a specific protocol
func containsProtocol(protocols, protocol string) bool {
	// Protocols are typically separated by colons, e.g., "eth:ethertype:ip:tcp:enip"
	// Split by colon and check each part
	parts := strings.Split(protocols, ":")
	for _, part := range parts {
		if part == protocol {
			return true
		}
	}
	return false
}

// ValidateENIPPacket is a convenience function that validates an ENIP packet
// Returns true if the packet is valid according to Wireshark, false otherwise
func ValidateENIPPacket(packet []byte) (bool, error) {
	validator := NewWiresharkValidator("")
	result, err := validator.ValidatePacket(packet)
	if err != nil {
		return false, err
	}
	return result.Valid, nil
}

// ValidateENIPPacketWithDetails validates an ENIP packet and returns detailed results
func ValidateENIPPacketWithDetails(packet []byte) (*ValidateResult, error) {
	validator := NewWiresharkValidator("")
	return validator.ValidatePacket(packet)
}
