package ui

import (
	"fmt"
	"strconv"
	"strings"
)

// CommandSpec represents a CLI invocation derived from a profile.
type CommandSpec struct {
	Args []string
}

// BuildCommand builds a CLI command from a profile kind/spec.
func BuildCommand(profile Profile) (CommandSpec, error) {
	switch strings.ToLower(profile.Kind) {
	case "pcap_replay":
		return buildPcapReplayCommand(profile)
	case "baseline":
		return buildBaselineCommand(profile)
	case "server":
		return buildServerCommand(profile)
	case "single":
		return buildSingleCommand(profile)
	default:
		return CommandSpec{}, fmt.Errorf("unsupported profile kind: %s", profile.Kind)
	}
}

func buildPcapReplayCommand(profile Profile) (CommandSpec, error) {
	spec := profile.Spec
	args := []string{"cipdip", "pcap-replay"}

	input := getString(spec, "input")
	preset := getString(spec, "preset")
	if input == "" && preset == "" {
		return CommandSpec{}, fmt.Errorf("pcap_replay requires spec.input or spec.preset")
	}
	if input != "" {
		args = append(args, "--input", input)
	}
	if preset != "" {
		args = append(args, "--preset", preset)
	}

	addStringFlag(&args, spec, "mode", "--mode")
	addStringFlag(&args, spec, "server_ip", "--server-ip")
	addIntFlag(&args, spec, "server_port", "--server-port")
	addIntFlag(&args, spec, "udp_port", "--udp-port")
	addStringFlag(&args, spec, "client_ip", "--client-ip")
	addStringFlag(&args, spec, "iface", "--iface")
	addIntFlag(&args, spec, "interval_ms", "--interval-ms")
	addBoolFlag(&args, spec, "realtime", "--realtime")
	addBoolFlag(&args, spec, "include_responses", "--include-responses")
	addIntFlag(&args, spec, "limit", "--limit")
	addBoolFlag(&args, spec, "report", "--report")
	addBoolFlag(&args, spec, "preflight_only", "--preflight-only")
	addStringFlag(&args, spec, "arp_target", "--arp-target")
	addIntFlag(&args, spec, "arp_timeout_ms", "--arp-timeout-ms")
	addIntFlag(&args, spec, "arp_retries", "--arp-retries")
	addBoolFlag(&args, spec, "arp_required", "--arp-required")
	addBoolFlag(&args, spec, "arp_auto_rewrite", "--arp-auto-rewrite")
	addIntFlag(&args, spec, "arp_refresh_ms", "--arp-refresh-ms")
	addBoolFlag(&args, spec, "arp_drift_fail", "--arp-drift-fail")
	addStringFlag(&args, spec, "rewrite_src_ip", "--rewrite-src-ip")
	addStringFlag(&args, spec, "rewrite_dst_ip", "--rewrite-dst-ip")
	addIntFlag(&args, spec, "rewrite_src_port", "--rewrite-src-port")
	addIntFlag(&args, spec, "rewrite_dst_port", "--rewrite-dst-port")
	addStringFlag(&args, spec, "rewrite_src_mac", "--rewrite-src-mac")
	addStringFlag(&args, spec, "rewrite_dst_mac", "--rewrite-dst-mac")
	addBoolFlag(&args, spec, "rewrite_only_enip", "--rewrite-only-enip")

	return CommandSpec{Args: args}, nil
}

func buildBaselineCommand(profile Profile) (CommandSpec, error) {
	spec := profile.Spec
	args := []string{"cipdip", "baseline"}
	addStringFlag(&args, spec, "output_dir", "--output-dir")
	addIntFlag(&args, spec, "duration", "--duration")
	return CommandSpec{Args: args}, nil
}

func buildServerCommand(profile Profile) (CommandSpec, error) {
	spec := profile.Spec
	args := []string{"cipdip", "server", "start"}
	addStringFlag(&args, spec, "server_config", "--server-config")
	addStringFlag(&args, spec, "listen_ip", "--listen-ip")
	addIntFlag(&args, spec, "listen_port", "--listen-port")
	addStringFlag(&args, spec, "personality", "--personality")
	addBoolFlag(&args, spec, "enable_udp_io", "--enable-udp-io")
	addStringFlag(&args, spec, "mode", "--mode")
	addStringFlag(&args, spec, "target", "--target")
	addStringFlag(&args, spec, "log_format", "--log-format")
	addStringFlag(&args, spec, "log_level", "--log-level")
	addIntFlag(&args, spec, "log_every_n", "--log-every-n")
	return CommandSpec{Args: args}, nil
}

func buildSingleCommand(profile Profile) (CommandSpec, error) {
	spec := profile.Spec
	args := []string{"cipdip", "single"}
	addStringFlag(&args, spec, "ip", "--ip")
	addIntFlag(&args, spec, "port", "--port")
	addStringFlag(&args, spec, "service", "--service")
	addStringFlag(&args, spec, "class", "--class")
	addStringFlag(&args, spec, "instance", "--instance")
	addStringFlag(&args, spec, "attribute", "--attribute")
	addStringFlag(&args, spec, "payload_hex", "--payload-hex")
	return CommandSpec{Args: args}, nil
}

func addStringFlag(args *[]string, spec map[string]interface{}, key, flag string) {
	if val := getString(spec, key); val != "" {
		*args = append(*args, flag, val)
	}
}

func addIntFlag(args *[]string, spec map[string]interface{}, key, flag string) {
	val := getInt(spec, key)
	if val != 0 {
		*args = append(*args, flag, strconv.Itoa(val))
	}
}

func addBoolFlag(args *[]string, spec map[string]interface{}, key, flag string) {
	val, ok := spec[key]
	if !ok {
		return
	}
	switch v := val.(type) {
	case bool:
		if v {
			*args = append(*args, flag)
		}
	case string:
		if parsed, err := strconv.ParseBool(v); err == nil && parsed {
			*args = append(*args, flag)
		}
	}
}

func getString(spec map[string]interface{}, key string) string {
	val, ok := spec[key]
	if !ok {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return ""
	}
}

func getInt(spec map[string]interface{}, key string) int {
	val, ok := spec[key]
	if !ok {
		return 0
	}
	switch v := val.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		if parsed, err := strconv.Atoi(v); err == nil {
			return parsed
		}
	}
	return 0
}
