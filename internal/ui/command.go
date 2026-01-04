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
	return BuildCommandWithWorkspace(profile, "")
}

// BuildCommandWithWorkspace builds a CLI command from a profile plus workspace defaults.
func BuildCommandWithWorkspace(profile Profile, workspaceRoot string) (CommandSpec, error) {
	resolved, err := ResolveProfile(profile, workspaceRoot)
	if err != nil {
		return CommandSpec{}, err
	}
	switch strings.ToLower(resolved.Kind) {
	case "pcap_replay":
		return buildPcapReplayCommand(resolved)
	case "baseline":
		return buildBaselineCommand(resolved)
	case "server":
		return buildServerCommand(resolved)
	case "single":
		return buildSingleCommand(resolved)
	default:
		return CommandSpec{}, fmt.Errorf("unsupported profile kind: %s", resolved.Kind)
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
	addStringFlag(&args, spec, "payload_type", "--payload-type")
	addStringSliceFlag(&args, spec, "payload_params", "--payload-param")
	addStringFlag(&args, spec, "tag", "--tag")
	addStringFlag(&args, spec, "tag_path", "--tag-path")
	addStringFlag(&args, spec, "elements", "--elements")
	addStringFlag(&args, spec, "offset", "--offset")
	addStringFlag(&args, spec, "type", "--type")
	addStringFlag(&args, spec, "value", "--value")
	addStringFlag(&args, spec, "file_offset", "--file-offset")
	addStringFlag(&args, spec, "chunk", "--chunk")
	addStringFlag(&args, spec, "modbus_fc", "--modbus-fc")
	addStringFlag(&args, spec, "modbus_addr", "--modbus-addr")
	addStringFlag(&args, spec, "modbus_qty", "--modbus-qty")
	addStringFlag(&args, spec, "modbus_data_hex", "--modbus-data-hex")
	addStringFlag(&args, spec, "pccc_hex", "--pccc-hex")
	addStringFlag(&args, spec, "route_slot", "--route-slot")
	addStringFlag(&args, spec, "ucmm_wrap", "--ucmm-wrap")
	addStringFlag(&args, spec, "catalog_root", "--catalog-root")
	addStringFlag(&args, spec, "catalog_key", "--catalog-key")
	addBoolFlag(&args, spec, "dry_run", "--dry-run")
	addStringFlag(&args, spec, "mutate", "--mutate")
	addIntFlag(&args, spec, "mutate_seed", "--mutate-seed")
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

func addStringSliceFlag(args *[]string, spec map[string]interface{}, key, flag string) {
	val, ok := spec[key]
	if !ok {
		return
	}
	switch v := val.(type) {
	case []string:
		for _, item := range v {
			if strings.TrimSpace(item) != "" {
				*args = append(*args, flag, item)
			}
		}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				*args = append(*args, flag, s)
			}
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
