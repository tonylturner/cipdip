package ui

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
)

func buildWizardForm(workspaceRoot string) *huh.Form {
	return buildWizardFormWithDefault("pcap-replay", workspaceRoot)
}

func buildWizardFormWithDefault(defaultKind, workspaceRoot string) *huh.Form {
	return buildWizardFormWithDefaults(workspaceRoot, CatalogEntry{})
}

func buildWizardFormWithDefaults(workspaceRoot string, entry CatalogEntry) *huh.Form {
	if strings.TrimSpace(entry.Key) != "" {
		return buildSingleWizardForm(workspaceRoot, entry)
	}
	defaultKind := "pcap-replay"
	if strings.TrimSpace(entry.Key) != "" {
		defaultKind = "single"
	}
	kind := defaultKind
	input := findFirstPcap(workspaceRoot)
	preset := ""
	mode := "raw"
	outputDir := filepath.Join(workspaceRoot, "runs")
	duration := "60"
	serverMode := "baseline"
	target := ""
	listenPort := "44818"
	singleIP := ""
	targetChoice := ""
	singlePort := "44818"
	singleService := ""
	singleClass := ""
	singleInstance := ""
	singleAttribute := ""
	singlePayloadType := ""
	singlePayloadParams := ""
	singlePayloadHex := ""
	singleTag := ""
	singleTagPath := ""
	singleElements := ""
	singleOffset := ""
	singleDataType := ""
	singleValue := ""
	singleRouteSlot := ""
	singleUcmmWrap := ""
	singleMutate := ""
	singleMutateSeed := ""
	singleDryRun := false
	catalogKey := ""
	planName := "plan"
	planSteps := "single:identity.vendor_id@192.168.0.10\nsleep:500ms\nreplay:baseline-raw.yaml"
	if ws, err := LoadWorkspace(workspaceRoot); err == nil {
		if ws.Config.Defaults.DefaultTargetIP != "" {
			singleIP = ws.Config.Defaults.DefaultTargetIP
			targetChoice = ws.Config.Defaults.DefaultTargetIP
		} else if len(ws.Config.Defaults.TargetIPs) > 0 {
			singleIP = ws.Config.Defaults.TargetIPs[0]
			targetChoice = ws.Config.Defaults.TargetIPs[0]
		}
	}
	if entry.Key != "" {
		catalogKey = entry.Key
		singleService = entry.Service
		singleClass = entry.Class
		singleInstance = entry.Instance
		singleAttribute = entry.Attribute
	}

	kindGroup := huh.NewGroup(
		huh.NewSelect[string]().
			Title("Wizard type").
			Description("Choose the workflow to generate a repeatable profile.").
			Key("wizard_type").
			Options(
				huh.NewOption("PCAP Replay", "pcap-replay"),
				huh.NewOption("Baseline Suite", "baseline"),
				huh.NewOption("Server Emulator", "server"),
				huh.NewOption("Single Request", "single"),
				huh.NewOption("Test Plan Builder", "plan"),
			).
			Value(&kind),
	)

	pcapGroup := huh.NewGroup(
		huh.NewInput().
			Title("PCAP input").
			Description("Path to a .pcap/.pcapng under workspace/pcaps.").
			Key("pcap_input").
			Value(&input),
		huh.NewInput().
			Title("Preset (optional)").
			Description("Named preset (overrides input when set).").
			Key("pcap_preset").
			Value(&preset),
		huh.NewInput().
			Title("Mode (raw|app|tcpreplay)").
			Description("raw=packet replay, app=regenerate traffic, tcpreplay=external tool").
			Key("pcap_mode").
			Value(&mode),
	).WithHideFunc(func() bool { return kind != "pcap-replay" })

	baselineGroup := huh.NewGroup(
		huh.NewInput().
			Title("Output directory").
			Description("Directory for baseline results.").
			Key("baseline_output_dir").
			Value(&outputDir),
		huh.NewInput().
			Title("Duration (seconds)").
			Description("How long to run the suite (0 = default).").
			Key("baseline_duration").
			Value(&duration),
	).WithHideFunc(func() bool { return kind != "baseline" })

	serverGroup := huh.NewGroup(
		huh.NewInput().
			Title("Mode (baseline|realistic|dpi-torture)").
			Description("Select server personality behavior set.").
			Key("server_mode").
			Value(&serverMode),
		huh.NewInput().
			Title("Target (optional)").
			Description("Vendor target preset (optional).").
			Key("server_target").
			Value(&target),
		huh.NewInput().
			Title("Listen port").
			Description("TCP port for EtherNet/IP (default 44818).").
			Key("server_listen_port").
			Value(&listenPort),
	).WithHideFunc(func() bool { return kind != "server" })

	singleGroup := huh.NewGroup(
		buildTargetSelect(workspaceRoot, &targetChoice),
		huh.NewInput().
			Title("Catalog key (optional)").
			Description("Catalog key to prefill service/class/instance/attribute (e.g., identity.vendor_id).").
			Key("single_catalog_key").
			Value(&catalogKey),
		huh.NewInput().
			Title("Target IP").
			Description("Device IP address.").
			Key("single_ip").
			Value(&singleIP),
		huh.NewInput().
			Title("Port").
			Description("TCP port for EtherNet/IP (default 44818).").
			Key("single_port").
			Value(&singlePort),
		huh.NewInput().
			Title("Service").
			Description("CIP service code (hex) or alias (e.g., get_attribute_single).").
			Key("single_service").
			Value(&singleService),
		huh.NewInput().
			Title("Class").
			Description("Class ID (hex) or alias (e.g., identity_object).").
			Key("single_class").
			Value(&singleClass),
		huh.NewInput().
			Title("Instance").
			Description("Instance ID (hex).").
			Key("single_instance").
			Value(&singleInstance),
		huh.NewInput().
			Title("Attribute (optional)").
			Description("Attribute ID (hex).").
			Key("single_attribute").
			Value(&singleAttribute),
		huh.NewInput().
			Title("Payload type (optional)").
			Description("Service payload type (forward_open, unconnected_send, rockwell_tag, file_object, modbus_object).").
			Key("single_payload_type").
			Value(&singlePayloadType),
		huh.NewInput().
			Title("Payload params (optional)").
			Description("Comma-separated key=value pairs (e.g., tag=MyTag, elements=1).").
			Key("single_payload_params").
			Value(&singlePayloadParams),
		huh.NewInput().
			Title("Payload hex (optional)").
			Description("Raw payload hex (overrides builder).").
			Key("single_payload_hex").
			Value(&singlePayloadHex),
		huh.NewInput().
			Title("Tag (optional)").
			Description("Symbolic tag name (e.g., MyTag).").
			Key("single_tag").
			Value(&singleTag),
		huh.NewInput().
			Title("Tag path (optional)").
			Description("Symbolic tag path (e.g., Program:Main.MyTag).").
			Key("single_tag_path").
			Value(&singleTagPath),
		huh.NewInput().
			Title("Elements (optional)").
			Description("Element count for tag operations.").
			Key("single_elements").
			Value(&singleElements),
		huh.NewInput().
			Title("Offset (optional)").
			Description("Byte offset for fragmented tag operations.").
			Key("single_offset").
			Value(&singleOffset),
		huh.NewInput().
			Title("Data type (optional)").
			Description("CIP data type (BOOL, INT, DINT, REAL, 0x00C4).").
			Key("single_data_type").
			Value(&singleDataType),
		huh.NewInput().
			Title("Value (optional)").
			Description("Value for write/tag payloads (comma-separated allowed).").
			Key("single_value").
			Value(&singleValue),
		huh.NewInput().
			Title("Route slot (optional)").
			Description("UCMM route slot (backplane port 1).").
			Key("single_route_slot").
			Value(&singleRouteSlot),
		huh.NewInput().
			Title("UCMM wrap (optional)").
			Description("Catalog key for embedded UCMM request.").
			Key("single_ucmm_wrap").
			Value(&singleUcmmWrap),
		huh.NewInput().
			Title("Mutate payload (optional)").
			Description("missing_fields, wrong_length, invalid_offsets, wrong_datatype, flip_bits").
			Key("single_mutate").
			Value(&singleMutate),
		huh.NewInput().
			Title("Mutate seed (optional)").
			Description("Deterministic seed for mutation.").
			Key("single_mutate_seed").
			Value(&singleMutateSeed),
		huh.NewConfirm().
			Title("Dry run (no traffic)").
			Description("Print constructed CIP bytes and exit.").
			Key("single_dry_run").
			Value(&singleDryRun),
	).WithHideFunc(func() bool { return kind != "single" })

	planGroup := huh.NewGroup(
		huh.NewInput().
			Title("Plan name").
			Description("Short name for the plan file.").
			Key("plan_name").
			Value(&planName),
		huh.NewText().
			Title("Plan steps").
			Description("One step per line (e.g., single:identity.vendor_id@192.168.0.10).").
			Key("plan_steps").
			Value(&planSteps),
	).WithHideFunc(func() bool { return kind != "plan" })

	return huh.NewForm(kindGroup, pcapGroup, baselineGroup, serverGroup, singleGroup, planGroup)
}

func buildSingleWizardForm(workspaceRoot string, entry CatalogEntry) *huh.Form {
	catalogKey := entry.Key
	singleIP := ""
	targetChoice := ""
	singlePort := "44818"
	singleService := entry.Service
	singleClass := entry.Class
	singleInstance := entry.Instance
	singleAttribute := entry.Attribute
	singlePayloadType := ""
	singlePayloadParams := ""
	singlePayloadHex := ""
	singleTag := ""
	singleTagPath := ""
	singleElements := ""
	singleOffset := ""
	singleDataType := ""
	singleValue := ""
	singleRouteSlot := ""
	singleUcmmWrap := ""
	singleMutate := ""
	singleMutateSeed := ""
	singleDryRun := false
	if ws, err := LoadWorkspace(workspaceRoot); err == nil {
		if ws.Config.Defaults.DefaultTargetIP != "" {
			singleIP = ws.Config.Defaults.DefaultTargetIP
			targetChoice = ws.Config.Defaults.DefaultTargetIP
		} else if len(ws.Config.Defaults.TargetIPs) > 0 {
			singleIP = ws.Config.Defaults.TargetIPs[0]
			targetChoice = ws.Config.Defaults.TargetIPs[0]
		}
	}

	singleGroup := huh.NewGroup(
		buildTargetSelect(workspaceRoot, &targetChoice),
		huh.NewInput().
			Title("Catalog key (optional)").
			Description("Catalog key to prefill service/class/instance/attribute (e.g., identity.vendor_id).").
			Key("single_catalog_key").
			Value(&catalogKey),
		huh.NewInput().
			Title("Target IP").
			Description("Device IP address.").
			Key("single_ip").
			Value(&singleIP),
		huh.NewInput().
			Title("Port").
			Description("TCP port for EtherNet/IP (default 44818).").
			Key("single_port").
			Value(&singlePort),
		huh.NewInput().
			Title("Service").
			Description("CIP service code (hex) or alias (e.g., get_attribute_single).").
			Key("single_service").
			Value(&singleService),
		huh.NewInput().
			Title("Class").
			Description("Class ID (hex) or alias (e.g., identity_object).").
			Key("single_class").
			Value(&singleClass),
		huh.NewInput().
			Title("Instance").
			Description("Instance ID (hex).").
			Key("single_instance").
			Value(&singleInstance),
		huh.NewInput().
			Title("Attribute (optional)").
			Description("Attribute ID (hex).").
			Key("single_attribute").
			Value(&singleAttribute),
		huh.NewInput().
			Title("Payload type (optional)").
			Description("Service payload type (forward_open, unconnected_send, rockwell_tag, file_object, modbus_object).").
			Key("single_payload_type").
			Value(&singlePayloadType),
		huh.NewInput().
			Title("Payload params (optional)").
			Description("Comma-separated key=value pairs (e.g., tag=MyTag, elements=1).").
			Key("single_payload_params").
			Value(&singlePayloadParams),
		huh.NewInput().
			Title("Payload hex (optional)").
			Description("Raw payload hex (overrides builder).").
			Key("single_payload_hex").
			Value(&singlePayloadHex),
		huh.NewInput().
			Title("Tag (optional)").
			Description("Symbolic tag name (e.g., MyTag).").
			Key("single_tag").
			Value(&singleTag),
		huh.NewInput().
			Title("Tag path (optional)").
			Description("Symbolic tag path (e.g., Program:Main.MyTag).").
			Key("single_tag_path").
			Value(&singleTagPath),
		huh.NewInput().
			Title("Elements (optional)").
			Description("Element count for tag operations.").
			Key("single_elements").
			Value(&singleElements),
		huh.NewInput().
			Title("Offset (optional)").
			Description("Byte offset for fragmented tag operations.").
			Key("single_offset").
			Value(&singleOffset),
		huh.NewInput().
			Title("Data type (optional)").
			Description("CIP data type (BOOL, INT, DINT, REAL, 0x00C4).").
			Key("single_data_type").
			Value(&singleDataType),
		huh.NewInput().
			Title("Value (optional)").
			Description("Value for write/tag payloads (comma-separated allowed).").
			Key("single_value").
			Value(&singleValue),
		huh.NewInput().
			Title("Route slot (optional)").
			Description("UCMM route slot (backplane port 1).").
			Key("single_route_slot").
			Value(&singleRouteSlot),
		huh.NewInput().
			Title("UCMM wrap (optional)").
			Description("Catalog key for embedded UCMM request.").
			Key("single_ucmm_wrap").
			Value(&singleUcmmWrap),
		huh.NewInput().
			Title("Mutate payload (optional)").
			Description("missing_fields, wrong_length, invalid_offsets, wrong_datatype, flip_bits").
			Key("single_mutate").
			Value(&singleMutate),
		huh.NewInput().
			Title("Mutate seed (optional)").
			Description("Deterministic seed for mutation.").
			Key("single_mutate_seed").
			Value(&singleMutateSeed),
		huh.NewConfirm().
			Title("Dry run (no traffic)").
			Description("Print constructed CIP bytes and exit.").
			Key("single_dry_run").
			Value(&singleDryRun),
	)
	return huh.NewForm(singleGroup)
}

func buildTargetSelect(workspaceRoot string, targetChoice *string) *huh.Select[string] {
	ws, err := LoadWorkspace(workspaceRoot)
	if err != nil || len(ws.Config.Defaults.TargetIPs) == 0 {
		return huh.NewSelect[string]().
			Title("Target preset (optional)").
			Description("No presets configured in workspace defaults.").
			Key("single_target_choice").
			Options(huh.NewOption("None", "")).
			Value(targetChoice)
	}
	options := []huh.Option[string]{
		huh.NewOption("Custom (enter below)", "custom"),
	}
	for _, ip := range ws.Config.Defaults.TargetIPs {
		label := ip
		if ws.Config.Defaults.DefaultTargetIP == ip {
			label = ip + " (default)"
		}
		options = append(options, huh.NewOption(label, ip))
	}
	return huh.NewSelect[string]().
		Title("Target preset").
		Description("Pick a saved target or choose custom.").
		Key("single_target_choice").
		Options(options...).
		Value(targetChoice)
}

func buildWizardProfileFromForm(form *huh.Form, workspaceRoot string) (Profile, error) {
	kind := strings.ToLower(strings.TrimSpace(form.GetString("wizard_type")))
	if kind == "" {
		if strings.TrimSpace(form.GetString("single_ip")) != "" ||
			strings.TrimSpace(form.GetString("single_service")) != "" ||
			strings.TrimSpace(form.GetString("single_class")) != "" ||
			strings.TrimSpace(form.GetString("single_catalog_key")) != "" {
			kind = "single"
		} else {
			kind = "pcap-replay"
		}
	}
	switch kind {
	case "pcap-replay":
		return BuildWizardProfile(WizardOptions{
			Kind:   "pcap-replay",
			Name:   "pcap-replay",
			Input:  strings.TrimSpace(form.GetString("pcap_input")),
			Preset: strings.TrimSpace(form.GetString("pcap_preset")),
			Mode:   strings.TrimSpace(form.GetString("pcap_mode")),
		})
	case "baseline":
		duration, _ := strconv.Atoi(strings.TrimSpace(form.GetString("baseline_duration")))
		return BuildWizardProfile(WizardOptions{
			Kind:      "baseline",
			Name:      "baseline",
			OutputDir: strings.TrimSpace(form.GetString("baseline_output_dir")),
			Duration:  duration,
		})
	case "server":
		port, _ := strconv.Atoi(strings.TrimSpace(form.GetString("server_listen_port")))
		return BuildWizardProfile(WizardOptions{
			Kind:       "server",
			Name:       "server",
			Mode:       strings.TrimSpace(form.GetString("server_mode")),
			Target:     strings.TrimSpace(form.GetString("server_target")),
			ServerPort: port,
		})
	case "single":
		port, _ := strconv.Atoi(strings.TrimSpace(form.GetString("single_port")))
		payloadParams := parsePayloadParamsText(form.GetString("single_payload_params"))
		mutateSeed, _ := strconv.Atoi(strings.TrimSpace(form.GetString("single_mutate_seed")))
		catalogKey := strings.TrimSpace(form.GetString("single_catalog_key"))
		if catalogKey != "" {
			entries, _ := ListCatalogEntries(workspaceRoot)
			if entry := FindCatalogEntry(entries, catalogKey); entry != nil {
				service := strings.TrimSpace(form.GetString("single_service"))
				classID := strings.TrimSpace(form.GetString("single_class"))
				instance := strings.TrimSpace(form.GetString("single_instance"))
				attribute := strings.TrimSpace(form.GetString("single_attribute"))
				if service == "" {
					service = entry.Service
				}
				if classID == "" {
					classID = entry.Class
				}
				if instance == "" {
					instance = entry.Instance
				}
				if attribute == "" {
					attribute = entry.Attribute
				}
				ip := strings.TrimSpace(form.GetString("single_ip"))
				if ip == "" {
					ip = strings.TrimSpace(form.GetString("single_target_choice"))
				}
				if ip == "" {
					return Profile{}, fmt.Errorf("single request requires target IP")
				}
				if service == "" || classID == "" {
					return Profile{}, fmt.Errorf("single request requires service and class")
				}
				return BuildWizardProfile(WizardOptions{
					Kind:          "single",
					Name:          entry.Key,
					CatalogKey:    catalogKey,
					IP:            ip,
					Port:          port,
					Service:       service,
					Class:         classID,
					Instance:      instance,
					Attribute:     attribute,
					PayloadHex:    strings.TrimSpace(form.GetString("single_payload_hex")),
					PayloadType:   strings.TrimSpace(form.GetString("single_payload_type")),
					PayloadParams: payloadParams,
					Tag:           strings.TrimSpace(form.GetString("single_tag")),
					TagPath:       strings.TrimSpace(form.GetString("single_tag_path")),
					Elements:      strings.TrimSpace(form.GetString("single_elements")),
					Offset:        strings.TrimSpace(form.GetString("single_offset")),
					DataType:      strings.TrimSpace(form.GetString("single_data_type")),
					Value:         strings.TrimSpace(form.GetString("single_value")),
					RouteSlot:     strings.TrimSpace(form.GetString("single_route_slot")),
					UcmmWrap:      strings.TrimSpace(form.GetString("single_ucmm_wrap")),
					DryRun:        form.GetBool("single_dry_run"),
					Mutate:        strings.TrimSpace(form.GetString("single_mutate")),
					MutateSeed:    mutateSeed,
				})
			}
		}
		ip := strings.TrimSpace(form.GetString("single_ip"))
		if ip == "" {
			ip = strings.TrimSpace(form.GetString("single_target_choice"))
		}
		service := strings.TrimSpace(form.GetString("single_service"))
		classID := strings.TrimSpace(form.GetString("single_class"))
		if ip == "" {
			return Profile{}, fmt.Errorf("single request requires target IP")
		}
		if service == "" || classID == "" {
			return Profile{}, fmt.Errorf("single request requires service and class")
		}
		return BuildWizardProfile(WizardOptions{
			Kind:          "single",
			Name:          "single",
			CatalogKey:    strings.TrimSpace(form.GetString("single_catalog_key")),
			IP:            ip,
			Port:          port,
			Service:       service,
			Class:         classID,
			Instance:      strings.TrimSpace(form.GetString("single_instance")),
			Attribute:     strings.TrimSpace(form.GetString("single_attribute")),
			PayloadHex:    strings.TrimSpace(form.GetString("single_payload_hex")),
			PayloadType:   strings.TrimSpace(form.GetString("single_payload_type")),
			PayloadParams: payloadParams,
			Tag:           strings.TrimSpace(form.GetString("single_tag")),
			TagPath:       strings.TrimSpace(form.GetString("single_tag_path")),
			Elements:      strings.TrimSpace(form.GetString("single_elements")),
			Offset:        strings.TrimSpace(form.GetString("single_offset")),
			DataType:      strings.TrimSpace(form.GetString("single_data_type")),
			Value:         strings.TrimSpace(form.GetString("single_value")),
			RouteSlot:     strings.TrimSpace(form.GetString("single_route_slot")),
			UcmmWrap:      strings.TrimSpace(form.GetString("single_ucmm_wrap")),
			DryRun:        form.GetBool("single_dry_run"),
			Mutate:        strings.TrimSpace(form.GetString("single_mutate")),
			MutateSeed:    mutateSeed,
		})
	case "plan":
		return BuildWizardProfile(WizardOptions{Kind: "plan"})
	default:
		return BuildWizardProfile(WizardOptions{Kind: kind})
	}
}

func wizardKindFromForm(form *huh.Form) string {
	kind := strings.ToLower(strings.TrimSpace(form.GetString("wizard_type")))
	if kind == "" {
		if strings.TrimSpace(form.GetString("single_ip")) != "" ||
			strings.TrimSpace(form.GetString("single_service")) != "" ||
			strings.TrimSpace(form.GetString("single_class")) != "" ||
			strings.TrimSpace(form.GetString("single_catalog_key")) != "" {
			return "single"
		}
		return "pcap-replay"
	}
	return kind
}

func parsePayloadParamsText(input string) []string {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		val := strings.TrimSpace(part)
		if val != "" {
			out = append(out, val)
		}
	}
	return out
}
