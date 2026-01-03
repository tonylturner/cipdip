package ui

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
)

func buildWizardForm(workspaceRoot string) *huh.Form {
	return buildWizardFormWithDefault("pcap-replay", workspaceRoot)
}

func buildWizardFormWithDefault(defaultKind, workspaceRoot string) *huh.Form {
	kind := defaultKind
	input := findFirstPcap(workspaceRoot)
	preset := ""
	mode := "raw"
	outputDir := "workspace/runs"
	duration := "60"
	serverMode := "baseline"
	target := ""
	listenPort := "44818"
	singleIP := ""
	singlePort := "44818"
	singleService := ""
	singleClass := ""
	singleInstance := ""
	singleAttribute := ""
	catalogKey := ""

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
	).WithHideFunc(func() bool { return kind != "single" })

	return huh.NewForm(kindGroup, pcapGroup, baselineGroup, serverGroup, singleGroup)
}

func buildWizardProfileFromForm(form *huh.Form, workspaceRoot string) (Profile, error) {
	kind := strings.ToLower(strings.TrimSpace(form.GetString("wizard_type")))
	if kind == "" {
		kind = "pcap-replay"
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
				return BuildWizardProfile(WizardOptions{
					Kind:      "single",
					Name:      entry.Key,
					IP:        strings.TrimSpace(form.GetString("single_ip")),
					Port:      port,
					Service:   service,
					Class:     classID,
					Instance:  instance,
					Attribute: attribute,
				})
			}
		}
		return BuildWizardProfile(WizardOptions{
			Kind:      "single",
			Name:      "single",
			IP:        strings.TrimSpace(form.GetString("single_ip")),
			Port:      port,
			Service:   strings.TrimSpace(form.GetString("single_service")),
			Class:     strings.TrimSpace(form.GetString("single_class")),
			Instance:  strings.TrimSpace(form.GetString("single_instance")),
			Attribute: strings.TrimSpace(form.GetString("single_attribute")),
		})
	default:
		return BuildWizardProfile(WizardOptions{Kind: kind})
	}
}
