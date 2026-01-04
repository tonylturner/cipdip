package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tturner/cipdip/internal/cipclient"
	"gopkg.in/yaml.v3"
)

// CatalogEntry represents a named CIP operation.
type CatalogEntry struct {
	Key        string         `yaml:"key"`
	Name       string         `yaml:"name"`
	Service    string         `yaml:"service"`
	Class      string         `yaml:"class"`
	Instance   string         `yaml:"instance"`
	Attribute  string         `yaml:"attribute"`
	Scope      string         `yaml:"scope,omitempty"`
	Vendor     string         `yaml:"vendor,omitempty"`
	Notes      string         `yaml:"notes,omitempty"`
	Payload    CatalogPayload `yaml:"payload,omitempty"`
	PayloadHex string         `yaml:"payload_hex,omitempty"`
}

// CatalogPayload describes service-specific request payloads.
type CatalogPayload struct {
	Type   string         `yaml:"type,omitempty"`
	Params map[string]any `yaml:"params,omitempty"`
}

// CatalogFile contains a list of entries.
type CatalogFile struct {
	Version int            `yaml:"version"`
	Name    string         `yaml:"name"`
	Entries []CatalogEntry `yaml:"entries"`
}

// LoadCatalogFile reads a catalog YAML file.
func LoadCatalogFile(path string) (*CatalogFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	var catalog CatalogFile
	if err := yaml.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}
	return &catalog, nil
}

// SaveCatalogFile writes a catalog YAML file.
func SaveCatalogFile(path string, catalog CatalogFile) error {
	data, err := yaml.Marshal(catalog)
	if err != nil {
		return fmt.Errorf("marshal catalog: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write catalog: %w", err)
	}
	return nil
}

// DefaultCatalog returns a small starter catalog for new workspaces.
func DefaultCatalog() CatalogFile {
	return CatalogFile{
		Version: 1,
		Name:    "core",
		Entries: []CatalogEntry{
			{
				Key:       "identity.vendor_id",
				Name:      "Vendor ID",
				Service:   "0x0E",
				Class:     "0x01",
				Instance:  "0x01",
				Attribute: "0x01",
				Scope:     "core",
			},
			{
				Key:       "identity.product_name",
				Name:      "Product Name",
				Service:   "0x0E",
				Class:     "0x01",
				Instance:  "0x01",
				Attribute: "0x07",
				Scope:     "core",
			},
		},
	}
}

// DefaultExtendedCatalog returns a broader catalog seeded from supported services.
func DefaultExtendedCatalog() CatalogFile {
	entries := []CatalogEntry{
		{Key: "identity.vendor_id", Name: "Vendor ID", Service: "0x0E", Class: "0x01", Instance: "0x01", Attribute: "0x01", Scope: "core"},
		{Key: "identity.device_type", Name: "Device Type", Service: "0x0E", Class: "0x01", Instance: "0x01", Attribute: "0x02", Scope: "core"},
		{Key: "identity.product_code", Name: "Product Code", Service: "0x0E", Class: "0x01", Instance: "0x01", Attribute: "0x03", Scope: "core"},
		{Key: "identity.revision", Name: "Revision", Service: "0x0E", Class: "0x01", Instance: "0x01", Attribute: "0x04", Scope: "core"},
		{Key: "identity.status", Name: "Status", Service: "0x0E", Class: "0x01", Instance: "0x01", Attribute: "0x05", Scope: "core"},
		{Key: "identity.serial_number", Name: "Serial Number", Service: "0x0E", Class: "0x01", Instance: "0x01", Attribute: "0x06", Scope: "core"},
		{Key: "identity.product_name", Name: "Product Name", Service: "0x0E", Class: "0x01", Instance: "0x01", Attribute: "0x07", Scope: "core"},
		{Key: "identity.class_revision", Name: "Identity Class Revision", Service: "0x0E", Class: "0x01", Instance: "0x00", Attribute: "0x01", Scope: "core", Notes: "Common class attribute"},
		{Key: "identity.max_instance", Name: "Identity Max Instance", Service: "0x0E", Class: "0x01", Instance: "0x00", Attribute: "0x02", Scope: "core", Notes: "Common class attribute"},
		{Key: "identity.number_of_instances", Name: "Identity Number of Instances", Service: "0x0E", Class: "0x01", Instance: "0x00", Attribute: "0x03", Scope: "core", Notes: "Common class attribute"},
		{Key: "identity.optional_attribute_list", Name: "Identity Optional Attribute List", Service: "0x0E", Class: "0x01", Instance: "0x00", Attribute: "0x04", Scope: "core", Notes: "Common class attribute"},
		{Key: "identity.optional_service_list", Name: "Identity Optional Service List", Service: "0x0E", Class: "0x01", Instance: "0x00", Attribute: "0x05", Scope: "core", Notes: "Common class attribute"},
		{Key: "identity.max_id_number_class_attributes", Name: "Identity Max Class Attribute ID", Service: "0x0E", Class: "0x01", Instance: "0x00", Attribute: "0x06", Scope: "core", Notes: "Common class attribute"},
		{Key: "identity.max_id_number_instance_attributes", Name: "Identity Max Instance Attribute ID", Service: "0x0E", Class: "0x01", Instance: "0x00", Attribute: "0x07", Scope: "core", Notes: "Common class attribute"},
		{Key: "connection_manager.forward_open", Name: "Forward Open", Service: "0x54", Class: "0x06", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Connection Manager", Payload: CatalogPayload{Type: "forward_open"}},
		{Key: "connection_manager.forward_close", Name: "Forward Close", Service: "0x4E", Class: "0x06", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Connection Manager", Payload: CatalogPayload{Type: "forward_close"}},
		{Key: "connection_manager.unconnected_send", Name: "Unconnected Send", Service: "0x52", Class: "0x06", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Encapsulates another CIP request", Payload: CatalogPayload{Type: "unconnected_send"}},
		{Key: "file_object.initiate_upload", Name: "Initiate Upload", Service: "0x4B", Class: "0x37", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Requires file payload", Payload: CatalogPayload{Type: "file_object"}},
		{Key: "file_object.initiate_download", Name: "Initiate Download", Service: "0x4C", Class: "0x37", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Requires file payload", Payload: CatalogPayload{Type: "file_object"}},
		{Key: "file_object.initiate_partial_read", Name: "Initiate Partial Read", Service: "0x4D", Class: "0x37", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Requires file payload", Payload: CatalogPayload{Type: "file_object"}},
		{Key: "file_object.initiate_partial_write", Name: "Initiate Partial Write", Service: "0x4E", Class: "0x37", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Requires file payload", Payload: CatalogPayload{Type: "file_object"}},
		{Key: "file_object.upload_transfer", Name: "Upload Transfer", Service: "0x4F", Class: "0x37", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Requires file payload", Payload: CatalogPayload{Type: "file_object"}},
		{Key: "file_object.download_transfer", Name: "Download Transfer", Service: "0x50", Class: "0x37", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Requires file payload", Payload: CatalogPayload{Type: "file_object"}},
		{Key: "file_object.clear_file", Name: "Clear File", Service: "0x51", Class: "0x37", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Requires file payload", Payload: CatalogPayload{Type: "file_object"}},
		{Key: "modbus.read_discrete_inputs", Name: "Read Discrete Inputs", Service: "0x4B", Class: "0x44", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Modbus object", Payload: CatalogPayload{Type: "modbus_object"}},
		{Key: "modbus.read_coils", Name: "Read Coils", Service: "0x4C", Class: "0x44", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Modbus object", Payload: CatalogPayload{Type: "modbus_object"}},
		{Key: "modbus.read_input_registers", Name: "Read Input Registers", Service: "0x4D", Class: "0x44", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Modbus object", Payload: CatalogPayload{Type: "modbus_object"}},
		{Key: "modbus.read_holding_registers", Name: "Read Holding Registers", Service: "0x4E", Class: "0x44", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Modbus object", Payload: CatalogPayload{Type: "modbus_object"}},
		{Key: "modbus.write_coils", Name: "Write Coils", Service: "0x4F", Class: "0x44", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Modbus object", Payload: CatalogPayload{Type: "modbus_object"}},
		{Key: "modbus.write_holding_registers", Name: "Write Holding Registers", Service: "0x50", Class: "0x44", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Modbus object", Payload: CatalogPayload{Type: "modbus_object"}},
		{Key: "modbus.passthrough", Name: "Modbus Passthrough", Service: "0x51", Class: "0x44", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Modbus object", Payload: CatalogPayload{Type: "modbus_object"}},
		{Key: "motion.get_axis_attributes_list", Name: "Get Axis Attributes List", Service: "0x4B", Class: "0x42", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Motion Axis object"},
		{Key: "motion.set_axis_attributes_list", Name: "Set Axis Attributes List", Service: "0x4C", Class: "0x42", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Motion Axis object"},
		{Key: "motion.get_motor_test_data", Name: "Get Motor Test Data", Service: "0x50", Class: "0x42", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Motion Axis object"},
		{Key: "motion.get_inertia_test_data", Name: "Get Inertia Test Data", Service: "0x52", Class: "0x42", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Motion Axis object"},
		{Key: "motion.get_hookup_test_data", Name: "Get Hookup Test Data", Service: "0x54", Class: "0x42", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Motion Axis object"},
		{Key: "energy.start_metering", Name: "Start Metering", Service: "0x4B", Class: "0x4E", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Energy Base object"},
		{Key: "energy.stop_metering", Name: "Stop Metering", Service: "0x4C", Class: "0x4E", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Energy Base object"},
		{Key: "safety.supervisor_reset", Name: "Safety Reset", Service: "0x54", Class: "0x39", Instance: "0x01", Attribute: "0x00", Scope: "core", Notes: "Safety Supervisor object", Payload: CatalogPayload{Type: "safety_reset"}},
		{Key: "safety.validator_reset_errors", Name: "Reset Error Counters", Service: "0x4B", Class: "0x3A", Instance: "0x00", Attribute: "0x00", Scope: "core", Notes: "Safety Validator object", Payload: CatalogPayload{Type: "safety_reset"}},
		{Key: "rockwell.execute_pccc", Name: "Execute PCCC", Service: "0x4B", Class: "0x0067", Instance: "0x0001", Attribute: "0x0000", Scope: "vendor", Vendor: "rockwell", Notes: "Requires PCCC payload", Payload: CatalogPayload{Type: "rockwell_pccc"}},
		{Key: "rockwell.read_tag", Name: "Read Tag", Service: "0x4C", Class: "0x006B", Instance: "0x0001", Attribute: "0x0000", Scope: "vendor", Vendor: "rockwell", Notes: "Requires tag payload and symbolic path support", Payload: CatalogPayload{Type: "rockwell_tag"}},
		{Key: "rockwell.write_tag", Name: "Write Tag", Service: "0x4D", Class: "0x006B", Instance: "0x0001", Attribute: "0x0000", Scope: "vendor", Vendor: "rockwell", Notes: "Requires tag payload and symbolic path support", Payload: CatalogPayload{Type: "rockwell_tag"}},
		{Key: "rockwell.read_tag_fragmented", Name: "Read Tag Fragmented", Service: "0x52", Class: "0x006B", Instance: "0x0001", Attribute: "0x0000", Scope: "vendor", Vendor: "rockwell", Notes: "Requires tag payload and symbolic path support", Payload: CatalogPayload{Type: "rockwell_tag_fragmented"}},
		{Key: "rockwell.write_tag_fragmented", Name: "Write Tag Fragmented", Service: "0x53", Class: "0x006B", Instance: "0x0001", Attribute: "0x0000", Scope: "vendor", Vendor: "rockwell", Notes: "Requires tag payload and symbolic path support", Payload: CatalogPayload{Type: "rockwell_tag_fragmented"}},
		{Key: "rockwell.template_read", Name: "Template Read", Service: "0x4C", Class: "0x006C", Instance: "0x0001", Attribute: "0x0000", Scope: "vendor", Vendor: "rockwell", Notes: "Requires template payload", Payload: CatalogPayload{Type: "rockwell_template"}},
	}
	return CatalogFile{
		Version: 1,
		Name:    "extended",
		Entries: entries,
	}
}

// ListCatalogEntries returns all catalog entries under workspace/catalogs.
func ListCatalogEntries(workspaceRoot string) ([]CatalogEntry, error) {
	catalogDir := filepath.Join(workspaceRoot, "catalogs")
	entries, err := os.ReadDir(catalogDir)
	if err != nil {
		return nil, fmt.Errorf("read catalogs dir: %w", err)
	}
	all := make([]CatalogEntry, 0)
	byKey := make(map[string]CatalogEntry)
	order := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		path := filepath.Join(catalogDir, entry.Name())
		catalog, err := LoadCatalogFile(path)
		if err != nil {
			continue
		}
		for _, item := range catalog.Entries {
			key := strings.TrimSpace(item.Key)
			if key == "" {
				continue
			}
			existing, ok := byKey[key]
			if !ok {
				byKey[key] = item
				order = append(order, key)
				continue
			}
			if betterCatalogEntry(item, existing) {
				byKey[key] = item
			}
		}
	}
	for _, key := range order {
		if entry, ok := byKey[key]; ok {
			all = append(all, entry)
		}
	}
	return all, nil
}

// ListCatalogSources returns the catalog YAML filenames under workspace/catalogs.
func ListCatalogSources(workspaceRoot string) ([]string, error) {
	catalogDir := filepath.Join(workspaceRoot, "catalogs")
	entries, err := os.ReadDir(catalogDir)
	if err != nil {
		return nil, fmt.Errorf("read catalogs dir: %w", err)
	}
	names := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		names = append(names, entry.Name())
	}
	return names, nil
}

// FindCatalogEntry looks up a catalog entry by key.
func FindCatalogEntry(entries []CatalogEntry, key string) *CatalogEntry {
	for _, entry := range entries {
		if entry.Key == key {
			return &entry
		}
	}
	return nil
}

// FilterCatalogEntries filters catalog entries by a search query.
func FilterCatalogEntries(entries []CatalogEntry, query string) []CatalogEntry {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return entries
	}
	matches := make([]CatalogEntry, 0)
	for _, entry := range entries {
		if catalogEntryMatches(entry, query) {
			matches = append(matches, entry)
		}
	}
	return matches
}

func catalogEntryMatches(entry CatalogEntry, query string) bool {
	if strings.Contains(strings.ToLower(entry.Key), query) ||
		strings.Contains(strings.ToLower(entry.Name), query) ||
		strings.Contains(strings.ToLower(entry.Scope), query) ||
		strings.Contains(strings.ToLower(entry.Vendor), query) ||
		strings.Contains(strings.ToLower(entry.Notes), query) ||
		strings.Contains(strings.ToLower(entry.Class), query) ||
		strings.Contains(strings.ToLower(entry.Service), query) ||
		strings.Contains(strings.ToLower(entry.Payload.Type), query) {
		return true
	}

	if serviceAlias := resolveServiceAlias(entry.Service); serviceAlias != "" {
		if strings.Contains(serviceAlias, query) {
			return true
		}
	}
	if classAlias := resolveClassAlias(entry.Class); classAlias != "" {
		if strings.Contains(classAlias, query) {
			return true
		}
	}
	return false
}

func resolveServiceAlias(value string) string {
	if code, ok := parseServiceValue(value); ok {
		if alias, ok := cipclient.ServiceAliasName(code); ok {
			return strings.ToLower(alias)
		}
	}
	if alias, ok := cipclient.ParseServiceAlias(value); ok {
		if name, ok := cipclient.ServiceAliasName(alias); ok {
			return strings.ToLower(name)
		}
	}
	return ""
}

func resolveClassAlias(value string) string {
	if code, ok := parseClassValue(value); ok {
		if alias, ok := cipclient.ClassAliasName(code); ok {
			return strings.ToLower(alias)
		}
	}
	if alias, ok := cipclient.ParseClassAlias(value); ok {
		if name, ok := cipclient.ClassAliasName(alias); ok {
			return strings.ToLower(name)
		}
	}
	return ""
}

func parseServiceValue(value string) (uint8, bool) {
	if code, err := strconv.ParseUint(strings.TrimSpace(value), 0, 8); err == nil {
		return uint8(code), true
	}
	if code, ok := cipclient.ParseServiceAlias(value); ok {
		return code, true
	}
	return 0, false
}

func parseClassValue(value string) (uint16, bool) {
	if code, err := strconv.ParseUint(strings.TrimSpace(value), 0, 16); err == nil {
		return uint16(code), true
	}
	if code, ok := cipclient.ParseClassAlias(value); ok {
		return code, true
	}
	return 0, false
}

func betterCatalogEntry(candidate, existing CatalogEntry) bool {
	return catalogEntryScore(candidate) > catalogEntryScore(existing)
}

func catalogEntryScore(entry CatalogEntry) int {
	score := 0
	if strings.TrimSpace(entry.Scope) != "" {
		score += 2
	}
	if strings.TrimSpace(entry.Vendor) != "" {
		score += 2
	}
	if strings.TrimSpace(entry.Notes) != "" {
		score++
	}
	if strings.TrimSpace(entry.PayloadHex) != "" {
		score++
	}
	if strings.TrimSpace(entry.Payload.Type) != "" {
		score++
	}
	if len(entry.Payload.Params) > 0 {
		score++
	}
	return score
}
