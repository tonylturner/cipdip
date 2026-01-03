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
	Key        string `yaml:"key"`
	Name       string `yaml:"name"`
	Service    string `yaml:"service"`
	Class      string `yaml:"class"`
	Instance   string `yaml:"instance"`
	Attribute  string `yaml:"attribute"`
	Scope      string `yaml:"scope,omitempty"`
	Vendor     string `yaml:"vendor,omitempty"`
	Notes      string `yaml:"notes,omitempty"`
	PayloadHex string `yaml:"payload_hex,omitempty"`
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

// ListCatalogEntries returns all catalog entries under workspace/catalogs.
func ListCatalogEntries(workspaceRoot string) ([]CatalogEntry, error) {
	catalogDir := filepath.Join(workspaceRoot, "catalogs")
	entries, err := os.ReadDir(catalogDir)
	if err != nil {
		return nil, fmt.Errorf("read catalogs dir: %w", err)
	}
	all := make([]CatalogEntry, 0)
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
		all = append(all, catalog.Entries...)
	}
	return all, nil
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
		strings.Contains(strings.ToLower(entry.Service), query) {
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
