package catalog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads a catalog from a YAML file.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog file: %w", err)
	}

	var file File
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse catalog YAML: %w", err)
	}

	return &file, nil
}

// LoadAndValidate reads a catalog and validates it.
func LoadAndValidate(path string) (*File, error) {
	file, err := Load(path)
	if err != nil {
		return nil, err
	}

	if err := file.Validate(); err != nil {
		return nil, fmt.Errorf("validate catalog: %w", err)
	}

	return file, nil
}

// Save writes a catalog to a YAML file.
func Save(path string, file *File) error {
	data, err := yaml.Marshal(file)
	if err != nil {
		return fmt.Errorf("marshal catalog: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write catalog file: %w", err)
	}

	return nil
}

// FindCoreCatalog searches for core.yaml in standard locations.
func FindCoreCatalog(startDir string) (string, error) {
	// Try explicit path first
	candidates := []string{
		filepath.Join(startDir, "catalogs", "core.yaml"),
		filepath.Join(startDir, "core.yaml"),
	}

	// Walk up from startDir looking for catalogs/core.yaml
	dir := startDir
	for i := 0; i < 10; i++ {
		path := filepath.Join(dir, "catalogs", "core.yaml")
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("core.yaml not found in %s or parent directories", startDir)
}

// Catalog provides indexed access to catalog entries.
type Catalog struct {
	file      *File
	byKey     map[string]*Entry
	bySvcCls  map[uint32][]*Entry // (service<<16 | class) -> entries
	byDomain  map[Domain][]*Entry
	groups    []*ServiceGroup
	groupsMap map[uint32]*ServiceGroup // (service<<16 | class) -> group
}

// NewCatalog creates an indexed catalog from a file.
func NewCatalog(file *File) *Catalog {
	c := &Catalog{
		file:      file,
		byKey:     make(map[string]*Entry),
		bySvcCls:  make(map[uint32][]*Entry),
		byDomain:  make(map[Domain][]*Entry),
		groupsMap: make(map[uint32]*ServiceGroup),
	}

	for _, e := range file.Entries {
		c.byKey[e.Key] = e

		key := uint32(e.ServiceCode)<<16 | uint32(e.ObjectClass)
		c.bySvcCls[key] = append(c.bySvcCls[key], e)
		c.byDomain[e.Domain] = append(c.byDomain[e.Domain], e)

		// Build or append to group
		if g, ok := c.groupsMap[key]; ok {
			g.Entries = append(g.Entries, e)
		} else {
			g := &ServiceGroup{
				ServiceCode: e.ServiceCode,
				ServiceName: e.ServiceName,
				ObjectClass: e.ObjectClass,
				ObjectName:  e.ObjectName,
				Domain:      e.Domain,
				Entries:     []*Entry{e},
			}
			c.groupsMap[key] = g
			c.groups = append(c.groups, g)
		}
	}

	return c
}

// Lookup finds an entry by key.
func (c *Catalog) Lookup(key string) (*Entry, bool) {
	e, ok := c.byKey[key]
	return e, ok
}

// MustLookup finds an entry by key or panics.
func (c *Catalog) MustLookup(key string) *Entry {
	e, ok := c.byKey[key]
	if !ok {
		panic(fmt.Sprintf("catalog key not found: %s", key))
	}
	return e
}

// LookupByServiceClass finds entries by service code and class.
func (c *Catalog) LookupByServiceClass(service uint8, class uint16) []*Entry {
	key := uint32(service)<<16 | uint32(class)
	return c.bySvcCls[key]
}

// ListByDomain returns entries filtered by domain.
func (c *Catalog) ListByDomain(domain Domain) []*Entry {
	return c.byDomain[domain]
}

// ListAll returns all entries.
func (c *Catalog) ListAll() []*Entry {
	return c.file.Entries
}

// Groups returns service groups for UI display.
func (c *Catalog) Groups() []*ServiceGroup {
	return c.groups
}

// GroupsByDomain returns groups filtered by domain.
func (c *Catalog) GroupsByDomain(domain Domain) []*ServiceGroup {
	var result []*ServiceGroup
	for _, g := range c.groups {
		if g.Domain == domain {
			result = append(result, g)
		}
	}
	return result
}

// Search finds entries matching query in key, name, or description.
func (c *Catalog) Search(query string) []*Entry {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return c.file.Entries
	}

	var matches []*Entry
	for _, e := range c.file.Entries {
		if strings.Contains(strings.ToLower(e.Key), query) ||
			strings.Contains(strings.ToLower(e.Name), query) ||
			strings.Contains(strings.ToLower(e.Description), query) ||
			strings.Contains(strings.ToLower(e.ServiceName), query) ||
			strings.Contains(strings.ToLower(e.ObjectName), query) {
			matches = append(matches, e)
		}
	}

	return matches
}

// File returns the underlying catalog file.
func (c *Catalog) File() *File {
	return c.file
}
