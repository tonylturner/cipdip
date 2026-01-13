package catalog

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadCoreCatalog(t *testing.T) {
	path := findCoreCatalogPath(t)

	file, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if file.Version != 1 {
		t.Errorf("expected version 1, got %d", file.Version)
	}

	if file.Name != "core" {
		t.Errorf("expected name 'core', got %q", file.Name)
	}

	if len(file.Entries) == 0 {
		t.Fatal("expected entries, got none")
	}

	// Verify first entry
	e := file.Entries[0]
	if e.Key != "identity.vendor_id" {
		t.Errorf("expected first key 'identity.vendor_id', got %q", e.Key)
	}
	if e.ServiceCode != 0x0E {
		t.Errorf("expected service_code 0x0E, got 0x%02X", e.ServiceCode)
	}
	if e.ObjectClass != 0x01 {
		t.Errorf("expected object_class 0x01, got 0x%02X", e.ObjectClass)
	}
	if e.EPATH.Kind != EPATHLogical {
		t.Errorf("expected epath.kind 'logical', got %q", e.EPATH.Kind)
	}
	if e.EPATH.Attribute != 0x01 {
		t.Errorf("expected epath.attribute 0x01, got 0x%02X", e.EPATH.Attribute)
	}
}

func TestCatalogValidation(t *testing.T) {
	path := findCoreCatalogPath(t)

	file, err := LoadAndValidate(path)
	if err != nil {
		t.Fatalf("LoadAndValidate failed: %v", err)
	}

	// Ensure basic validation passes
	if err := file.Validate(); err != nil {
		t.Errorf("Validate failed: %v", err)
	}
}

func TestCatalogLookup(t *testing.T) {
	path := findCoreCatalogPath(t)

	file, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	c := NewCatalog(file)

	// Test lookup by key
	entry, ok := c.Lookup("identity.vendor_id")
	if !ok {
		t.Fatal("lookup identity.vendor_id failed")
	}
	if entry.ServiceCode != 0x0E {
		t.Errorf("expected service 0x0E, got 0x%02X", entry.ServiceCode)
	}

	// Test lookup non-existent
	_, ok = c.Lookup("nonexistent.key")
	if ok {
		t.Error("expected lookup of nonexistent key to return false")
	}

	// Test lookup by service+class
	entries := c.LookupByServiceClass(0x0E, 0x01) // Get_Attribute_Single on Identity
	if len(entries) == 0 {
		t.Error("expected entries for service 0x0E, class 0x01")
	}

	// Verify all returned entries match
	for _, e := range entries {
		if e.ServiceCode != 0x0E || e.ObjectClass != 0x01 {
			t.Errorf("entry %s has wrong service/class", e.Key)
		}
	}
}

func TestCatalogDomainFilter(t *testing.T) {
	path := findCoreCatalogPath(t)

	file, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	c := NewCatalog(file)

	// Test core domain
	coreEntries := c.ListByDomain(DomainCore)
	if len(coreEntries) == 0 {
		t.Error("expected core domain entries")
	}
	for _, e := range coreEntries {
		if e.Domain != DomainCore {
			t.Errorf("entry %s has domain %s, expected core", e.Key, e.Domain)
		}
	}

	// Test logix domain
	logixEntries := c.ListByDomain(DomainLogix)
	if len(logixEntries) == 0 {
		t.Error("expected logix domain entries")
	}
	for _, e := range logixEntries {
		if e.Domain != DomainLogix {
			t.Errorf("entry %s has domain %s, expected logix", e.Key, e.Domain)
		}
	}
}

func TestCatalogGroups(t *testing.T) {
	path := findCoreCatalogPath(t)

	file, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	c := NewCatalog(file)

	groups := c.Groups()
	if len(groups) == 0 {
		t.Fatal("expected service groups")
	}

	// Find identity group
	var identityGroup *ServiceGroup
	for _, g := range groups {
		if g.ServiceCode == 0x0E && g.ObjectClass == 0x01 {
			identityGroup = g
			break
		}
	}

	if identityGroup == nil {
		t.Fatal("expected identity attribute group (0x0E, 0x01)")
	}

	if len(identityGroup.Entries) < 7 {
		t.Errorf("expected at least 7 identity attributes, got %d", len(identityGroup.Entries))
	}

	// Test target preview
	preview := identityGroup.TargetPreview(3)
	if preview == "" || preview == "-" {
		t.Errorf("expected target preview, got %q", preview)
	}
}

func TestCatalogSearch(t *testing.T) {
	path := findCoreCatalogPath(t)

	file, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	c := NewCatalog(file)

	// Search for "vendor"
	results := c.Search("vendor")
	if len(results) == 0 {
		t.Error("expected results for 'vendor' search")
	}

	// Search for "read_tag"
	results = c.Search("read_tag")
	if len(results) == 0 {
		t.Error("expected results for 'read_tag' search")
	}

	// Verify at least one result is symbol.read_tag
	found := false
	for _, e := range results {
		if e.Key == "symbol.read_tag" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected symbol.read_tag in search results")
	}
}

func TestValidateAgainstSpec(t *testing.T) {
	path := findCoreCatalogPath(t)

	file, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	c := NewCatalog(file)
	result := ValidateAgainstSpec(c)

	// Log warnings (acceptable)
	for _, w := range result.Warnings {
		t.Logf("warning: %v", w)
	}

	// Errors should be zero
	if len(result.Errors) > 0 {
		for _, e := range result.Errors {
			t.Errorf("validation error: %v", e)
		}
	}
}

func TestEntryToCIPRequest(t *testing.T) {
	path := findCoreCatalogPath(t)

	file, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	c := NewCatalog(file)

	entry, ok := c.Lookup("identity.vendor_id")
	if !ok {
		t.Fatal("lookup failed")
	}

	req := entry.ToCIPRequest()
	if req.Service != 0x0E {
		t.Errorf("expected service 0x0E, got 0x%02X", req.Service)
	}
	if req.Path.Class != 0x01 {
		t.Errorf("expected class 0x01, got 0x%02X", req.Path.Class)
	}
	if req.Path.Instance != 0x01 {
		t.Errorf("expected instance 0x01, got 0x%02X", req.Path.Instance)
	}
	if req.Path.Attribute != 0x01 {
		t.Errorf("expected attribute 0x01, got 0x%02X", req.Path.Attribute)
	}
}

func findCoreCatalogPath(t *testing.T) string {
	t.Helper()

	// Get the directory of this test file
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get caller info")
	}

	// Navigate up to repo root and find catalogs/core.yaml
	dir := filepath.Dir(filename)
	for i := 0; i < 5; i++ {
		path := filepath.Join(dir, "catalogs", "core.yaml")
		if fileExists(path) {
			return path
		}
		dir = filepath.Dir(dir)
	}

	t.Fatal("could not find catalogs/core.yaml")
	return ""
}

func fileExists(path string) bool {
	_, err := Load(path)
	return err == nil
}
