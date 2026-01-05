package ui

import (
	"path/filepath"
	"testing"
)

func TestListCatalogEntries(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	if _, err := CreateWorkspace(root, "catalogs"); err != nil {
		t.Fatalf("CreateWorkspace failed: %v", err)
	}
	catalog := CatalogFile{
		Version: 1,
		Name:    "core",
		Entries: []CatalogEntry{
			{Key: "identity.vendor_id", Name: "Vendor ID", Service: "0x0E", Class: "0x01", Instance: "0x01", Attribute: "0x01"},
		},
	}
	path := filepath.Join(root, "catalogs", "core.yaml")
	if err := SaveCatalogFile(path, catalog); err != nil {
		t.Fatalf("SaveCatalogFile failed: %v", err)
	}
	entries, err := ListCatalogEntries(root)
	if err != nil {
		t.Fatalf("ListCatalogEntries failed: %v", err)
	}
	if len(entries) < 1 {
		t.Fatalf("expected at least 1 entry, got %d", len(entries))
	}
	found := false
	for _, entry := range entries {
		if entry.Key == "identity.vendor_id" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected identity.vendor_id in catalog entries")
	}
}

func TestFilterCatalogEntries(t *testing.T) {
	entries := []CatalogEntry{
		{Key: "identity.vendor_id", Name: "Vendor ID", Service: "0x0E", Class: "0x01"},
		{Key: "identity.product_name", Name: "Product Name", Service: "0x0E", Class: "0x01"},
	}
	filtered := FilterCatalogEntries(entries, "vendor")
	if len(filtered) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(filtered))
	}
	if filtered[0].Key != "identity.vendor_id" {
		t.Fatalf("unexpected entry key: %s", filtered[0].Key)
	}
}
