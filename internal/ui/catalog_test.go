package ui

import (
	"testing"
)

// Note: Workspace-based catalogs have been removed.
// The single source of truth is /catalogs/core.yaml at repo root.
// See internal/cip/catalog for the canonical catalog implementation.

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
