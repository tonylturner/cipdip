package ui

import "github.com/tturner/cipdip/internal/app"

// Note: Workspace-based catalogs have been removed.
// The single source of truth is /catalogs/core.yaml at repo root.
// See internal/cip/catalog for the canonical catalog implementation.

// These legacy types and functions are kept for backward compatibility
// with existing code that uses them (e.g., single command, emit-bytes).

type CatalogEntry = app.CatalogEntry
type CatalogPayload = app.CatalogPayload
type CatalogFile = app.CatalogFile

func ListCatalogEntries(workspaceRoot string) ([]CatalogEntry, error) {
	return app.ListCatalogEntries(workspaceRoot)
}

func ListCatalogSources(workspaceRoot string) ([]string, error) {
	return app.ListCatalogSources(workspaceRoot)
}

func FindCatalogEntry(entries []CatalogEntry, key string) *CatalogEntry {
	return app.FindCatalogEntry(entries, key)
}

func FilterCatalogEntries(entries []CatalogEntry, query string) []CatalogEntry {
	return app.FilterCatalogEntries(entries, query)
}
