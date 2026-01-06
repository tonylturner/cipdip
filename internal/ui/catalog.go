package ui

import "github.com/tturner/cipdip/internal/app"

type CatalogEntry = app.CatalogEntry
type CatalogPayload = app.CatalogPayload
type CatalogFile = app.CatalogFile

func LoadCatalogFile(path string) (*CatalogFile, error) {
	return app.LoadCatalogFile(path)
}

func SaveCatalogFile(path string, catalog CatalogFile) error {
	return app.SaveCatalogFile(path, catalog)
}

func DefaultCatalog() CatalogFile {
	return app.DefaultCatalog()
}

func DefaultExtendedCatalog() CatalogFile {
	return app.DefaultExtendedCatalog()
}

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
