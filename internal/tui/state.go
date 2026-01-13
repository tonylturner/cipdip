package tui

import (
	"context"
	"time"

	"github.com/tturner/cipdip/internal/app"
	"github.com/tturner/cipdip/internal/ui"
)

// Type aliases from app package for convenience
type CatalogEntry = app.CatalogEntry
type CatalogPayload = app.CatalogPayload
type CatalogFile = app.CatalogFile

// Type aliases from ui package to consolidate duplicates
type StatsUpdate = ui.StatsUpdate
type CommandResult = ui.CommandResult

// ProfileInfo contains information about a profile.
type ProfileInfo struct {
	Path string
	Name string
	Kind string
}

// RecentRun represents a recent operation for display.
type RecentRun struct {
	Time       time.Time
	Type       string // "client", "server", "pcap"
	Details    string // scenario name, file, etc.
	Target     string // IP or file
	Status     string // "running", "ok", "error"
	Count      int    // request count or packet count
	ErrorCount int
}

// AppState holds shared state across all screens.
type AppState struct {
	// Workspace
	WorkspaceRoot string
	WorkspaceName string

	// Cached data
	Profiles       []ProfileInfo
	Runs           []string
	Catalog        []CatalogEntry
	CatalogSources []string

	// Active operations
	ServerRunning    bool
	ServerCtx        context.Context
	ServerCancel     context.CancelFunc
	ServerStatsChan  <-chan StatsUpdate
	ServerResultChan <-chan CommandResult
	ClientRunning    bool
	ClientCtx        context.Context
	ClientCancel     context.CancelFunc
	ClientStatsChan  <-chan StatsUpdate
	ClientResultChan <-chan CommandResult

	// Recent runs for main menu
	RecentRuns []RecentRun
}

// NewAppState creates a new AppState for a workspace.
func NewAppState(workspaceRoot, workspaceName string) *AppState {
	return &AppState{
		WorkspaceRoot: workspaceRoot,
		WorkspaceName: workspaceName,
	}
}

// Helper functions for loading data - these delegate to app package

// LoadCatalogFile loads a catalog file.
func LoadCatalogFile(path string) (*CatalogFile, error) {
	return app.LoadCatalogFile(path)
}

// SaveCatalogFile saves a catalog file.
func SaveCatalogFile(path string, catalog CatalogFile) error {
	return app.SaveCatalogFile(path, catalog)
}

// ListCatalogEntries lists all catalog entries in a workspace.
func ListCatalogEntries(workspaceRoot string) ([]CatalogEntry, error) {
	return app.ListCatalogEntries(workspaceRoot)
}

// ListCatalogSources lists catalog source files in a workspace.
func ListCatalogSources(workspaceRoot string) ([]string, error) {
	return app.ListCatalogSources(workspaceRoot)
}

// FindCatalogEntry finds a catalog entry by key.
func FindCatalogEntry(entries []CatalogEntry, key string) *CatalogEntry {
	return app.FindCatalogEntry(entries, key)
}

// FilterCatalogEntries filters catalog entries by query.
func FilterCatalogEntries(entries []CatalogEntry, query string) []CatalogEntry {
	return app.FilterCatalogEntries(entries, query)
}
