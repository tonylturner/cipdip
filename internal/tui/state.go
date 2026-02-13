package tui

import (
	"context"
	"time"

	"github.com/tonylturner/cipdip/internal/cip/catalog"
	"github.com/tonylturner/cipdip/internal/orch/controller"
	"github.com/tonylturner/cipdip/internal/ui"
)

// Type aliases from catalog package - single source of truth
type CatalogEntry = catalog.Entry
type CatalogFile = catalog.File
type Catalog = catalog.Catalog
type ServiceGroup = catalog.ServiceGroup

// Type aliases from ui package to consolidate duplicates
type StatsUpdate = ui.StatsUpdate
type CommandResult = ui.CommandResult
type ProfileInfo = ui.ProfileInfo

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
	Profiles []ProfileInfo
	Runs     []string

	// Catalog - single source of truth from /catalogs/core.yaml
	CatalogInstance *Catalog // The loaded catalog with lookup methods
	CatalogEntries  []*CatalogEntry
	CatalogGroups   []*ServiceGroup

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

	// Orchestration state
	OrchRunning  bool
	OrchCtx      context.Context
	OrchCancel   context.CancelFunc
	OrchOutputCh <-chan controller.OutputEvent
	OrchPhaseCh  <-chan orchPhaseUpdateMsg

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

// Helper functions for loading catalog - uses internal/cip/catalog

// LoadCoreCatalog loads the core catalog from /catalogs/core.yaml.
// This is the single source of truth for all catalog operations.
func LoadCoreCatalog() (*Catalog, error) {
	// Find the core catalog relative to current working directory
	catalogPath, err := catalog.FindCoreCatalog(".")
	if err != nil {
		return nil, err
	}

	file, err := catalog.LoadAndValidate(catalogPath)
	if err != nil {
		return nil, err
	}

	return catalog.NewCatalog(file), nil
}

// FindCatalogEntry finds a catalog entry by key using the catalog instance.
func FindCatalogEntry(cat *Catalog, key string) (*CatalogEntry, bool) {
	if cat == nil {
		return nil, false
	}
	return cat.Lookup(key)
}

// SearchCatalog searches for entries matching a query.
func SearchCatalog(cat *Catalog, query string) []*CatalogEntry {
	if cat == nil {
		return nil
	}
	return cat.Search(query)
}
