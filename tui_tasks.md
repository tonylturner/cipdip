# TUI Refactor Tasks

Tracking progress for the TUI refactor based on `notes/TUI_SPEC.md` v3.0.

## Phase 1: Core Architecture

- [x] Create new screen-based model structure (`internal/ui/screens.go`)
- [x] Define Screen enum and AppState struct
- [x] Implement global key handling (q, m, ?, Esc)
- [x] Create base screen interface with Init/Update/View

## Phase 2: Main Menu Screen

- [x] Create `internal/ui/screen_main.go`
- [x] Implement main menu with [c]/[s]/[p]/[k]/[r] navigation
- [x] Show recent runs with status indicators
- [x] Display running server status if active

## Phase 3: Client Screen

- [x] Create `internal/ui/screen_client.go`
- [x] Implement target IP/port input fields
- [x] Add scenario radio selection (baseline, mixed, stress, io, edge)
- [x] Show config summary when loaded
- [x] Implement command preview (always visible)
- [x] Add running state with live statistics
- [x] Implement stop/pause controls

## Phase 4: Server Screen

- [x] Create `internal/ui/screen_server.go`
- [x] Implement listen IP/port configuration
- [x] Add personality selection (adapter, logix_like)
- [x] Show command preview
- [x] Implement running state with connection list
- [x] Add request log display

## Phase 5: PCAP Screen

- [x] Create `internal/ui/screen_pcap.go`
- [x] Implement file path input
- [x] Add action menu (summary, report, coverage, replay, rewrite, dump)
- [x] Create replay configuration sub-view
- [x] Show command preview for each action

## Phase 6: Catalog Screen

- [x] Create `internal/ui/screen_catalog.go`
- [x] Implement class list with filter
- [x] Add expandable class detail view
- [x] Create probe dialog for attributes
- [x] Implement copy path functionality

## Phase 7: Runs Screen

- [x] Create `internal/ui/screen_runs.go`
- [x] Implement run history list with filters
- [x] Create run detail view
- [x] Add artifact viewer (open, re-run, copy command)

## Phase 8: Help System

- [x] Implement context-sensitive help overlay
- [x] Add screen-specific help content
- [x] Ensure help toggle works on all screens

## Phase 9: Error Handling

- [x] Implement inline validation errors
- [x] Add status bar for runtime errors
- [x] Create fatal error screen with recovery options

## Phase 10: Run Artifacts

- [x] Ensure all runs save command.txt, stdout.log, summary.json (existing code)
- [x] Implement automatic artifact directory creation (existing code)
- [x] Add artifact loading for run history

## Phase 11: Integration & Cleanup

- [x] Update `RunTUI` entry point to use `RunTUIV2`
- [x] Remove unused TUI code (RenderHomeScreenWithCursor, RenderPaletteView)
- [x] Keep CLI helpers (palette, wizard, home, review, plan) for --cli mode
- [x] Update existing tests
- [x] Add new tests for screen transitions (done in Phase 13)
- [x] Verify all keybindings work correctly

## Phase 12: Testing

- [x] Existing tests pass (`go test ./internal/ui/...`)
- [ ] Add screen navigation tests
- [ ] Add command preview tests

---

## Progress Notes

### 2026-01-10: Initial Implementation Complete

Created new screen-based TUI architecture:

**New Files:**
- `internal/ui/screens.go` - Core model, AppState, styles, global key handling
- `internal/ui/screen_main.go` - Main menu with [c]/[s]/[p]/[k]/[r] navigation
- `internal/ui/screen_client.go` - Client configuration and running state
- `internal/ui/screen_server.go` - Server emulator configuration and monitoring
- `internal/ui/screen_pcap.go` - PCAP tools with action selection
- `internal/ui/screen_catalog.go` - CIP catalog browser with probe dialog
- `internal/ui/screen_runs.go` - Run history with filtering and detail view

**Key Changes:**
- Flat navigation model (all screens reachable via single keypress)
- Command preview always visible on configuration screens
- Context-sensitive help overlay (press `?` on any screen)
- Consistent footer showing available keys per screen
- Running state views for client/server with live stats

**Entry Point:**
- Created `RunTUIV2()` function that uses new Model
- Updated `cmd/cipdip/ui.go` to use `RunTUIV2` for `--tui` flag
- Old `RunTUI()` preserved for backward compatibility

**Testing:**
- All existing UI tests pass
- Build succeeds with no errors
- Note: Pre-existing test failures in `internal/cip/client` unrelated to TUI changes

**Remaining Work:**
- Add screen navigation tests (optional)

### 2026-01-10: TUI Improvements Complete

**Changes Made:**
- Deleted old TUI files: `tui.go`, `wizard_form.go`, `workspace_form.go` (~2,265 lines removed)
- Improved main menu with timestamp/status display for recent runs
- Wired up actual command execution in Client, Server, and PCAP screens
- All screens now create run artifacts (command.txt, stdout.log, summary.json)
- Commands execute asynchronously with proper cancellation support

**Code Quality:**
- Removed duplicate code by extracting `buildCommandArgs()` methods
- Added `LoadRunSummary()` helper for efficient status display
- All builds pass, all UI tests pass
- Pre-existing failures in `internal/cip/client` (ODVA compliance tests) are unrelated

---

## Phase 13: Polish & Advanced Features

### 13.1 Screen Navigation Tests
- [x] Add tests for main menu navigation (c/s/p/k/r keys)
- [x] Add tests for global keys (q, m, ?, Esc)
- [x] Add tests for screen-specific key handling
- [x] Add command preview tests

### 13.2 PCAP File Browser
- [x] Implement directory listing component
- [x] Add file selection with filtering (*.pcap, *.pcapng)
- [x] Navigate with arrow keys, Enter to select
- [x] Show file size and modification time

### 13.3 Live Stats During Runs
- [x] Add ticker message for periodic updates
- [x] Update client screen with request counts, latency
- [x] Update server screen with connection count, uptime
- [x] Show elapsed time counter

### 13.4 Catalog Probe Execution
- [x] Wire up probe dialog to execute `cipdip single` command
- [x] Display probe result in dialog
- [x] Save probe results to run artifacts

### 13.5 Runs Screen Artifact Viewer
- [x] Implement 'o' key to open artifact in $EDITOR
- [x] Implement 'r' key to re-run command
- [x] Show stdout.log preview in detail view
- [x] Add delete confirmation dialog

---

### 2026-01-10: Phase 13 Complete

**13.1 Screen Navigation Tests (`screens_test.go`):**
- Tests for main menu navigation (c/s/p/k/r keys)
- Tests for global keys (m returns to main, ? shows help, Esc clears error/closes help)
- Tests for arrow navigation and Enter to select
- Tests for scenario selection and command preview generation
- Tests for all screen command previews (client, server, PCAP, catalog)

**13.2 PCAP File Browser (`screen_pcap.go`):**
- Added `FileEntry` struct for directory listing
- Implemented `openFileBrowser()`, `loadDirectory()`, `updateFileBrowser()`, `viewFileBrowser()`
- Filters to show only .pcap and .pcapng files
- Navigate with arrow keys, Enter to select, h/left for parent directory
- Shows file size and modification time

**13.3 Live Stats During Runs (`screens.go`):**
- Added `tickMsg` and `tickCmd()` for periodic updates
- Added `handleTick()` to update elapsed time on client and uptime on server
- Ticks every 1 second when running, 5 seconds when idle
- Added `StartTime *time.Time` to ClientScreenModel and ServerScreenModel

**13.4 Catalog Probe Execution (`screen_catalog.go`):**
- Wired up probe dialog to execute `cipdip single` command
- `runProbe()` executes command and returns `probeResultMsg`
- `buildProbeCommandArgs()` constructs proper command line
- Results saved to run artifacts

**13.5 Runs Screen Artifact Viewer (`screen_runs.go`):**
- 'o' key opens artifact in $EDITOR (falls back to `less`)
- 'r' key re-runs the saved command
- 'd' key with y/n confirmation to delete runs
- `viewDetail()` now shows stdout.log preview (first 8 lines)
- Added `rerunResultMsg` and handler

---

### 2026-01-10: Phase 14 Complete - Final Polish

**14.1 Code Cleanup:**
- Removed unused `RenderHomeScreenWithCursor` and `RenderPaletteView` functions from home.go
- Simplified `RenderHomeScreen` for CLI-only usage (no cursor tracking)
- Updated home screen tip to "use --tui for interactive mode"
- Kept CLI helpers (palette, wizard, home, review, plan) for --cli mode compatibility

**14.2 Documentation:**
- Created `docs/TUI_GUIDE.md` with complete TUI documentation
  - Navigation guide with all keybindings
  - Screen-by-screen documentation
  - Workspace usage instructions
  - Non-interactive mode examples
- Updated `docs/EXAMPLES.md` to reference the TUI as the recommended starting point

**14.3 Integration Tests:**
- Added tests for message handling: WindowSizeMsg, tickMsg, errorMsg, clearErrorMsg
- Added tests for run result messages: runResultMsg, serverStatusMsg
- Added tests for fatal error screen handling
- Added view rendering tests for all 6 screens
- Added filter tests for catalog and runs screens
- Added input tests: IP entry, backspace, personality selection
- Added catalog probe dialog tests

**14.4 Testing & Verification:**
- All tests pass (`go test ./internal/ui/...`)
- Build succeeds with no warnings (`go vet ./internal/ui/...`)
- CLI modes work correctly (`--home`, `--catalog`, `--palette`)
- Known limitation: `openArtifact` uses `cmd.Start()` which may have display issues with TUI editors

---

### 2026-01-10: Bug Fixes

**Bug 1: Edit config not working in client/server mode**
- The 'e' key handler had a TODO comment instead of actual implementation
- Added full editor opening logic to both client and server screens
- Creates default config path if not set
- Creates template config file if it doesn't exist
- Opens file in $EDITOR using `OpenEditor()` function
- Added `os` and `path/filepath` imports

**Bug 2: Esc key navigation on screens**
- Global esc handler was consuming the keypress before screens could handle it
- Fixed by only consuming esc at global level if there's an error to clear
- Otherwise, esc passes through to screen-specific handlers for back navigation
- Sub-views (catalog expanded, PCAP file browser, runs detail) now handle esc correctly

**Bug 3: Catalog showing entries with same hex code**
- Display was showing only Class value (e.g., 0x01) for each entry
- Many entries share the same class but have different instances/attributes
- Changed display to show full Class/Instance/Attribute path
- Now shows "0x01/0x01/0x01" instead of just "0x01"
- Each entry is now visually distinct
