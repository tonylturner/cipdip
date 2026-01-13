# CIPDIP Distributed Orchestration Implementation Tasks

Tracking progress for Controller/Agent orchestration feature implementation.

**Spec Reference:** User-provided spec for distributed orchestration with SSH transport
**Start Date:** 2026-01-13
**Status:** COMPLETE - All 11 phases implemented

---

## Project Overview

### Summary
Implement a Controller/Agent orchestration model for cipdip that enables:
- Multi-host test coordination via SSH management channel
- Explicit control plane / data plane separation
- Run Manifests for declarative orchestration
- Run Bundles for self-describing artifact archives
- Enhanced diff UX for bundle comparison
- TUI extensions for Controller and Agent modes

### Architecture Notes
- **Existing packages to leverage:**
  - `internal/config` - YAML loading patterns
  - `internal/app` - CLI orchestration (client.go, server.go)
  - `internal/tui` - Dashboard TUI (bubbletea)
  - `internal/ui` - Screen-based UI patterns
  - `internal/pcap/diff.go` - Existing PCAP diff logic
  - `internal/artifact` - Output management
  - `internal/profile` - Process profile YAML format

- **New packages to create:**
  - `internal/orch` - Controller, plan, bundle
  - `internal/transport` - SSH, local transport abstraction
  - `internal/manifest` - Schema, load, resolve

---

## Phase 0: Legacy TUI Cleanup (COMPLETED 2026-01-13)

### Summary
Removed legacy TUI code while keeping all shared helper functions.

### Changes Made
1. **Removed `--classic` flag** from `cmd/cipdip/ui.go`
2. **Deleted 10 legacy TUI files** (~1,300 lines):
   - `screens.go`, `screens_test.go` (legacy model, RunTUIV2)
   - `screen_client.go`, `screen_server.go`, `screen_pcap.go`
   - `screen_catalog.go`, `screen_runs.go`, `screen_profile.go`
   - `screen_main.go`, `interface_selector.go`
3. **Added `presets.go`** with `ModePreset` and `ModePresets` (used by new TUI)
4. **Added `serverStatusMsg` type** to `exec.go` (was in deleted screens.go)

### Remaining Structure
```
internal/ui/           # 21 files - shared helpers only
  workspace.go         # Workspace management
  profile.go           # Profile loading
  run.go               # Run artifacts
  command.go           # Command building
  exec.go              # Command execution
  catalog.go           # Catalog helpers
  wizard.go            # Wizard profiles
  palette.go           # Command palette
  home.go              # CLI rendering
  plan.go              # Plan management
  review.go            # Review screen
  resolve.go           # Profile resolution
  editor.go            # Editor opening
  presets.go           # Mode presets (NEW)
  + test files

internal/tui/          # 17 files - Dashboard TUI (unchanged)
```

### Verification
- [x] `go build ./...` passes
- [x] `go test ./...` passes (all 31 packages)
- [x] No references to `--classic` flag remain in code

---

## Phase 1: Research & Planning (Current)

### 1.1 Codebase Review
- [x] Review project structure and architecture
- [x] Understand existing CLI command patterns (Cobra)
- [x] Review TUI architecture (bubbletea dashboard + panels)
- [x] Understand config/YAML loading patterns
- [x] Review existing pcap-diff implementation
- [x] Review artifact/output management
- [x] Review profile system for YAML format patterns
- [x] Verify all existing tests pass

### 1.2 Design Decisions
- [ ] Define Run Manifest YAML schema
- [ ] Define Run Bundle directory structure
- [ ] Design Transport interface
- [ ] Design Controller execution model
- [ ] Design server readiness check mechanism
- [ ] Plan TUI screen additions

---

## Phase 2: Run Manifest & Bundles (Local Only) - COMPLETED 2026-01-13

### 2.1 Manifest Package (`internal/manifest`)
- [x] Create package structure
- [x] Define manifest types (ManifestV1, Role, Network, Profile, Artifacts)
- [x] Implement YAML unmarshaling with api_version validation
- [x] Implement schema validation (required fields, role requirements)
- [x] Implement `LoadManifest(path string) (*Manifest, error)`
- [x] Write unit tests for schema validation
- [x] Write unit tests for YAML parsing edge cases

### 2.2 Manifest Resolution
- [x] Implement manifest resolver (paths, checksums, CLI args)
- [x] Generate `manifest_resolved.yaml` content
- [x] Compute profile checksums (sha256)
- [x] Expand role CLI arguments from manifest fields
- [x] Write unit tests for resolution

### 2.3 Run Bundle Structure (`internal/orch/bundle`)
- [x] Define bundle directory layout constants
- [x] Implement `CreateBundleDir(runID string) (string, error)`
- [x] Implement `WriteManifest(bundleDir string, manifest *Manifest)`
- [x] Implement `WriteResolvedManifest(bundleDir string, resolved *ResolvedManifest)`
- [x] Implement `WriteVersions(bundleDir string, versions *VersionInfo)`
- [x] Implement `WriteRoleMeta(bundleDir, role string, meta *RoleMeta)`
- [x] Implement `ComputeHashes(bundleDir string) (map[string]string, error)`
- [x] Implement `WriteHashes(bundleDir string, hashes map[string]string)`
- [x] Write unit tests for bundle creation

### 2.4 Bundle Verification
- [x] Implement `VerifyBundle(bundlePath string) (*VerifyResult, error)`
- [x] Check required files exist
- [x] Verify hashes match
- [x] Validate schema version
- [x] Check pcaps exist and non-empty
- [x] Write unit tests for verification

### 2.5 CLI: `cipdip bundle verify`
- [x] Create `cmd/cipdip/bundle.go`
- [x] Implement `newBundleCmd()` with `verify` subcommand
- [x] Wire verification to bundle package
- [x] Add to main.go
- [x] Write CLI tests

---

## Phase 3: Local Controller (No Remote) - COMPLETED 2026-01-13

### 3.1 Controller Core (`internal/orch/controller`)
- [x] Define Controller struct and options
- [x] Implement execution plan from manifest
- [x] Implement local role runner (exec.Command based)
- [x] Implement server readiness check (structured JSON line on stdout)
- [x] Implement TCP connect fallback for readiness
- [x] Implement timeout handling
- [x] Implement graceful + force stop
- [x] Write unit tests with mock roles

### 3.2 Execution Phases
- [x] Phase 1: Init (bundle creation, manifest resolution)
- [x] Phase 2: Profile staging (copy to bundle)
- [x] Phase 3: Start server role
- [x] Phase 4: Wait for server readiness
- [x] Phase 5: Start client role
- [x] Phase 6: Wait for client completion
- [x] Phase 7: Stop server role
- [x] Phase 8: Collect artifacts into bundle
- [x] Phase 9: Bundle finalization + verification
- [x] Phase 10: Optional analysis (stubbed)
- [x] Phase 11: Optional diff (stubbed)

### 3.3 CLI: `cipdip run manifest` (Local Mode)
- [x] Create `cmd/cipdip/run.go`
- [x] Implement `newRunCmd()` with `manifest` subcommand
- [x] Add flags: `--bundle-dir`, `--timeout`, `--dry-run`, `--no-analyze`, `--no-diff`, `--print-plan`, `--verbose`
- [x] Implement dry-run mode (validate + plan only)
- [x] Implement print-plan (render resolved execution plan)
- [x] Add to main.go
- [x] Write CLI tests for local execution

### 3.4 Server Readiness Enhancement
- [x] Modify server to emit JSON readiness line on stdout
- [x] Format: `{"event":"server_ready","listen":"ip:port"}`
- [x] Ensure backward compatibility (non-breaking change)
- [x] Document readiness check protocol (see docs/ORCHESTRATION.md)

---

## Phase 4: SSH Transport - COMPLETED 2026-01-13

### 4.1 Transport Interface (`internal/transport`)
- [x] Define `Transport` interface with Exec, ExecStream, Put, Get, Mkdir, Stat, Remove, Close
- [x] Define Options struct (timeout, retries)
- [x] Define SSHOptions struct (user, key, password, agent, host verification)
- [x] Create `transport/local.go` for local execution
- [x] Write unit tests for local transport

### 4.2 SSH Transport Implementation
- [x] Create `transport/ssh.go`
- [x] Implement SSH connection with key-based auth
- [x] SSH agent support
- [x] Implement `Exec` via SSH command execution
- [x] Implement `ExecStream` for long-running commands
- [x] Implement `Put` via SFTP
- [x] Implement `Get` via SFTP
- [x] Implement `Mkdir`
- [x] Implement `Stat`
- [x] Implement `Remove`
- [x] Handle host key verification (known_hosts by default)
- [x] InsecureIgnoreHost option for testing
- [x] Connection keep-alive support

### 4.3 Transport Parsing
- [x] Parse SSH URLs: `ssh://user@host:port?key=/path&insecure=true`
- [x] Parse bare hostnames: `host`, `user@host`, `user@host:port`
- [x] Create transport factory (`Parse`, `ParseWithOptions`)
- [x] Helper functions: `IsLocal`, `IsSSH`, `MustParse`
- [x] Write unit tests for URL parsing

---

## Phase 5: Remote Orchestration - COMPLETED 2026-01-13

### 5.1 Remote Server/Client Role
- [x] Created RoleRunner interface to abstract local vs remote execution
- [x] Implemented RemoteRunner using Transport interface
- [x] Remote command execution via transport.ExecStream
- [x] Remote readiness check via stdout parsing
- [x] Artifact collection from remote (stdout, stderr, PCAP files)

### 5.2 Controller Integration
- [x] Extended Controller Options with Agents map
- [x] Controller creates transports at init time
- [x] createRunner factory method for local vs remote runners
- [x] phaseStage pushes profiles to remote agents
- [x] phaseCollect uses CollectArtifacts on all runners
- [x] Controller.Close() cleans up transports

### 5.3 Agent Specification
- [x] Updated CLI with `--agent role=transport` flag
- [x] Support agent ID to transport mapping
- [x] ValidateAgents() method tests connectivity before run
- [x] HasRemoteAgents() helper method

### 5.4 Profile Distribution
- [x] Implemented push mode (profile copied to remote workdir)
- [x] Remote artifact collection via SFTP

**Files Created/Modified:**
```
internal/orch/controller/
  role_runner.go        # RoleRunner interface
  remote_runner.go      # RemoteRunner implementation
  remote_runner_test.go # Unit tests
  controller.go         # Updated with agent support
  controller_test.go    # Updated with agent tests

cmd/cipdip/
  run.go                # Added --agent flag
```

**Test Coverage:**
- RemoteRunner lifecycle (Start, Wait, Stop)
- RoleRunner interface verification
- Controller with agent mappings
- Agent validation
- Readiness detection via stdout

**All tests passing:** 35 packages

---

## Phase 6: CLI: Agent Command - COMPLETED 2026-01-13

### 6.1 Agent Command (`cipdip agent`)
- [x] Created `cmd/cipdip/agent.go`
- [x] Implemented `newAgentCmd()` with subcommands
- [x] `cipdip agent status` - Show local agent capabilities
- [x] `cipdip agent check <transport>` - Validate remote agent
- [x] Flags: `--json`, `--workdir`, `--timeout`
- [x] SSH-based agent model (no daemon required)
- [x] Added to main.go

### 6.2 Agent Capabilities Detection
- [x] Report cipdip version and build info
- [x] Report OS and architecture
- [x] Report available network interfaces with bind capability
- [x] Report workdir writability
- [x] Report pcap capture capability (tcpdump, tshark, bpf)

### 6.3 Remote Agent Checking
- [x] Connectivity validation via SSH
- [x] cipdip installation check
- [x] Remote OS/Arch detection
- [x] Remote workdir writable check
- [x] Remote pcap capability check
- [x] JSON output for scripting

**Files Created:**
```
cmd/cipdip/
  agent.go       # Agent command implementation
  agent_test.go  # Unit tests
```

**Usage Examples:**
```bash
# Check local agent capabilities
cipdip agent status
cipdip agent status --json

# Validate remote agent
cipdip agent check ssh://user@192.168.1.10
cipdip agent check user@server.local --timeout 30s
cipdip agent check host --json
```

**All tests passing:** 35 packages

---

## Phase 7: Diff Run UX Upgrade - COMPLETED 2026-01-13

### 7.1 Bundle-Aware Diff (`cipdip diff run`)
- [x] Created `cmd/cipdip/diff_run.go`
- [x] Implemented `newDiffRunCmd()` with subcommand structure
- [x] Auto-select comparable pcaps from bundles:
  - Default: `roles/client/client.pcap`
  - `--role client|server` flag
  - Falls back to first available PCAP if standard name not found
- [x] Load bundle metadata for context (RunMeta, RoleMeta)
- [x] Wraps existing pcap.DiffPCAPs for analysis
- [x] Added `--raw` flag for existing pcap-diff output (no bundle context)

### 7.2 Enhanced Diff Summary
- [x] DiffSummary struct with high-level metrics
- [x] Services added/removed/common counts
- [x] Classes added/removed/common counts
- [x] Packet and CIP message count deltas
- [x] P95 latency delta
- [x] Jitter delta
- [x] HasSignificantDiff flag
- [x] DiffScore (0-100) for quick comparison assessment
- [x] Output formats: text, JSON, markdown

**Files Created:**
```
cmd/cipdip/
  diff_run.go       # Diff run command implementation
  diff_run_test.go  # Unit tests
```

**Usage Examples:**
```bash
# Compare two bundles (default: client role)
cipdip diff run runs/baseline-run runs/test-run

# Compare server role
cipdip diff run --role server runs/run1 runs/run2

# JSON output for programmatic use
cipdip diff run --format json runs/baseline runs/compare -o diff.json

# Markdown report
cipdip diff run --format markdown runs/before runs/after -o report.md

# Raw pcap-diff output (no bundle context)
cipdip diff run --raw runs/run1 runs/run2
```

**All tests passing:** 35 packages

---

## Phase 8: TUI Extensions - COMPLETED 2026-01-13

### 8.1 TUI Architecture Planning
- [x] Review current Screen enum and panel system
- [x] Plan Controller page structure
- [x] Plan Agent page structure
- [x] Define navigation (maintain current patterns)

### 8.2 Controller Mode TUI
- [x] Added EmbedOrch to EmbeddedPanel enum
- [x] Created `orchestration_panel.go` with OrchestrationPanel
- [x] Implemented manifest path input and validation
- [x] Implemented manifest validation display
- [x] Implemented agent mapping display
- [x] Implemented execution control (start/dry-run)
- [x] Implemented execution phase display with visual progress
- [x] Implemented bundle directory configuration
- [x] Implemented timeout configuration
- [x] Implemented verbose/dry-run toggles

### 8.3 Agent Mode TUI
- [x] Added Tab toggle for Controller/Agent views
- [x] Created agent status view
- [x] Display cipdip version and build info
- [x] Display OS/Arch information
- [x] Display hostname
- [x] Display workdir with writability status
- [x] Display PCAP capture capability (tcpdump/tshark/bpf)
- [x] Display network interfaces with bind capability
- [x] Display supported roles (client, server)
- [x] Refresh capability (R key)

### 8.4 TUI Integration
- [x] Added `[o]` key binding for Orchestration panel
- [x] Panel renders in main screen embedded panel area
- [x] Help content for all modes
- [x] Unit tests for OrchestrationPanel

**Files Created:**
```
internal/tui/
  orchestration_panel.go       # OrchestrationPanel implementation
  orchestration_panel_test.go  # Unit tests
```

**Files Modified:**
```
internal/tui/
  model.go          # Added EmbedOrch, orchPanel, key bindings
  screen_main.go    # Added renderOrchPanel, getOrchHelp
```

**Features:**
- Controller view: Configure and execute orchestrated runs
  - Manifest path input with validation
  - Bundle directory and timeout settings
  - Dry run and verbose toggles
  - Visual phase progress during execution
  - Agent mapping display from manifest
- Agent view: Local agent capability status
  - System information (version, OS, arch, hostname)
  - Workdir writability check
  - PCAP capture capability detection
  - Network interface enumeration with bind testing
  - Supported roles display

**Navigation:**
- Press `[o]` to open Orchestration panel
- Press `[Tab]` to toggle between Controller and Agent views
- Press `[v]` to validate manifest
- Press `[e]` to edit manifest in external editor
- Press `[Enter]` to start run, `[d]` for dry run
- Press `[R]` in Agent view to refresh status

**All tests passing:** 35 packages

---

## Phase 9: Testing & Documentation - COMPLETED 2026-01-13

### 9.1 Unit Tests
- [x] Manifest schema validation tests (20+ test cases)
- [x] Resolved manifest generation tests
- [x] Bundle hashing and verification tests (13 tests)
- [x] Transport command construction tests (15+ tests)
- [x] Controller phase tests (15+ tests with mocks)

### 9.2 Integration Tests
- [x] Local controller run (no SSH) - tested via Controller tests
- [x] End-to-end bundle creation - tested in bundle_test.go
- [x] Bundle verification - TestVerify, TestVerify_MissingFiles, TestVerify_HashMismatch
- [x] Diff run on bundles - CLI tests for diff_run command

### 9.3 Documentation
- [x] Update CLAUDE.md with new packages (orchestration packages table)
- [x] Create docs/ORCHESTRATION.md - comprehensive guide
- [x] Create docs/RUN_MANIFEST.md with schema reference
- [x] TUI orchestration panel documented in ORCHESTRATION.md

### 9.4 Code Quality
- [x] Run go vet on all packages
- [x] Fixed IPv6 address format issue in SSH transport
- [x] All 35 packages passing tests

**Files Created:**
```
docs/
  ORCHESTRATION.md   # Comprehensive orchestration guide
  RUN_MANIFEST.md    # Manifest schema reference
```

**Files Modified:**
```
CLAUDE.md                          # Added orchestration packages
internal/transport/ssh.go          # Fixed IPv6 address handling
```

**Test Coverage Summary:**
- Manifest: 6 test functions, 20+ sub-tests
- Bundle: 13 test functions
- Controller: 15+ test functions
- Transport: 15+ test functions
- TUI Orchestration Panel: 17 test functions
- CLI Commands: agent, diff_run, bundle tests

**All tests passing:** 35 packages

---

## Phase 10: Polish & Finalization - COMPLETED 2026-01-13

### 10.1 Code Quality
- [x] Run go vet on all new packages
- [x] Ensure all tests pass (35 packages)
- [x] Review error messages for clarity
- [x] Check for security issues (no command injection, secret redaction)

### 10.2 CLI Polish
- [x] Consistent flag naming
- [x] Helpful error messages
- [x] Progress indicators for long operations (via verbose mode)
- [x] Dry-run outputs are clear

### 10.3 Final Integration
- [x] All new commands in main.go (run, bundle, agent, diff run)
- [x] Build verification (go build ./...)
- [x] Cross-compile check (note: gopacket/pcap requires CGO/libpcap - known limitation)

**Note:** Cross-compilation to Linux/Windows fails due to gopacket/pcap CGO dependency (requires libpcap and CGO). This is a pre-existing project limitation, not specific to orchestration code. Native compilation works on all platforms with libpcap installed.

---

## Progress Notes

### 2026-01-13: Initial Planning

**Codebase Review Complete:**
- Project location: `/Users/tturner/Documents/GitHub/cipdip`
- ~65,800 lines of Go code across 273 files
- 79 test files, all tests passing
- Well-structured with clean package separation

**Key Existing Components:**
- CLI: Cobra-based with 23+ commands
- TUI: Bubbletea dashboard (`internal/tui`) + screen-based (`internal/ui`)
- Config: YAML loading with validation (`internal/config`)
- Profiles: Process profiles with YAML format (`internal/profile`)
- PCAP: Comprehensive analysis including diff (`internal/pcap`)
- Artifact: Output management (`internal/artifact`)
- Metrics: Collection and reporting (`internal/metrics`)

**Architecture Decisions Made:**
1. Create new packages rather than extending existing ones:
   - `internal/orch` - Orchestration controller and bundle
   - `internal/transport` - SSH and local transport
   - `internal/manifest` - Manifest schema and resolution

2. SSH-first transport (per spec recommendation)

3. TUI additions as new screens/panels, not replacing existing

4. Server readiness via structured JSON stdout line

**Next Steps:**
1. Define detailed manifest YAML schema
2. Design bundle directory structure
3. Implement Phase 2 (manifest + bundles, local only)

### 2026-01-13: Phase 2 & 3 Complete

**Phase 2 Implementation (Manifest & Bundles):**
- Created `internal/manifest/` package with full YAML schema support
- Manifest types: Manifest, ProfileConfig, NetworkConfig, RolesConfig, ReadinessConfig
- Validation with detailed error reporting (ValidationErrors)
- Resolution with checksum computation, CLI arg generation
- Created `internal/orch/bundle/` package for run bundle management
- Bundle creation with roles directories, analysis directory
- SHA256 hash computation and verification
- `cipdip bundle verify` and `cipdip bundle info` commands

**Phase 3 Implementation (Local Controller):**
- Created `internal/orch/controller/` package
- Controller with 12-phase execution model
- Local Runner using exec.Command for server/client processes
- Server readiness detection (structured_stdout and tcp_connect methods)
- Graceful shutdown with SIGTERM + timeout + SIGKILL
- Output capture for stdout/stderr logs
- `cipdip run manifest` command with flags:
  - `--bundle-dir` - Output directory for bundles
  - `--timeout` - Overall run timeout
  - `--dry-run` - Validate and create bundle without execution
  - `--print-plan` - Show resolved execution plan
  - `--verbose` - Phase-by-phase output

**Files Created:**
```
internal/manifest/
  manifest.go       # Types and YAML loading
  validate.go       # Schema validation
  resolve.go        # Resolution and CLI arg generation
  manifest_test.go  # Unit tests

internal/orch/bundle/
  bundle.go         # Bundle creation and file management
  verify.go         # Verification logic
  bundle_test.go    # Unit tests

internal/orch/controller/
  controller.go     # Controller and phase execution
  runner.go         # Local role runner
  readiness.go      # TCP readiness check
  controller_test.go # Unit tests

cmd/cipdip/
  bundle.go         # cipdip bundle command
  run.go            # cipdip run command
```

**All tests passing:** 34 packages

### 2026-01-13: Phase 4 Complete

**Phase 4 Implementation (SSH Transport):**
- Created `internal/transport/` package with Transport interface
- LocalTransport: Full implementation with exec, file ops, context support
- SSHTransport: Full implementation using golang.org/x/crypto/ssh and github.com/pkg/sftp
  - Key-based authentication (file, agent, passphrase)
  - Password authentication fallback
  - Host key verification (known_hosts or insecure mode)
  - Connection keep-alive
  - SFTP for file operations
- URL parsing for transport specs:
  - `local` - local transport
  - `ssh://user@host:port?key=/path&insecure=true` - SSH URL
  - `user@host:port` - bare SSH host spec
- Helper functions: IsLocal, IsSSH, MustParse, ParseWithOptions

**Files Created:**
```
internal/transport/
  transport.go      # Transport interface and options
  local.go          # LocalTransport implementation
  ssh.go            # SSHTransport implementation
  parse.go          # URL parsing
  transport_test.go # Unit tests
```

**Dependencies Added:**
- golang.org/x/crypto/ssh
- golang.org/x/crypto/ssh/agent
- golang.org/x/crypto/ssh/knownhosts
- github.com/pkg/sftp

**All tests passing:** 35 packages

---

## Design Specifications

### D1: Run Manifest YAML Schema

```yaml
# manifest.yaml - Run Manifest Schema v1
api_version: v1                    # Required: schema version

# Run identification
run_id: auto                       # "auto" generates timestamped ID, or explicit string
seed: 1337                         # Optional: RNG seed for deterministic runs

# Profile configuration
profile:
  path: profiles/logix_like.yaml   # Required: path relative to controller working dir
  distribution: inline             # Required: inline|push|preinstalled
  checksum: sha256:abc123...       # Optional: controller computes if omitted

# Network configuration
network:
  control_plane: management        # Descriptive label only
  data_plane:
    client_bind_ip: 10.10.10.10    # Required if client role defined: explicit bind for client
    server_listen_ip: 10.10.10.20  # Required if server role defined: explicit bind for server
    target_ip: 10.10.10.20         # Required: where client connects to

# Role definitions
roles:
  server:                          # Optional role
    agent: A1                      # Agent ID from --agents or "local"
    mode: baseline                 # Server mode: baseline|realistic|dpi-torture|perf
    personality: adapter           # Server personality: adapter|logix_like
    args:                          # Additional CLI args
      pcap: server.pcap            # PCAP output filename
      responses_only: false        # Server-specific flags
      enable_udp_io: false
      log_level: info

  client:                          # Optional role
    agent: local                   # Agent ID or "local" for controller host
    scenario: baseline             # Scenario name OR "profile" for profile-based
    profile_role: hmi              # If scenario=profile, which role from profile
    duration_seconds: 60           # Run duration
    interval_ms: 250               # Polling interval (optional, uses scenario default)
    args:                          # Additional CLI args
      pcap: client.pcap            # PCAP output filename
      verbose: false
      debug: false

# Readiness configuration
readiness:
  method: structured_stdout        # structured_stdout|tcp_connect
  timeout_seconds: 30              # How long to wait for server ready

# Artifact configuration
artifacts:
  bundle_format: dir               # dir|zip
  include:                         # Patterns to include in bundle
    - manifest_resolved.yaml
    - profile.yaml
    - run_meta.json
    - "*.pcap"
    - "logs/*.log"

# Post-run actions
post_run:
  analyze: true                    # Run pcap analysis
  diff_baseline: ""                # Path to baseline bundle for diff (empty = skip)
```

**Schema Validation Rules:**
1. `api_version` must be "v1"
2. `profile.path` must exist (checked at load time or remote stat)
3. `profile.distribution` must be one of: inline, push, preinstalled
4. At least one role (server or client) must be defined
5. If server role: `agent`, `network.data_plane.server_listen_ip` required
6. If client role: `agent`, `scenario`, `duration_seconds`, `network.data_plane.target_ip` required
7. `readiness.method` must be one of: structured_stdout, tcp_connect
8. All agent IDs must map to provided `--agents` specs

---

### D2: Run Bundle Directory Structure

```
runs/<run_id>/
├── manifest.yaml                 # Original manifest (copy)
├── manifest_resolved.yaml        # Controller-resolved manifest
├── profile.yaml                  # Staged profile content
├── run_meta.json                 # Aggregated run metadata
├── versions.json                 # Tool versions and build info
├── hashes.txt                    # SHA256 hashes for all files
│
├── roles/
│   ├── server/
│   │   ├── server.pcap           # Server-side packet capture
│   │   ├── stdout.log            # Server stdout
│   │   ├── stderr.log            # Server stderr
│   │   └── role_meta.json        # Server role metadata
│   │
│   └── client/
│       ├── client.pcap           # Client-side packet capture
│       ├── stdout.log            # Client stdout
│       ├── stderr.log            # Client stderr
│       ├── metrics.csv           # Client metrics (if enabled)
│       └── role_meta.json        # Client role metadata
│
└── analysis/                     # Optional post-run analysis
    ├── summary.json              # PCAP summary
    └── diff_report.md            # Diff against baseline (if configured)
```

**File Specifications:**

`run_meta.json`:
```json
{
  "run_id": "2026-01-13_14-30-00_baseline",
  "started_at": "2026-01-13T14:30:00Z",
  "finished_at": "2026-01-13T14:35:00Z",
  "duration_seconds": 300,
  "status": "success",
  "controller_host": "controller.local",
  "phases_completed": ["stage", "server_start", "ready", "client_start", "client_done", "server_stop", "collect", "bundle"],
  "error": null
}
```

`versions.json`:
```json
{
  "cipdip_version": "0.2.1",
  "git_commit": "abc123def",
  "build_timestamp": "2026-01-10T10:00:00Z",
  "go_version": "1.25.5",
  "controller_os": "darwin",
  "controller_arch": "arm64",
  "roles": {
    "server": {
      "host": "server.local",
      "os": "linux",
      "arch": "amd64",
      "transport": "ssh"
    },
    "client": {
      "host": "localhost",
      "os": "darwin",
      "arch": "arm64",
      "transport": "local"
    }
  }
}
```

`role_meta.json`:
```json
{
  "role": "client",
  "agent_id": "local",
  "argv": ["cipdip", "client", "--ip", "10.10.10.20", "--scenario", "baseline", "--duration-seconds", "60", "--pcap", "client.pcap"],
  "bind_ip": "10.10.10.10",
  "target_ip": "10.10.10.20",
  "started_at": "2026-01-13T14:30:05Z",
  "finished_at": "2026-01-13T14:31:05Z",
  "exit_code": 0,
  "pcap_files": ["client.pcap"],
  "metrics_file": "metrics.csv"
}
```

`hashes.txt`:
```
sha256:abc123... manifest.yaml
sha256:def456... manifest_resolved.yaml
sha256:789ghi... profile.yaml
sha256:jkl012... roles/server/server.pcap
sha256:mno345... roles/client/client.pcap
...
```

---

### D3: Transport Interface

```go
package transport

import (
    "context"
    "io"
    "os"
)

// Transport abstracts remote/local execution and file transfer.
type Transport interface {
    // Exec runs a command and returns exit code, stdout, stderr.
    // cmd is the command as argv (not shell string).
    // env is additional environment variables.
    // cwd is the working directory (empty = default).
    Exec(ctx context.Context, cmd []string, env map[string]string, cwd string) (exitCode int, stdout, stderr string, err error)

    // ExecStream runs a command with streaming stdout/stderr.
    // Used for long-running processes where we need to monitor output.
    ExecStream(ctx context.Context, cmd []string, env map[string]string, cwd string, stdout, stderr io.Writer) (exitCode int, err error)

    // Put copies a local file to remote path.
    Put(ctx context.Context, localPath, remotePath string) error

    // Get copies a remote file to local path.
    Get(ctx context.Context, remotePath, localPath string) error

    // Mkdir creates a directory (and parents) on remote.
    Mkdir(ctx context.Context, remotePath string) error

    // Stat returns file info for remote path.
    Stat(ctx context.Context, remotePath string) (os.FileInfo, error)

    // Remove deletes a file or empty directory.
    Remove(ctx context.Context, remotePath string) error

    // Close releases any held resources (e.g., SSH connection).
    Close() error
}

// TransportOptions configures transport behavior.
type TransportOptions struct {
    Timeout       time.Duration // Default command timeout
    RetryAttempts int           // Retries on transient failures
    RetryDelay    time.Duration // Delay between retries
}

// ParseTransportSpec parses a transport specification string.
// Formats:
//   - "local" -> LocalTransport
//   - "ssh://user@host:port?key=/path/to/key" -> SSHTransport
//   - "agent://host:port" -> AgentTransport (future)
func ParseTransportSpec(spec string, opts TransportOptions) (Transport, error)
```

**LocalTransport Implementation:**
- `Exec`: Uses `os/exec` with proper context handling
- `ExecStream`: Uses `os/exec` with piped stdout/stderr
- `Put/Get`: Uses `os.CopyFile` equivalent
- `Mkdir`: Uses `os.MkdirAll`
- `Stat`: Uses `os.Stat`
- `Remove`: Uses `os.Remove`

**SSHTransport Implementation:**
- Uses `golang.org/x/crypto/ssh` package
- Key-based authentication (password optional)
- Host key verification by default (`--insecure-no-hostkey-check` to disable)
- SFTP for file transfer (`github.com/pkg/sftp`)
- Connection pooling/reuse for multiple operations

---

### D4: Controller Execution Model

```go
package orch

// Controller orchestrates a distributed run.
type Controller struct {
    manifest   *manifest.Manifest
    agents     map[string]transport.Transport
    bundleDir  string
    opts       ControllerOptions
}

// ControllerOptions configures the controller.
type ControllerOptions struct {
    BundleDir    string        // Base directory for bundles
    BundleFormat string        // "dir" or "zip"
    Timeout      time.Duration // Overall run timeout
    DryRun       bool          // Validate and plan only
    NoAnalyze    bool          // Skip post-run analysis
    NoDiff       bool          // Skip diff even if baseline specified
}

// Phase represents an execution phase.
type Phase string

const (
    PhaseInit         Phase = "init"
    PhaseStage        Phase = "stage"
    PhaseServerStart  Phase = "server_start"
    PhaseServerReady  Phase = "server_ready"
    PhaseClientStart  Phase = "client_start"
    PhaseClientDone   Phase = "client_done"
    PhaseServerStop   Phase = "server_stop"
    PhaseCollect      Phase = "collect"
    PhaseBundle       Phase = "bundle"
    PhaseAnalyze      Phase = "analyze"
    PhaseDiff         Phase = "diff"
    PhaseDone         Phase = "done"
)

// RunResult contains the outcome of a run.
type RunResult struct {
    RunID           string
    BundlePath      string
    Status          string // "success", "failed", "timeout"
    PhasesCompleted []Phase
    Error           error
    StartTime       time.Time
    EndTime         time.Time
}

// Run executes the orchestrated run.
func (c *Controller) Run(ctx context.Context) (*RunResult, error)
```

**Execution Flow:**

```
┌─────────────────────────────────────────────────────────────────┐
│                        Controller.Run()                         │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ Phase 1: INIT                                                   │
│ - Create bundle directory                                       │
│ - Generate run_id if "auto"                                     │
│ - Resolve manifest (paths, checksums, CLI args)                 │
│ - Write manifest.yaml and manifest_resolved.yaml                │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ Phase 2: STAGE                                                  │
│ - If profile.distribution == "push": SCP profile to agents      │
│ - If profile.distribution == "inline": embed in bundle          │
│ - If profile.distribution == "preinstalled": validate checksum  │
│ - Create role work directories on agents                        │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ Phase 3: SERVER_START                                           │
│ - Build server command line from manifest                       │
│ - Execute via agent transport (local or SSH)                    │
│ - Stream stdout/stderr to role logs                             │
│ - Server runs in background                                     │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ Phase 4: SERVER_READY                                           │
│ - If readiness.method == "structured_stdout":                   │
│   - Parse stdout for {"event":"server_ready","listen":"..."}    │
│ - If readiness.method == "tcp_connect":                         │
│   - Poll TCP connect to server_listen_ip:port                   │
│ - Timeout after readiness.timeout_seconds                       │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ Phase 5: CLIENT_START                                           │
│ - Build client command line from manifest                       │
│ - Execute via agent transport                                   │
│ - Stream stdout/stderr to role logs                             │
│ - Wait for completion (duration_seconds)                        │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ Phase 6: CLIENT_DONE                                            │
│ - Client process exits                                          │
│ - Capture exit code                                             │
│ - Write role_meta.json for client                               │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ Phase 7: SERVER_STOP                                            │
│ - Send graceful shutdown (SIGTERM or context cancel)            │
│ - Wait up to 10 seconds                                         │
│ - Force kill if needed (SIGKILL)                                │
│ - Capture exit code                                             │
│ - Write role_meta.json for server                               │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ Phase 8: COLLECT                                                │
│ - For each remote role:                                         │
│   - Get pcap files via transport                                │
│   - Get log files via transport                                 │
│   - Get metrics files via transport                             │
│ - Move local artifacts into bundle                              │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ Phase 9: BUNDLE                                                 │
│ - Write run_meta.json                                           │
│ - Write versions.json                                           │
│ - Compute hashes for all files                                  │
│ - Write hashes.txt                                              │
│ - If bundle_format == "zip": create archive                     │
│ - Verify bundle                                                 │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ Phase 10: ANALYZE (optional)                                    │
│ - Run pcap-summary on client.pcap                               │
│ - Write analysis/summary.json                                   │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ Phase 11: DIFF (optional)                                       │
│ - If diff_baseline specified:                                   │
│   - Run pcap-diff between bundles                               │
│   - Write analysis/diff_report.md                               │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ Phase 12: DONE                                                  │
│ - Return RunResult with bundle path                             │
└─────────────────────────────────────────────────────────────────┘
```

---

### D5: Server Readiness Check

**Structured Stdout Method (preferred):**

The server emits a JSON line when ready:
```json
{"event":"server_ready","listen":"10.10.10.20:44818","timestamp":"2026-01-13T14:30:02Z"}
```

Implementation in `internal/server/core/server.go`:
```go
// After listener is bound and accepting connections:
if os.Getenv("CIPDIP_EMIT_READY") == "1" || tuiStats {
    readyEvent := map[string]string{
        "event":     "server_ready",
        "listen":    listenAddr,
        "timestamp": time.Now().UTC().Format(time.RFC3339),
    }
    data, _ := json.Marshal(readyEvent)
    fmt.Fprintf(os.Stdout, "%s\n", data)
    os.Stdout.Sync()
}
```

Controller parses stdout line-by-line looking for `"event":"server_ready"`.

**TCP Connect Method (fallback):**

Controller polls TCP connect to `server_listen_ip:port`:
```go
func waitForTCPReady(ctx context.Context, addr string, timeout time.Duration) error {
    deadline := time.Now().Add(timeout)
    for time.Now().Before(deadline) {
        conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
        if err == nil {
            conn.Close()
            return nil
        }
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-time.After(500 * time.Millisecond):
        }
    }
    return fmt.Errorf("server not ready after %v", timeout)
}
```

---

### D6: TUI Page Design

**Current TUI Structure:**
```
┌─────────────────────────────────────────────────────────────────┐
│                      CIPDIP Dashboard                           │
├─────────────────────────────────────────────────────────────────┤
│  [c] Client   [s] Server   [p] PCAP   [k] Catalog   [r] Runs    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────────┐   ┌─────────────────────────────────┐     │
│   │   STATS         │   │   TRAFFIC                       │     │
│   │   ...           │   │   [graph]                       │     │
│   └─────────────────┘   └─────────────────────────────────┘     │
│                                                                 │
│   ┌─────────────────┐   ┌─────────────────────────────────┐     │
│   │   SERVICES      │   │   RECENT RUNS                   │     │
│   │   ...           │   │   ...                           │     │
│   └─────────────────┘   └─────────────────────────────────┘     │
│                                                                 │
│   [Embedded Panel: Client/Server/PCAP/Catalog when active]      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Proposed Controller/Agent Addition:**

Add new navigation keys: `[o] Orchestration` (or `[ctrl] Controller`, `[a] Agent`)

**Option A: Embedded Panel Approach (Recommended)**

Keep current dashboard, add panels:
```
[c] Client  [s] Server  [p] PCAP  [k] Catalog  [r] Runs  [o] Orch
```

When `[o]` pressed, embedded panel shows:
- Tab to switch between Controller and Agent sub-views
- Controller view: manifest selection, agent config, run control, status
- Agent view: local agent status, readiness checks

**Option B: Separate Screen Approach**

Add `ScreenOrchestration` to Screen enum:
- Full-screen view for orchestration
- Separate from embedded panel system
- More space for complex workflows

**Recommended: Option A with sub-tabs**

```
┌─────────────────────────────────────────────────────────────────┐
│                      ORCHESTRATION PANEL                        │
│  [Tab: Controller | Agent]                                      │
├─────────────────────────────────────────────────────────────────┤
│ CONTROLLER MODE:                                                │
│                                                                 │
│ Manifest: [manifest.yaml              ] [Browse] [Edit] [New]   │
│ Status:   ✓ Valid                                               │
│                                                                 │
│ Agents:                                                         │
│   A1: ssh://user@server.local:22  [Test: ✓ Connected]           │
│   A2: local                       [Test: ✓ Ready]               │
│                                                                 │
│ Roles:                                                          │
│   Server: A1 (baseline, adapter)                                │
│   Client: local (baseline, 60s)                                 │
│                                                                 │
│ ─────────────────────────────────────────────────────────────── │
│ [Enter] Start Run   [d] Dry Run   [v] View Plan   [Esc] Close   │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ CONTROLLER MODE - RUNNING:                                      │
│                                                                 │
│ Run ID: 2026-01-13_14-30-00_baseline                            │
│ Phase:  ▶ CLIENT_START (5/11)                                   │
│ Elapsed: 00:35                                                  │
│                                                                 │
│ Server (A1):  ✓ Running [44818]   Requests: 142                 │
│ Client (local): ● Running         Requests: 137  Errors: 0      │
│                                                                 │
│ Progress: [████████████░░░░░░░░] 35/60s                         │
│                                                                 │
│ ─────────────────────────────────────────────────────────────── │
│ [Space] Pause   [x] Stop   [Esc] Background                     │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ AGENT MODE:                                                     │
│                                                                 │
│ Local Agent Status                                              │
│                                                                 │
│ cipdip version:  0.2.1                                          │
│ OS/Arch:         darwin/arm64                                   │
│ Workdir:         /tmp/cipdip-agent  [✓ Writable]                │
│ PCAP Capture:    ✓ Available (BPF)                              │
│                                                                 │
│ Network Interfaces:                                             │
│   en0:  192.168.1.100  [✓ Can bind]                             │
│   lo0:  127.0.0.1      [✓ Can bind]                             │
│                                                                 │
│ Supported Roles: client, server                                 │
│                                                                 │
│ Agent Daemon:    Not running                                    │
│ [s] Start Daemon   [Esc] Close                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Key TUI Requirements:**
1. All actions map to CLI commands (reproducible)
2. No adaptive behavior during runs
3. Manifest editing via external editor (like current config editing)
4. Run in progress blocks manifest editing
5. Clear phase indication during execution
6. Per-role status with live stats

---

## Appendix: File Locations

### New Files to Create
```
cmd/cipdip/
  agent.go           # cipdip agent command
  run.go             # cipdip run manifest command
  bundle.go          # cipdip bundle verify command
  diff_run.go        # cipdip diff run command

internal/manifest/
  manifest.go        # Types and loading
  schema.go          # Validation
  resolve.go         # Resolution logic
  manifest_test.go   # Tests

internal/transport/
  transport.go       # Interface definition
  local.go           # Local transport
  ssh.go             # SSH transport
  parse.go           # URL parsing
  transport_test.go  # Tests

internal/orch/
  controller.go      # Controller orchestration
  plan.go            # Execution planning
  phases.go          # Phase execution
  bundle/
    bundle.go        # Bundle creation
    verify.go        # Bundle verification
    hashes.go        # Hash computation
  orch_test.go       # Tests

internal/tui/
  screen_controller.go  # Controller TUI (or extend existing)
  agent_panel.go        # Agent status panel
```

### Files to Modify
```
cmd/cipdip/main.go           # Add new commands
cmd/cipdip/server.go         # Add readiness JSON output
internal/app/server.go       # Emit readiness event
internal/tui/model.go        # Add Controller/Agent screens
CLAUDE.md                    # Update with new packages
```

---

## Risk & Mitigation

| Risk | Mitigation |
|------|------------|
| SSH library complexity | Use golang.org/x/crypto/ssh, well-tested |
| Cross-platform SSH | Document requirements clearly |
| TUI complexity growth | Keep Controller/Agent as separate pages |
| Breaking existing tests | Run tests after each phase |
| Large scope | Implement incrementally, local-first |
