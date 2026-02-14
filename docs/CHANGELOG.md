# Changelog

All notable changes to CIPDIP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.7] - 2026-02-13

### Fixed
- Fix flaky `TestRunner_StartWait` CI failure: added `sync.WaitGroup` so `Wait()` doesn't return until stdout/stderr capture goroutines finish reading all buffered pipe data

## [0.2.6] - 2026-02-13

### Changed
- **Lint cleanup**: Resolved all 220 golangci-lint issues across 83 files (errcheck: 91, unused: 48, staticcheck: 76, ineffassign: 5), removing ~700 lines of dead code
- **CI**: golangci-lint now enforces zero issues on all code (removed `only-new-issues` workaround)
- **errcheck exclusions**: Expanded `.golangci.yml` exclude-functions for common cleanup patterns (Close, Remove, Flush, Fprint, Sscanf)

## [0.2.5] - 2026-02-13

### Security
- Remove `sh -c` shell wrapping from remote runner; PATH is now set via transport env map with `prependEnvVars()`, eliminating shell injection surface
- Replace unreliable `session.Setenv` in SSH transport with command-string env prepending (works with any sshd config)

### Added
- **CI: race detector** — `go test -race ./...` now runs in CI to catch data races in concurrent code (TUI, server, orchestration)
- **CI: golangci-lint** — Added `golangci-lint` step with `.golangci.yml` config (errcheck, staticcheck, unused, etc.)
- **Test coverage**: `internal/cip/codec` (0% -> 100%), `internal/cip/protocol` (3.9% -> 45.6%), `internal/artifact` (0% -> 95.1%), plus `prependEnvVars` transport tests

### Fixed
- Fix stale version "0.2.2" in TUI orchestration panel; version is now set from main via `tui.SetVersion()` to avoid duplication
- Fix `paint_shop_conveyor.yaml` personality mismatch (adapter -> logix_like; profile uses symbolic tags)
- Replace JSON `Seek` syscall with boolean flag in metrics writer for I/O performance

### Changed
- Add Cobra `Deprecated` field to `single` command for proper deprecation warnings
- Replace custom `contains()` reimplementations with `strings.Contains()` in 3 files

## [0.2.4] - 2026-02-13

### Added
- **Test coverage**: Added test files for `internal/errors`, `internal/logging`, `internal/progress`, and `internal/validation/fixtures` — 73 new test cases covering all previously untested packages.

### Changed
- **Release workflow**: Expanded platform matrix from 3 to 5 native builds (added linux-arm64 and darwin-amd64). Added version/commit/date ldflags injection. Archives and checksums generated dynamically for any number of artifacts.
- **GoReleaser config**: Added version/commit/date ldflags for local CGO_ENABLED=0 builds via `goreleaser release --clean`.

## [0.2.3] - 2026-02-13

### Added
- **`metrics-report` command**: Batch-aligned DPI test report generator. Reads all `*_metrics.csv` files from a directory, groups them by DPI test batch (1-8), computes batch-specific metrics, and prints a formatted report matching the `dpi_test_batches.md` specification. Supports all 8 batches with per-batch metrics tables (baseline pass-through rates, stress throughput, churn ForwardOpen stats, vendor variant per-profile breakdown, DPI explicit per-phase verdicts, evasion per-technique results, edge/legacy pass rates, and mixed regression totals with firewall pack details).
- **Selftest manifest**: `selftest --metrics-dir` now writes a `_manifest.json` alongside the CSVs containing run timestamp, scenario list, duration, and cipdip version. Used by `metrics-report` for run coherence validation.
- **Shared CSV reader**: Extracted `metrics.ReadMetricsCSV()` into `internal/metrics/csv_reader.go` for reuse by both `metrics-analyze` and `metrics-report`.
- **Timestamp coherence checking**: `metrics-report` warns when CSV files span >1 hour or when files appear to be from different runs.

### Changed
- **`metrics-analyze` refactored**: Now uses the shared `metrics.ReadMetricsCSV()` function instead of inline CSV parsing, reducing code duplication.

## [0.2.2] - 2026-02-13

### Fixed
- Fix `go vet` IPv6 address formatting in evasion scenarios (use `net.JoinHostPort`)
- Fix context leak in vendor_variants scenario (cancel not called on all return paths)
- Skip pcap-dependent tests on Windows CI when npcap/wpcap is unavailable

## [0.2.1] - 2026-02-13

### Security
- Wire SFTP path traversal validation into Put/Get/Mkdir/Stat/Remove
- Gate SSH password authentication behind explicit AllowPassword flag
- Add nil guards to TUI channel reads in handleTick
- Add input validation to Client/Server TUI panels
- Remove hardcoded credentials from repository and git history
- Bump Go to 1.26.0 (fixes CVE-2025-68121, CVE-2025-61730, CVE-2025-61726, CVE-2025-61728)

### Added
- **PCAP Summary Improvements**: Contextual CIP service labeling for Rockwell tag services (0x4B/0x4C/0x4D), Unconnected Send decoding, and embedded service counts.
- **PCAP Dump Command**: Added `cipdip pcap-dump` to extract sample CIP packets for a specific service code.
- **PCAP Coverage Command**: Added `cipdip pcap-coverage` to summarize CIP service/object coverage across PCAPs.
- **CIP Application Profiles**: Added `--cip-profile` (energy|safety|motion|all) and profile class overrides in config.
- **Progress Indicators**: Added progress bars to all scenario types (baseline, mixed, stress, churn, io) to provide visual feedback during long-running operations. Progress bars show completion percentage, elapsed time, and ETA. Progress bars write to stderr to avoid interfering with stdout logging.

- **Auto-Generate Default Config**: Added `--quick-start` flag to automatically generate a default configuration file if missing. This enables zero-config usage for quick testing. The default config includes common CIP paths (InputBlock1, InputBlock2, OutputBlock1) that work with many devices.

- **Wireshark Integration**: Added Wireshark validation for ENIP packets using `tshark`. The `internal/validation/wireshark.go` package validates that generated packets are correctly structured and can be read by Wireshark without errors. Validates packet structure (Ethernet/IP/TCP on port 44818) and ensures tshark can parse the PCAP file. Provides `ValidateENIPPacket()` and `ValidateENIPPacketWithDetails()` functions for easy integration.

- **User-Friendly Error Messages** (`internal/errors/userfriendly.go`)
  - `UserFriendlyError` type with context, hints, and suggestions
  - `WrapNetworkError()` for network errors with helpful context
  - `WrapCIPError()` for CIP protocol errors
  - `WrapConfigError()` for configuration errors
  - Integrated throughout client, config, and CLI code

- **Packet Validation Layer** (`internal/cip/client/validation.go`)
  - `PacketValidator` with strict/non-strict modes
  - `ValidateENIP()` for ENIP encapsulation validation
  - `ValidateCIPRequest()` for CIP request validation
  - `ValidateCIPResponse()` for CIP response validation
  - `ValidateRPIMicroseconds()` and `ValidateConnectionSize()` for parameter validation
  - Integrated into client operations for pre-send and post-receive validation

- **Reference Packet Library** (`internal/reference/reference.go`)
  - `ReferencePacket` type for storing known-good ODVA-compliant packets
  - `CompareWithReference()` for packet comparison
  - `FindFirstDifference()` for byte-level diff analysis
  - `ValidatePacketStructure()` for structural validation
  - Ready for population with real device packets

- **Progress Indicator Helper** (`internal/progress/progress.go`)
  - `ProgressBar` with percentage, ETA, and elapsed time
  - `SimpleProgress` for operation count tracking
  - Throttled updates to avoid excessive output
  - Ready for integration into scenarios

- **Documentation**
  - Compliance testing guide (`docs/COMPLIANCE_TESTING.md`)

### Changed
- **Error Handling**: All network, CIP, and config errors now use user-friendly wrappers
  - More helpful error messages with context and suggestions
  - Better error messages in CLI output
  - Improved error messages in config loading

- **Packet Validation**: All packets validated before sending and after receiving
  - RegisterSession packets validated
  - CIP requests validated
  - CIP responses validated (non-strict mode)

### Added (Infrastructure)
- GitHub Actions CI (test on Linux/macOS/Windows, go vet, govulncheck)
- CycloneDX SBOM at docs/sbom.cdx.json
- SECURITY.md with responsible disclosure via GitHub Security Advisories
- CONTRIBUTING.md with development guidelines
- .goreleaser.yml for cross-platform binary releases
- TUI dashboard screenshot in README

### Improved
- **UX**: Better error messages make troubleshooting easier
- **Compliance**: Packet validation catches protocol issues early
- **Maintainability**: Clear separation of concerns with new packages

## [0.1] - 2025-01-27

### Added
- **Core CIP/EtherNet-IP Client Implementation**
  - Session management (RegisterSession/UnregisterSession)
  - UCMM messaging (SendRRData) for explicit messaging
  - Connected messaging (ForwardOpen/ForwardClose, SendUnitData)
  - Generic CIP service invocation API
  - ReadAttribute/WriteAttribute convenience methods

- **Transport Support**
  - TCP 44818 for explicit messaging (UCMM, connected explicit)
  - UDP 2222 for Class 1 I/O (implicit messaging) ✅
  - UDP 44818 for discovery (ListIdentity)
  - Transport abstraction layer (TCP/UDP)

- **Scenarios**
  - `baseline`: Low-frequency read-only polling (250ms default)
  - `mixed`: Medium-frequency mixed reads/writes (100ms default)
  - `stress`: High-frequency reads (20ms default)
  - `churn`: Connection setup/teardown cycles (100ms default)
  - `io`: Connected Class 1 I/O-style behavior (10ms default, UDP 2222)

- **CLI Commands**
  - `cipdip client`: Run in client/scanner mode
  - `cipdip server`: Run in server/emulator mode
  - `cipdip discover`: Discover CIP devices via ListIdentity
  - `cipdip test`: Test connectivity to a CIP device
  - `cipdip pcap`: Analyze packet captures for compliance
  - `cipdip version`: Show version information
  - `cipdip install`: Install binary and shell completion

- **Server/Emulator Mode**
  - Adapter personality (assembly-style object model)
  - Logix-like personality (tag-based interface)
  - TCP 44818 server
  - Optional UDP 2222 I/O server

- **Configuration**
  - YAML-based client config (`cipdip_client.yaml`)
  - YAML-based server config (`cipdip_server.yaml`)
  - Config-driven CIP paths and services
  - I/O connection configuration with transport selection

- **Metrics & Logging**
  - Structured logging (human-readable, file output)
  - Metrics collection (CSV/JSON output)
  - Operation-level metrics (RTT, success/failure, status codes)
  - Target type tracking (click, emulator_adapter, emulator_logix, pcap_replay)

- **Protocol Compliance Testing**
  - ENIP encapsulation header validation
  - RegisterSession/SendRRData/SendUnitData packet structure tests
  - ForwardOpen/ForwardClose packet structure tests
  - EPATH encoding validation (8-bit/16-bit)
  - CIP service code validation
  - Response structure validation
  - Integration test framework
  - Packet capture analysis framework (`internal/pcap`)
  - ODVA compliance validation for captured packets
  - Packet comparison tools
  - Hex dump utilities

- **Documentation**
  - README with usage examples
  - Compliance testing guide (`docs/COMPLIANCE_TESTING.md`)
  - Troubleshooting guide (`docs/TROUBLESHOOTING.md`)
  - Hardware setup guide (`docs/HARDWARE_SETUP.md`)
  - Packet analysis guide (`docs/PCAP_USAGE.md`)
  - Usage examples (`docs/EXAMPLES.md`)
  - Example configuration files

### Technical Details
- **Language**: Go 1.21+
- **Dependencies**: 
  - `github.com/spf13/cobra` for CLI
  - `gopkg.in/yaml.v3` for YAML parsing
- **Test Coverage**: 72+ test cases covering protocol compliance, transport layer, and response handling
- **Protocol Compliance**: ODVA EtherNet/IP specification compliant packet structures

### Known Limitations
- Extended status parsing is basic (may need enhancement)
- Packet capture analysis framework requires external tools
- Hardware validation pending (when hardware available)

### Future Enhancements
- Phase 13: Vendor Implementation Research & Emulation
- Enhanced extended status code parsing
- Additional CIP service support
- Performance optimizations


