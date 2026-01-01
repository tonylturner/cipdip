# CIPDIP Project Plan

**Project Name:** CIPDIP (CIP/EtherNet-IP Scanner for DPI Testing)  
**Language:** Go (minimum version 1.21)  
**Purpose:** Command-line tool to generate repeatable, controllable CIP traffic for firewall DPI research testing

---

## Project Overview

CIPDIP is a Go-based EtherNet/IP / CIP client/scanner tool designed to:
- Generate repeatable, controllable CIP traffic for DPI testing through industrial firewalls
- Support multiple traffic scenarios (baseline, mixed, stress, churn, io)
- Provide a generic CIP client that can invoke any CIP service over EtherNet/IP
- Support both unconnected (UCMM) and connected messaging
- Produce structured logs and metrics for offline analysis

---

## Requirements Summary

### Transport Support
- **TCP 44818** - Explicit messaging (UCMM, connected explicit)
- **UDP 2222** - Class 1 I/O (implicit messaging) - Primary for `io` scenario
- **UDP 44818** - Discovery (optional, ListIdentity)
- **TCP 2222** - Optional for I/O connections

### Scenarios
1. **baseline** - Low-frequency read-only polling (250ms default)
2. **mixed** - Medium-frequency mixed reads/writes (100ms default)
3. **stress** - High-frequency reads (20ms default)
4. **churn** - Connection setup/teardown cycles (100ms default)
5. **io** - Connected Class 1 I/O-style behavior (10ms default, UDP 2222)

### Configuration
- YAML-based config files:
  - Client config: `cipdip_client.yaml` (default for `--config`)
  - Server config: `cipdip_server.yaml` (default for `--server-config`)
- Defines CIP paths, services, and I/O connections
- Config-driven behavior (no hardcoded CIP constants)

### Modes of Operation
- **Client mode** (primary): Scanner that connects to CIP targets and generates traffic
- **Server mode** (lower priority): Emulator that acts as a CIP endpoint
- **Discovery mode**: ListIdentity discovery via separate subcommand

---

## Project Structure

```
cipdip/
├── cmd/
│   └── cipdip/
│       └── main.go              # CLI entry point
├── internal/
│   ├── config/
│   │   └── config.go            # Config loading and validation
│   ├── cipclient/
│   │   ├── client.go            # Client interface and implementation
│   │   ├── enip.go              # EtherNet/IP protocol handling
│   │   ├── cip.go               # CIP encoding/decoding
│   │   └── transport.go         # TCP/UDP transport abstraction
│   ├── scenario/
│   │   ├── interface.go         # Scenario interface
│   │   ├── baseline.go
│   │   ├── mixed.go
│   │   ├── stress.go
│   │   ├── churn.go
│   │   └── io.go
│   ├── metrics/
│   │   ├── metrics.go           # Metrics collection
│   │   └── writer.go            # CSV/JSON output
│   ├── logging/
│   │   └── logger.go            # Structured logging
│   └── server/
│       ├── server.go            # Server interface and implementation
│       ├── adapter.go           # Adapter personality
│       └── logix.go             # Logix-like personality
├── pkg/                          # Public APIs (if needed)
├── configs/
│   ├── cipdip_client.yaml.example # Example client config file
│   └── cipdip_server.yaml.example # Example server config file
├── go.mod
├── go.sum
├── README.md
└── notes/project_plan.md              # This file
```

---

## Implementation Phases

### Phase 1: Project Setup & Foundation
**Status:** ✅ Completed

- [x] Review all specification documents
- [x] Create project plan
- [x] Initialize Go module (`go mod init`)
- [x] Set up project structure
- [x] Create README.md with usage examples
- [x] Add example config files (cipdip_client.yaml.example, cipdip_server.yaml.example)

### Phase 2: Core CIP/EtherNet-IP Client
**Status:** ✅ Completed

- [x] Implement EtherNet/IP protocol layer
  - [x] TCP client for port 44818
  - [x] UDP client for port 2222 (I/O)
  - [x] UDP client for port 44818 (discovery)
  - [x] Session registration/unregistration
  - [x] RegisterSession/UnregisterSession
  - [x] SendRRData, SendUnitData encapsulation
- [x] Implement CIP encoding/decoding
  - [x] CIP service code handling
  - [x] CIP path encoding (EPATH format)
  - [x] CIP request/response parsing
  - [x] General status and extended status handling
- [x] Implement Client interface
  - [x] Connect/Disconnect
  - [x] InvokeService (generic service invocation)
  - [x] ReadAttribute (convenience helper)
  - [x] WriteAttribute (convenience helper)
  - [x] ForwardOpen/ForwardClose (connected messaging - implemented)
  - [x] SendIOData/ReceiveIOData (I/O connections - implemented)

### Phase 3: Configuration System
**Status:** ✅ Completed

- [x] Define client config structs
  - [x] AdapterConfig
  - [x] CIPTarget
  - [x] IOConnectionConfig (with Transport field: "udp" default or "tcp")
  - [x] Config (root)
- [x] Define server config structs
  - [x] ServerConfig
  - [x] AdapterAssemblyConfig
  - [x] LogixTagConfig
- [x] Implement YAML config loader for client config (`cipdip_client.yaml`)
- [x] Implement YAML config loader for server config (`cipdip_server.yaml`)
- [x] Add config validation
  - [x] Required fields
  - [x] Service code validation
  - [x] Transport validation ("udp" or "tcp")
  - [x] RPI and size validation
  - [x] Server personality validation ("adapter" or "logix_like")
- [x] Apply defaults:
  - [x] Client config: port 44818, transport "udp", config file `cipdip_client.yaml`
  - [x] Server config: listen-ip "0.0.0.0", listen-port 44818, server-config `cipdip_server.yaml`

### Phase 4: CLI Implementation
**Status:** ✅ Completed

- [x] Implement CLI using `spf13/cobra` (required for subcommand architecture)
- [x] Implement subcommands:
  - [x] `cipdip help` - Top-level and per-command help
  - [x] `cipdip version` - Version information
  - [x] `cipdip client` - Client/scanner mode (primary functionality)
  - [x] `cipdip server` - Server/emulator mode
  - [x] `cipdip discover` - ListIdentity discovery subcommand
  - [x] `cipdip install` - Install binary and shell completion
- [x] `cipdip client` subcommand:
  - [x] Required flags:
    - [x] `--ip` - Target IP address
    - [x] `--scenario` - Scenario name (baseline|mixed|stress|churn|io)
  - [x] Optional flags:
    - [x] `--port` - TCP port (default 44818, shown in help)
    - [x] `--interval-ms` - Base polling interval
    - [x] `--duration-seconds` - Run duration (default 300)
    - [x] `--config` - Config file path (default "cipdip_client.yaml")
    - [x] `--log-file` - Log file path
    - [x] `--metrics-file` - Metrics output file path
    - [x] `--verbose` - Enable verbose output
    - [x] `--debug` - Enable debug output (optional)
    - [x] `-h, --help` - Show help
- [x] `cipdip server` subcommand:
  - [x] `--listen-ip` - Listen IP address (default "0.0.0.0")
  - [x] `--listen-port` - Listen port (default 44818)
  - [x] `--personality` - Server personality (adapter|logix_like, default "adapter")
  - [x] `--server-config` - Server config file path (default "cipdip_server.yaml")
  - [x] `--enable-udp-io` - Enable UDP I/O on port 2222 (default false)
  - [x] `-h, --help` - Show help
- [x] `cipdip discover` subcommand:
  - [x] `--interface` - Network interface for broadcast
  - [x] `--timeout` - Discovery timeout duration
  - [x] `--output` - Output format (text|json)
  - [x] `-h, --help` - Show help
- [x] Exit code implementation:
  - [x] Exit code 0 for success
  - [x] Exit code 1 for CLI/usage errors
  - [x] Exit code 2 for runtime errors
- [x] Verbosity levels:
  - [x] Silent/minimal (default): Only necessary output, errors to stderr
  - [x] Verbose (`--verbose`): Extra operational details
  - [x] Debug (`--debug`): Detailed logs, raw packet hex dumps
- [x] Help system:
  - [x] `cipdip help` - Top-level usage with subcommand list
  - [x] `cipdip help <command>` - Detailed help per command
  - [x] `-h` / `--help` flags for each subcommand
  - [x] Short, scannable help text (one-line descriptions, usage examples, options list)
  - [x] Show default values in help text
- [x] Error handling:
  - [x] Required flags validation with clear error messages
  - [x] Invalid input handling with helpful error messages
  - [x] Error messages to stderr with format: "error: <description>"
  - [x] Include helpful hints in error messages (e.g., "try 'cipdip help client'")
- [x] Flag naming:
  - [x] Lowercase, hyphen-separated words (e.g., `--listen-ip`, `--duration-seconds`)
  - [x] Short flags only for common cases (`-h`, `-v` for verbose if used)
- [x] Output style:
  - [x] No emojis or decorative characters
  - [x] Plain text, single-line or short multi-line summaries
  - [x] Brief confirmations for success (e.g., "OK" or "Completed scenario 'baseline' in 60s (1200 operations, 0 errors)")
- [x] Install command:
  - [x] Binary installation to PATH directory
  - [x] Automatic shell detection (zsh, bash, fish, PowerShell)
  - [x] Shell completion installation
  - [x] Cross-platform support (Windows, macOS, Linux)
  - [x] Custom install path option
  - [x] Force overwrite option

### Phase 5: Metrics & Logging
**Status:** ✅ Completed

- [x] Implement metrics collection
  - [x] Operation timing (RTT)
  - [x] Success/failure counts
  - [x] Status codes
  - [x] Error tracking
  - [x] Target type tracking (click, emulator_adapter, emulator_logix, pcap_replay)
- [x] Implement metrics writer
  - [x] CSV output format (include target_type field)
  - [x] JSON output format (optional)
  - [x] Summary statistics
- [x] Implement structured logging
  - [x] Startup information
  - [x] Per-operation logging
  - [x] Debug-level logging (verbose/debug flags)
  - [x] Log file output (when `--log-file` specified)
- [x] CLI output separation:
  - [x] CLI stdout: High-level summaries only (brief confirmations)
  - [x] CLI stderr: Errors only
  - [x] Log file: Detailed operational events (when `--log-file` specified)
  - [x] Default: No log file output unless `--log-file` is provided
- [x] Output style requirements:
  - [x] No emojis or decorative characters
  - [x] Plain text, scannable format
  - [x] Success examples: "OK" or "Completed scenario 'baseline' in 60s (1200 operations, 0 errors)"
  - [x] Error examples: "error: missing --ip; try 'cipdip help client'"

### Phase 6: Scenario Implementations
**Status:** ✅ Completed

- [x] Define Scenario interface
- [x] Implement baseline scenario
  - [x] Read-only polling loop
  - [x] RTT measurement
  - [x] Metrics collection
- [x] Implement mixed scenario
  - [x] Read and write operations
  - [x] Pattern-based value generation (increment, toggle, constant)
  - [x] Separate metrics for reads/writes
- [x] Implement stress scenario
  - [x] High-frequency reads
  - [x] Timeout tracking
  - [ ] RTT histogram (deferred - can be added later if needed)
- [x] Implement churn scenario
  - [x] Connection setup/teardown cycles
  - [x] Per-cycle reads
  - [x] Cycle metrics
- [x] Implement io scenario
  - [x] ForwardOpen for each I/O connection (fully implemented)
  - [x] O→T and T→O data handling (implemented using SendUnitData)
  - [x] RPI-based timing (default interval: 10ms)
  - [x] ForwardClose on shutdown (fully implemented)
  - [x] TCP transport support for I/O (via SendUnitData over existing TCP connection)
  - [ ] UDP 2222 transport support (optional enhancement - currently uses TCP)
  - [ ] TCP 2222 transport support (optional, via transport field in config)

### Phase 7: Signal Handling & Error Management
**Status:** ✅ Completed

- [x] Context-based cancellation
- [x] SIGINT (Ctrl+C) handling
- [x] Graceful shutdown
- [x] Metrics flush on exit
- [x] Connection cleanup
- [x] Error propagation and logging

### Phase 8: Discovery Support
**Status:** ✅ Completed

- [x] Implement `cipdip discover` subcommand (separate subcommand, not scenario)
- [x] ListIdentity helper function
- [x] UDP 44818 broadcast support
- [x] Response collection with timeout
- [x] DiscoveredDevice struct (IP, identity, product information)
- [x] Output formatting (text or JSON)
- [x] Network interface selection support

### Phase 9: Testing & Documentation
**Status:** ✅ Completed (Basic)

- [x] Unit tests for core components
  - [x] CIP encoding/decoding tests
  - [x] ENIP encapsulation tests
  - [x] Config validation tests
- [ ] Integration tests (if test hardware available) - Deferred until hardware available
- [x] Example config files for different devices (created in Phase 1)
- [x] Usage documentation (README.md created and updated)
- [ ] Troubleshooting guide - Can be added as needed

### Phase 10: Polish & Optimization
**Status:** ✅ Completed (Basic)

- [x] Code review and cleanup (basic cleanup done)
- [ ] Performance optimization (deferred - optimize as needed)
- [x] Error message improvements (error messages follow CLI best practices)
- [x] Log formatting improvements (structured logging implemented)
- [x] Final documentation updates (README and example configs complete)

### Phase 11: Server/Emulator Mode (Lower Priority)
**Status:** ✅ Completed

- [x] Server package implementation
  - [x] Server interface definition
  - [x] ENIPServer implementation
- [x] TCP server on port 44818
  - [x] Connection handling
  - [x] Session management
- [x] Optional UDP server on port 2222 (when `--enable-udp-io`)
  - [x] UDP I/O packet handling (basic structure in place)
- [x] Session handling
  - [x] RegisterSession/UnregisterSession
  - [x] Session state management
- [x] Request handling
  - [x] SendRRData (UCMM)
  - [x] SendUnitData (connected messaging)
  - [x] CIP request parsing and dispatch
- [x] Adapter personality implementation
  - [x] Assembly-style object model
  - [x] Get_Attribute_Single (0x0E) support
  - [x] Set_Attribute_Single (0x10) support for writable assemblies
  - [x] Update patterns: counter, static, random, reflect_inputs
  - [x] In-memory data storage with sync.RWMutex
- [x] Logix-like personality implementation
  - [x] Tag-based interface
  - [x] Tag types: BOOL, SINT, INT, DINT, REAL
  - [x] Tag update patterns: counter, static, random, sine, sawtooth
  - [x] Tag namespace support (config field exists)
  - [x] Array element access (array_length support)
- [x] Server config loading and validation
  - [x] Load `cipdip_server.yaml` (default)
  - [x] Validate personality type
  - [x] Validate assembly/tag configurations
- [x] Error handling
  - [x] Unknown services → appropriate CIP error status
  - [x] Invalid paths → CIP path error status
- [ ] Integration with metrics
  - [ ] Track target_type as "emulator_adapter" or "emulator_logix" (deferred - server doesn't generate metrics, only responds to requests)

### Phase 12: ODVA Protocol Compliance Testing
**Status:** ✅ Completed

- [x] Research ODVA EtherNet/IP specification documents
  - [x] Identify key compliance requirements
  - [x] Document packet structure requirements (in test code)
  - [x] Document service code requirements (in test code)
  - [x] Document EPATH encoding requirements (in test code)
- [x] Implement packet structure validation tests
  - [x] ENIP encapsulation header validation (24 bytes, correct field order)
  - [x] RegisterSession packet structure validation
  - [x] SendRRData packet structure validation
  - [x] SendUnitData packet structure validation
  - [x] ForwardOpen packet structure validation
  - [x] ForwardClose packet structure validation
- [x] Implement EPATH encoding validation tests
  - [x] 8-bit vs 16-bit segment encoding
  - [x] Class/Instance/Attribute path encoding
  - [x] Connection path encoding for ForwardOpen
- [x] Implement CIP service code validation
  - [x] Service code values match ODVA spec
  - [x] Service response structure validation
  - [x] Status code handling validation
- [x] Packet capture analysis framework
  - [x] Generate test packets and capture with Wireshark
  - [x] Verify Wireshark EtherNet/IP dissector recognizes packets (via tshark validation)
  - [x] Compare packet structure with ODVA spec examples
  - [x] Document any deviations or non-standard behavior
  - [x] Wireshark validation package (`internal/validation/wireshark.go`)
  - [x] PCAP extraction from baseline and real-world captures
  - [x] Reference packet library (8 of 9 types populated)
- [x] Integration test suite against server mode
  - [x] Test client-server communication (basic)
  - [x] Test ForwardOpen/ForwardClose against server
  - [x] Test I/O data exchange
  - [ ] Test all scenarios against local server emulator (deferred - can be done manually)
  - [ ] Capture and analyze packets (requires packet capture tools)
- [ ] Hardware validation test suite (when hardware available)
  - [ ] Test against CLICK C2-03CPU
  - [ ] Test against other CIP devices (if available)
  - [ ] Compare behavior with commercial CIP tools
  - [ ] Document any device-specific quirks
- [ ] Protocol compliance checklist
  - [ ] ENIP encapsulation headers (24 bytes, little-endian, correct field order)
  - [ ] RegisterSession/UnregisterSession compliance
  - [ ] SendRRData structure (Interface Handle=0, Timeout, CIP data)
  - [ ] SendUnitData structure (Connection ID, CIP data)
  - [ ] EPATH encoding (segment types, 8-bit/16-bit formats)
  - [ ] ForwardOpen parameters (RPIs, priorities, connection path)
  - [ ] ForwardClose connection path
  - [ ] CIP service codes and status codes
  - [ ] ListIdentity discovery packet structure
- [x] Create compliance test report template
  - [x] Document test methodology (docs/COMPLIANCE.md)
  - [x] Document test results
  - [x] Document any known limitations or deviations

### Phase 13: Vendor Implementation Research & Emulation
**Status:** ⏳ Pending (Future Enhancement)

- [ ] Research vendor-specific EtherNet/IP/CIP implementations
  - [ ] Identify major vendors (Rockwell/Allen-Bradley, Schneider, Siemens, etc.)
  - [ ] Research vendor-specific protocol extensions or deviations
  - [ ] Document non-standard behaviors or packet structures
  - [ ] Identify vendor-specific service codes or object models
- [ ] Document vendor-specific implementations
  - [ ] Create markdown documentation files for each vendor
  - [ ] Document vendor-specific behaviors
  - [ ] Document packet capture examples
  - [ ] Document known quirks or deviations from ODVA spec
  - [ ] Optional: Create YAML config files for emulation settings
- [ ] Implement vendor emulation modes (optional)
  - [ ] Add vendor-specific personality flags (e.g., `--vendor rockwell`, `--vendor schneider`)
  - [ ] Implement vendor-specific packet structures
  - [ ] Implement vendor-specific service code handling
  - [ ] Implement vendor-specific EPATH encoding variations
- [ ] Vendor-specific test scenarios
  - [ ] Test scenarios that exercise vendor-specific behaviors
  - [ ] Verify emulation matches real vendor implementations
  - [ ] Document any limitations in emulation accuracy
- [ ] Use cases for vendor emulation
  - [ ] Test firewall behavior with vendor-specific traffic
  - [ ] Test DPI rules against vendor-specific implementations
  - [ ] Identify firewall vulnerabilities to vendor-specific traffic
  - [ ] Research firewall handling of non-standard CIP traffic

---

## Key Design Decisions

### Library Selection
- **CLI:** Use `spf13/cobra` (required for subcommand-based architecture)
- **Logging:** Standard `log` package or `zap`/`logrus` (evaluate based on needs)
- **YAML:** Use `gopkg.in/yaml.v3` or similar
- **EtherNet/IP Library:** Evaluate existing Go libraries first; implement minimal client if none suitable

### CLI Design Principles
- **Subcommand-based:** Use `cipdip <command>` pattern (not `--mode` flags)
- **Minimal output:** Default to brief, scannable output; no emojis or decorative characters
- **Verbosity levels:** Silent/minimal (default), verbose (`--verbose`), debug (`--debug`)
- **Exit codes:** 0 (success), 1 (CLI/usage error), 2 (runtime error)
- **Help system:** Short, scannable help with examples; show defaults in help text
- **Error messages:** Write to stderr with format "error: <description>"; include helpful hints
- **Separation of concerns:** CLI output (stdout/stderr) separate from detailed logs (log file)
- **Flag naming:** Lowercase, hyphen-separated words
- **See:** `.cursorrules/go_cli_best_practices.md` for complete guidelines

### Transport Abstraction
- Create transport abstraction layer to support:
  - TCP 44818 (explicit messaging)
  - UDP 2222 (I/O implicit messaging)
  - UDP 44818 (discovery)
  - TCP 2222 (optional I/O)

### Error Handling
- Use `context.Context` for all operations
- Return structured errors with context
- Log errors with sufficient detail for debugging

### Metrics Format
- Primary: CSV (easy to analyze)
- Optional: JSON (structured, machine-readable)
- Include: timestamp, scenario, target_type, operation, target_name, service_code, success, rtt_ms, status, error
- Target types: click, emulator_adapter, emulator_logix, pcap_replay

### CIP/EtherNet-IP Library Strategy

#### Evaluation Phase
1. **Research existing libraries:**
   - Evaluate `gologix` (github.com/danomagnum/gologix)
   - Check for UDP 2222 support
   - Verify ForwardOpen/ForwardClose capabilities
   - Assess generic service invocation support
   - Review maintenance status and code quality

2. **Decision criteria:**
   - Must support: TCP 44818, UDP 2222, ForwardOpen/ForwardClose
   - Should support: Generic service invocation, UDP 44818 discovery
   - Nice to have: Well-maintained, good documentation

#### Implementation Approach

**Option A: Use Existing Library (Preferred)**
- If `gologix` or similar meets requirements:
  - Integrate as dependency
  - Wrap in our `Client` interface
  - Extend with missing features (UDP 2222, discovery)
  - Ensure protocol compliance through library

**Option B: Custom Implementation (Fallback)**
- If no suitable library exists:
  - Implement minimal EtherNet/IP/CIP client
  - Follow ODVA EtherNet/IP specifications
  - Implement only required features:
    - Session management (RegisterSession/UnregisterSession)
    - UCMM (SendRRData)
    - Connected messaging (SendUnitData, ForwardOpen/ForwardClose)
    - Discovery (ListIdentity)
  - Ensure protocol compliance through careful implementation

#### Protocol Compliance
- **Reference:** ODVA EtherNet/IP specifications (not RFC)
- **Focus areas:**
  - Correct EtherNet/IP encapsulation headers
  - Proper CIP service code handling
  - Accurate EPATH encoding
  - Valid connection parameters for ForwardOpen
- **Validation:** Test against real hardware (CLICK C2-03CPU) to verify compliance

---

## Progress Tracking

### Completed Tasks
- [x] Project plan creation
- [x] Requirements review
- [x] Phase 1: Project Setup & Foundation
- [x] Phase 2: Core CIP/EtherNet-IP Client
- [x] Phase 3: Configuration System
- [x] Phase 4: CLI Implementation (fully completed)
- [x] Phase 5: Metrics & Logging
- [x] Phase 6: Scenario Implementations (all 5 scenarios implemented)
- [x] Phase 7: Signal Handling & Error Management
- [x] Phase 8: Discovery Support
- [x] Phase 9: Testing & Documentation (basic)
- [x] Phase 10: Polish & Optimization (basic)
- [x] Phase 11: Server/Emulator Mode
- [x] Phase 12: ODVA Protocol Compliance Testing

### Current Focus
- ✅ Phase 12: ODVA Protocol Compliance Testing - **COMPLETED**
- ✅ UDP 2222 Transport Support - **COMPLETED**
- ✅ Packet Capture Analysis Framework - **COMPLETED**
- ✅ Hardware Testing Preparation - **COMPLETED**
- Phase 13: Vendor Implementation Research & Emulation (Documentation-based, no database)

### Next Steps
1. ✅ Phase 12: ODVA Protocol Compliance Testing - **COMPLETED**
   - ✅ Research ODVA specifications (documented in tests and docs/COMPLIANCE.md)
   - ✅ Implement packet structure validation tests (8 compliance tests passing)
   - ✅ Implement EPATH encoding validation
   - ✅ Implement CIP service code validation
   - ✅ Implement response structure validation (6 response tests passing)
   - ✅ Create integration test framework (ready for use with -tags=integration)
   - ✅ Create compliance documentation (docs/COMPLIANCE.md)
   - ✅ Packet capture analysis framework (basic implementation complete)
     - ✅ Packet analysis library (`internal/pcap`)
     - ✅ ODVA compliance validation
     - ✅ Packet comparison tools
     - ✅ CLI command (`cipdip pcap`)
   - ✅ Hardware testing preparation
     - ✅ Connectivity test command (`cipdip test`)
     - ✅ Improved error messages for hardware connections
     - ✅ Troubleshooting documentation
     - ✅ Hardware setup guide
   - ⏳ Hardware validation (when hardware installed)
2. ✅ **COMPLETED**: UDP 2222 transport support for I/O connections
   - ✅ Added transport field to ConnectionParams and IOConnection
   - ✅ Updated ForwardOpen to create UDP transport when transport=udp
   - ✅ Updated SendIOData/ReceiveIOData to use connection-specific transport
   - ✅ Updated io scenario to default to UDP 2222
   - ✅ Proper cleanup of UDP transports on disconnect
3. ✅ **IN PROGRESS**: Packet Capture Analysis Framework - **COMPLETED**
   - ✅ Packet analysis library (`internal/pcap`)
   - ✅ ODVA compliance validation
   - ✅ Packet comparison tools
   - ✅ Hex dump utilities
   - ✅ CLI command (`cipdip pcap`)
   - ✅ 6 tests passing
4. ⏳ **IN PROGRESS**: Phase 13 - Vendor implementation research and emulation
   - ✅ Documentation structure (markdown files, no database)
   - ✅ Vendor template files created (Rockwell, Schneider, Siemens)
   - ⏳ Vendor research (pending hardware installation)
   - ⏳ Optional emulation modes (future)

---

## Notes & Considerations

- **Device Compatibility:** Config-driven approach allows support for different CIP devices without code changes
- **Extensibility:** Generic `InvokeService` API allows adding new CIP services easily
- **Research Focus:** Tool is optimized for DPI testing, not production ICS use
- **Transport Priority:** UDP 2222 is critical for realistic I/O traffic patterns
- **Discovery:** Implemented as separate `cipdip discover` subcommand for lab verification and firewall behavior testing
- **Server Mode:** Lower priority but required for complete test matrix (real device, emulator, PCAP replay)
- **Config File Naming:** 
  - Client config: `cipdip_client.yaml` (default for `--config`)
  - Server config: `cipdip_server.yaml` (default for `--server-config`)
  - Common prefix `cipdip_` for consistency
- **CLI Design:** Subcommand-based architecture (`cipdip client`, `cipdip server`) preferred over `--mode` flag approach for better UX and extensibility
- **Protocol Compliance:** Custom implementation follows ODVA EtherNet/IP specifications; Phase 12 completed with comprehensive compliance testing (14 tests passing, documented in docs/COMPLIANCE.md)
- **Vendor Emulation:** Phase 13 will add research and optional emulation of vendor-specific implementations for enhanced DPI testing coverage

---

## References

### Specification Documents
- Main Spec: `.cursorrules/cip_scanner_spec.md`
- Addendum 1: `.cursorrules/cip_scanner_addendum.md` (Connected I/O support)
- Addendum 2: `.cursorrules/cip_scanner_addendum_v2.md` (Transport coverage)
- Addendum 3: `.cursorrules/cip_scanner_addendum_server.md` (Server/emulator mode)
- CLI Best Practices: `.cursorrules/go_cli_best_practices.md`

### Protocol Specifications
- **ODVA EtherNet/IP Specifications** (primary reference for protocol compliance)
  - EtherNet/IP Encapsulation Protocol
  - Common Industrial Protocol (CIP) Specification
  - CIP Connection Management
  - Note: These are ODVA member documents, not RFCs

### Vendor Documentation (for Phase 13)
- Rockwell Automation EtherNet/IP documentation
- Schneider Electric Modicon EtherNet/IP documentation
- Siemens PROFINET/EtherNet/IP documentation
- Other vendor-specific EtherNet/IP implementations

---

**Last Updated:** December 7, 2024  
**Status:** Core Implementation Complete - All Phases 1-12 Done ✅  
**Version:** 0.1  
**Recent Updates (December 2024):**
- ✅ Progress Indicators: Added to all 5 scenarios (baseline, mixed, stress, churn, io)
- ✅ Auto-Generate Default Config: `--quick-start` flag for zero-config usage
- ✅ Wireshark Integration: Packet validation using tshark dissector
- ✅ RegisterSession Request Extraction: Fixed and extracted from baseline captures
- ✅ Reference Packet Library: 8 of 9 packet types populated
- ✅ User-Friendly Error Messages: Integrated throughout codebase
- ✅ Packet Validation Layer: Comprehensive ENIP/CIP validation
- ✅ PCAP Extraction: Working for both baseline and real-world captures

**Previous Updates:**
- ✅ Phase 12: ODVA Protocol Compliance Testing (14 tests passing)
- ✅ UDP 2222 Transport Support for I/O connections
- ✅ Transport abstraction with TCP/UDP support
- ✅ Comprehensive test coverage for transport layer
- ✅ Packet Capture Analysis Framework (`cipdip pcap` command)
- ✅ Phase 13: Vendor Research Structure (documentation templates ready)

