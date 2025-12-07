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
└── project_plan.md              # This file
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
**Status:** ✅ Completed (Partial - ForwardOpen/ForwardClose stubbed)

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
  - [ ] ForwardOpen/ForwardClose (connected messaging - stubbed, TODO)
  - [ ] SendIOData/ReceiveIOData (I/O connections - stubbed, TODO)

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
**Status:** ✅ Completed (Structure complete, integration pending)

- [ ] Implement CLI using `spf13/cobra` (required for subcommand architecture)
- [ ] Implement subcommands:
  - [ ] `cipdip help` - Top-level and per-command help
  - [ ] `cipdip version` - Version information
  - [ ] `cipdip client` - Client/scanner mode (primary functionality)
  - [ ] `cipdip server` - Server/emulator mode
  - [ ] `cipdip discover` - ListIdentity discovery subcommand
- [ ] `cipdip client` subcommand:
  - [ ] Required flags:
    - [ ] `--ip` - Target IP address
    - [ ] `--scenario` - Scenario name (baseline|mixed|stress|churn|io)
  - [ ] Optional flags:
    - [ ] `--port` - TCP port (default 44818, shown in help)
    - [ ] `--interval-ms` - Base polling interval
    - [ ] `--duration-seconds` - Run duration (default 300)
    - [ ] `--config` - Config file path (default "cipdip_client.yaml")
    - [ ] `--log-file` - Log file path
    - [ ] `--metrics-file` - Metrics output file path
    - [ ] `--verbose` - Enable verbose output
    - [ ] `--debug` - Enable debug output (optional)
    - [ ] `-h, --help` - Show help
- [ ] `cipdip server` subcommand:
  - [ ] `--listen-ip` - Listen IP address (default "0.0.0.0")
  - [ ] `--listen-port` - Listen port (default 44818)
  - [ ] `--personality` - Server personality (adapter|logix_like, default "adapter")
  - [ ] `--server-config` - Server config file path (default "cipdip_server.yaml")
  - [ ] `--enable-udp-io` - Enable UDP I/O on port 2222 (default false)
  - [ ] `-h, --help` - Show help
- [ ] `cipdip discover` subcommand:
  - [ ] `--interface` - Network interface for broadcast
  - [ ] `--timeout` - Discovery timeout duration
  - [ ] `--output` - Output format (text|json)
  - [ ] `-h, --help` - Show help
- [ ] Exit code implementation:
  - [ ] Exit code 0 for success
  - [ ] Exit code 1 for CLI/usage errors
  - [ ] Exit code 2 for runtime errors
- [ ] Verbosity levels:
  - [ ] Silent/minimal (default): Only necessary output, errors to stderr
  - [ ] Verbose (`--verbose`): Extra operational details
  - [ ] Debug (`--debug`): Detailed logs, raw packet hex dumps
- [ ] Help system:
  - [ ] `cipdip help` - Top-level usage with subcommand list
  - [ ] `cipdip help <command>` - Detailed help per command
  - [ ] `-h` / `--help` flags for each subcommand
  - [ ] Short, scannable help text (one-line descriptions, usage examples, options list)
  - [ ] Show default values in help text
- [ ] Error handling:
  - [ ] Required flags validation with clear error messages
  - [ ] Invalid input handling with helpful error messages
  - [ ] Error messages to stderr with format: "error: <description>"
  - [ ] Include helpful hints in error messages (e.g., "try 'cipdip help client'")
- [ ] Flag naming:
  - [ ] Lowercase, hyphen-separated words (e.g., `--listen-ip`, `--duration-seconds`)
  - [ ] Short flags only for common cases (`-h`, `-v` for verbose if used)
- [ ] Output style:
  - [ ] No emojis or decorative characters
  - [ ] Plain text, single-line or short multi-line summaries
  - [ ] Brief confirmations for success (e.g., "OK" or "Completed scenario 'baseline' in 60s (1200 operations, 0 errors)")

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
**Status:** ⏳ Pending

- [ ] Define Scenario interface
- [ ] Implement baseline scenario
  - [ ] Read-only polling loop
  - [ ] RTT measurement
  - [ ] Metrics collection
- [ ] Implement mixed scenario
  - [ ] Read and write operations
  - [ ] Pattern-based value generation (increment, toggle, constant)
  - [ ] Separate metrics for reads/writes
- [ ] Implement stress scenario
  - [ ] High-frequency reads
  - [ ] RTT histogram (if feasible)
  - [ ] Timeout tracking
- [ ] Implement churn scenario
  - [ ] Connection setup/teardown cycles
  - [ ] Per-cycle reads
  - [ ] Cycle metrics
- [ ] Implement io scenario
  - [ ] ForwardOpen for each I/O connection
  - [ ] UDP 2222 transport support (primary, default)
  - [ ] TCP 2222 transport support (optional, via transport field in config)
  - [ ] Transport field support (UDP/TCP selection from IOConnectionConfig)
  - [ ] O→T and T→O data handling
  - [ ] RPI-based timing (default interval: 10ms)
  - [ ] ForwardClose on shutdown

### Phase 7: Signal Handling & Error Management
**Status:** ⏳ Pending

- [ ] Context-based cancellation
- [ ] SIGINT (Ctrl+C) handling
- [ ] Graceful shutdown
- [ ] Metrics flush on exit
- [ ] Connection cleanup
- [ ] Error propagation and logging

### Phase 8: Discovery Support
**Status:** ⏳ Pending

- [ ] Implement `cipdip discover` subcommand (separate subcommand, not scenario)
- [ ] ListIdentity helper function
- [ ] UDP 44818 broadcast support
- [ ] Response collection with timeout
- [ ] DiscoveredDevice struct (IP, identity, product information)
- [ ] Output formatting (text or JSON)
- [ ] Network interface selection support

### Phase 9: Testing & Documentation
**Status:** ⏳ Pending

- [ ] Unit tests for core components
- [ ] Integration tests (if test hardware available)
- [ ] Example config files for different devices
- [ ] Usage documentation
- [ ] Troubleshooting guide

### Phase 10: Polish & Optimization
**Status:** ⏳ Pending

- [ ] Code review and cleanup
- [ ] Performance optimization
- [ ] Error message improvements
- [ ] Log formatting improvements
- [ ] Final documentation updates

### Phase 11: Server/Emulator Mode (Lower Priority)
**Status:** ⏳ Pending

- [ ] Server package implementation
  - [ ] Server interface definition
  - [ ] ENIPServer implementation
- [ ] TCP server on port 44818
  - [ ] Connection handling
  - [ ] Session management
- [ ] Optional UDP server on port 2222 (when `--enable-udp-io`)
  - [ ] I/O data handling
- [ ] Session handling
  - [ ] RegisterSession/UnregisterSession
  - [ ] Session state management
- [ ] Request handling
  - [ ] SendRRData (UCMM)
  - [ ] SendUnitData (connected messaging)
  - [ ] CIP request parsing and dispatch
- [ ] Adapter personality implementation
  - [ ] Assembly-style object model
  - [ ] Get_Attribute_Single (0x0E) support
  - [ ] Set_Attribute_Single (0x10) support for writable assemblies
  - [ ] Update patterns: counter, static, random, reflect_inputs
  - [ ] In-memory data storage with sync.RWMutex
- [ ] Logix-like personality implementation
  - [ ] Tag-based interface
  - [ ] Tag types: BOOL, SINT, INT, DINT, REAL
  - [ ] Tag update patterns: counter, static, random, sine, sawtooth
  - [ ] Tag namespace support
  - [ ] Array element access
- [ ] Server config loading and validation
  - [ ] Load `cipdip_server.yaml` (default)
  - [ ] Validate personality type
  - [ ] Validate assembly/tag configurations
- [ ] Error handling
  - [ ] Unknown services → appropriate CIP error status
  - [ ] Invalid paths → CIP path error status
- [ ] Integration with metrics
  - [ ] Track target_type as "emulator_adapter" or "emulator_logix"

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
- [x] Phase 2: Core CIP/EtherNet-IP Client (partial - ForwardOpen/ForwardClose stubbed)
- [x] Phase 3: Configuration System
- [x] Phase 4: CLI Implementation (structure complete)
- [x] Phase 5: Metrics & Logging

### Current Focus
- Phase 6: Scenario Implementations

### Next Steps
1. Implement scenario interface
2. Implement baseline scenario
3. Implement mixed, stress, churn, and io scenarios
4. Integrate scenarios with CLI, metrics, and logging

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

---

## References

- Main Spec: `.cursorrules/cip_scanner_spec.md`
- Addendum 1: `.cursorrules/cip_scanner_addendum.md` (Connected I/O support)
- Addendum 2: `.cursorrules/cip_scanner_addendum_v2.md` (Transport coverage)
- Addendum 3: `.cursorrules/cip_scanner_addendum_server.md` (Server/emulator mode)
- CLI Best Practices: `.cursorrules/go_cli_best_practices.md`

---

**Last Updated:** 2025-01-27  
**Status:** Implementation In Progress - Phases 1-5 Complete, Scenarios Next

