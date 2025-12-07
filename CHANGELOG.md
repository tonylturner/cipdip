# Changelog

All notable changes to CIPDIP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  - Compliance documentation (docs/COMPLIANCE.md)
  - Troubleshooting guide (docs/TROUBLESHOOTING.md)
  - Hardware setup guide (docs/HARDWARE_SETUP.md)
  - Packet analysis guide (docs/PCAP_USAGE.md)
  - Usage examples (docs/EXAMPLES.md)
  - Vendor research framework (docs/VENDOR_RESEARCH.md)
  - Project plan (project_plan.md)
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

