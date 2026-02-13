# CIPDIP

![Go](https://img.shields.io/badge/go-1.22+-00ADD8?logo=go) ![License](https://img.shields.io/badge/license-Apache%202.0-blue) ![Version](https://img.shields.io/badge/version-0.2.1-green)
![SBOM](https://img.shields.io/badge/SBOM-CycloneDX-brightgreen) ![PCAP Validated](https://img.shields.io/badge/pcap-validated-brightgreen) ![CIP](https://img.shields.io/badge/protocol-CIP%20%2F%20EtherNet%2FIP-blue) ![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-0078D6)

Protocol-aware CIP/EtherNet-IP deep packet inspection test harness. CIPDIP generates strict ODVA-framed traffic with optional vendor-variant profiles, designed for evaluating industrial firewall DPI engines, validating protocol implementations, and testing CIP/ENIP security controls.

## Use Cases

- **Firewall DPI evaluation** -- Generate controlled CIP traffic to measure detection accuracy, false positive rates, and protocol parsing depth
- **Protocol compliance testing** -- Validate ODVA-compliant framing, connection lifecycle, and service handling
- **Security research** -- Test evasion techniques (TCP segmentation, timing manipulation, protocol anomalies) against industrial DPI engines
- **Device interoperability** -- Verify CIP behavior across Rockwell, Schneider, Siemens, and other vendor implementations

## Features

- **Interactive TUI Dashboard** -- Real-time traffic visualization, service stats, error tracking, and workspace management
- **21 Test Scenarios** -- Baseline, stress, I/O, edge cases, vendor variants, PCCC, Modbus, DPI explicit messaging, evasion, and firewall regression packs
- **Server Emulator** -- Adapter and Logix-like personalities with configurable responses, fault injection, and session policies
- **PCAP Analysis** -- Summary, coverage, diff, replay, rewrite, hex dump, and multi-file analysis modes
- **Distributed Orchestration** -- Run manifests, multi-agent coordination via SSH, run bundles with integrity verification
- **CIP Service Catalog** -- Browse and test CIP services with live device requests
- **TCP Metrics** -- Retransmit, reset, and lost segment detection via tshark integration
- **Protocol Profiles** -- Strict ODVA, Rockwell, Schneider M580, Siemens S7-1200, and legacy compatibility modes

## Requirements

- **Go 1.22+** (build from source)
- **Optional:** tshark (Wireshark CLI) for TCP-level metrics
- **Optional:** libpcap / npcap for packet capture and ARP resolution

## Quick Start

```bash
# Build
go build ./cmd/cipdip

# Launch interactive TUI
./cipdip ui

# Or use CLI directly
./cipdip client --ip 10.0.0.50 --scenario baseline
./cipdip server --personality adapter
./cipdip pcap-summary --input capture.pcap
./cipdip single --ip 10.0.0.50 --service 0x0E --class 0x01 --instance 0x01 --attribute 0x01
```

## Installation

```bash
# From source
git clone https://github.com/tturner/cipdip.git
cd cipdip
go build ./cmd/cipdip

# Install to PATH
go install ./cmd/cipdip

# Or use the built-in installer (copies to system PATH)
./cipdip install
```

## TUI Dashboard

The interactive dashboard (`cipdip ui`) provides a unified workspace with real-time monitoring:

| Panel | Description |
|-------|-------------|
| **TRAFFIC** | Braille graph showing reads, writes, errors, and other operations |
| **STATS** | Real-time counters for requests, errors, connections |
| **SERVICES** | Bar chart of CIP service distribution |
| **RECENT RUNS** | History of client, server, and PCAP operations |
| **ERRORS** | Validation errors, TCP metrics, CIP error responses |

**Keyboard:** `c` client, `s` server, `p` PCAP, `k` catalog, `Tab` cycle panels, `h` help, `q` quit

## CLI Reference

```bash
# Scenarios
./cipdip client --ip TARGET --scenario baseline     # Low-frequency read polling
./cipdip client --ip TARGET --scenario stress        # High-frequency reads
./cipdip client --ip TARGET --scenario mixed         # Reads + writes
./cipdip client --ip TARGET --scenario churn         # Connection cycling
./cipdip client --ip TARGET --scenario io            # ForwardOpen + UDP I/O
./cipdip client --ip TARGET --scenario dpi_explicit  # 6-phase DPI stress test
./cipdip client --ip TARGET --scenario evasion_segment  # TCP segmentation evasion
./cipdip client --ip TARGET --scenario pccc          # PCCC-over-CIP (legacy PLC)
./cipdip client --ip TARGET --scenario modbus        # Modbus-over-CIP

# PCAP analysis
./cipdip pcap-summary --input capture.pcap
./cipdip pcap-coverage --dir pcaps/
./cipdip pcap-diff --file1 before.pcap --file2 after.pcap
./cipdip pcap-replay --input capture.pcap --server-ip TARGET --app-only

# Orchestration
./cipdip run manifest path/to/manifest.yaml
./cipdip bundle verify runs/my-run
./cipdip agent check ssh://user@host

# Discovery
./cipdip discover --timeout 5

# Help
./cipdip help
./cipdip <command> --help
```

## Configuration

- `cipdip_client.yaml` -- Client targets, I/O connections, protocol settings
- `cipdip_server.yaml` -- Server personality, assemblies, tags

See [Configuration Guide](docs/CONFIGURATION.md) for full reference.

## Documentation

| Document | Description |
|----------|-------------|
| [Configuration](docs/CONFIGURATION.md) | Full client/server YAML reference |
| [Examples](docs/EXAMPLES.md) | Usage examples and workflows |
| [Compliance Testing](docs/COMPLIANCE_TESTING.md) | Test methodology and validation |
| [PCAP Usage](docs/PCAP_USAGE.md) | Capture analysis modes |
| [Orchestration](docs/ORCHESTRATION.md) | Distributed test coordination |
| [Run Manifests](docs/RUN_MANIFEST.md) | Manifest YAML schema |
| [CIP Reference](docs/cip_reference.md) | Protocol implementation details |
| [Hardware Setup](docs/HARDWARE_SETUP.md) | Lab environment setup |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and fixes |
| [TUI Guide](docs/TUI_GUIDE.md) | Dashboard navigation |
| [Vendor Notes](docs/vendors/) | Rockwell, Schneider, Siemens, Omron, Keyence |

## Project Structure

```
cipdip/
├── cmd/cipdip/          # CLI entry point (Cobra)
├── internal/
│   ├── cip/             # CIP protocol (codec, client, spec)
│   ├── enip/            # EtherNet/IP framing, CPF items
│   ├── server/          # Emulator (core, handlers, vendor logic)
│   ├── scenario/        # 21 test scenarios
│   ├── evasion/         # DPI evasion techniques
│   ├── pcap/            # PCAP parsing, replay, coverage
│   ├── tui/             # Interactive dashboard (bubbletea)
│   ├── orch/            # Orchestration (controller, bundles)
│   ├── transport/       # Local + SSH execution
│   ├── metrics/         # Latency, jitter, misclassification
│   ├── config/          # YAML config loading
│   └── validation/      # Loopback and Wireshark validation
├── catalogs/            # CIP service definitions
├── profiles/            # Device test profiles
├── baseline_captures/   # Synthetic reference PCAPs
├── docs/                # User documentation
└── agents.yaml.example  # Agent registry template
```

## SBOM

A CycloneDX Software Bill of Materials is available at [docs/sbom.cdx.json](docs/sbom.cdx.json).

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes before submitting a pull request.

## License

[Apache License 2.0](LICENSE)
