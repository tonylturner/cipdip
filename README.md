# CIPDIP

![Go](https://img.shields.io/badge/go-1.22+-00ADD8?logo=go) ![License](https://img.shields.io/badge/license-Apache%202.0-blue) ![Version](https://img.shields.io/badge/version-0.2.1-green)
![SBOM](https://img.shields.io/badge/SBOM-available-brightgreen) ![OSV-Scanner](https://img.shields.io/badge/osv--scanner-no%20known%20vulns-brightgreen)
![PCAP Validated](https://img.shields.io/badge/pcap-validated-brightgreen) ![CIP](https://img.shields.io/badge/protocol-CIP%20%2F%20EtherNet%2FIP-blue) ![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-0078D6)

Protocol-aware CIP/EtherNet-IP deep packet inspection test harness. CIPDIP generates strict ODVA-framed traffic by default, with optional vendor-variant profiles for known identities. Features an interactive TUI dashboard, client/scanner scenarios, server/emulator mode, PCAP analysis, and validation workflows.

## Features

- **Interactive TUI Dashboard** - Unified view with real-time traffic visualization, service stats, and error tracking
- **Client Scenarios** - Baseline, stress, I/O, edge, mixed, firewall, and vendor variant testing
- **Server Emulator** - Adapter and Logix-like personalities with configurable responses
- **PCAP Analysis** - Summary, coverage, diff, replay, rewrite, and hex dump modes
- **CIP Service Catalog** - Browse and test CIP services with live device requests
- **TCP Metrics** - Retransmit, reset, and lost segment detection via tshark integration
- **Workspace Management** - Organize runs, profiles, and captures per project

## Quick Start

```bash
# Build
go build ./cmd/cipdip

# Launch interactive TUI
./cipdip poc

# Or use CLI directly:
# Client scenario (strict ODVA by default)
./cipdip client --ip 10.0.0.50 --scenario baseline

# Server emulator
./cipdip server --personality adapter

# PCAP summary
./cipdip pcap-summary --input pcaps/ENIP.pcap

# Version
./cipdip version
```

## TUI Dashboard

The interactive dashboard (`cipdip poc`) provides:

| Panel | Description |
|-------|-------------|
| **TRAFFIC** | Colored braille graph showing reads (blue), writes (orange), errors (red), other (green) |
| **SYSTEM** | Workspace info, profile count, PCAP count, session duration |
| **STATS** | Real-time reads/writes/errors/connections counters |
| **SERVICES** | Bar chart of CIP service distribution from PCAP |
| **RECENT RUNS** | History of client, server, and PCAP operations |
| **ERRORS** | Validation errors, TCP retransmits, CIP error responses |

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `c` | Open Client panel |
| `s` | Open Server panel |
| `p` | Open PCAP panel |
| `k` | Open Catalog browser |
| `Tab` | Cycle panel focus |
| `h` | Toggle help |
| `q` | Quit |

### PCAP Analysis Modes

| Mode | Description |
|------|-------------|
| **Summary** | Quick stats and service breakdown |
| **Report** | Full markdown report generation |
| **Coverage** | CIP service coverage analysis |
| **Replay** | Re-send packets to target device |
| **Rewrite** | Modify IPs/MACs in capture |
| **Dump** | Hex dump with service filtering |
| **Diff** | Compare two PCAP files |

Press `[b]` in PCAP mode to browse for files with built-in file navigator.

## CLI Examples

```bash
# Quick-start config generation
./cipdip client --ip 10.0.0.50 --scenario mixed --quick-start

# Single CIP request (no config file needed)
./cipdip single --ip 10.0.0.50 --service 0x0E --class 0x01 --instance 0x01 --attribute 0x01

# PCAP replay (app-layer only)
./cipdip pcap-replay --input pcaps/ENIP.pcap --server-ip 10.0.0.10 --app-only

# PCAP diff
./cipdip pcap-diff --file1 before.pcap --file2 after.pcap

# Generate coverage report
./cipdip pcap-coverage --dir pcaps/
```

## TCP Metrics

When tshark is available, CIPDIP provides TCP-level analysis:

- **Retransmits** - Packet retransmission count
- **Resets** - TCP RST flag occurrences
- **Lost Segments** - Detected packet loss
- **CIP Errors** - Non-zero CIP status responses

These metrics appear in the ERRORS panel and are factored into the error rate graph.

## Configuration

- `cipdip_client.yaml` - Client targets, I/O connections, protocol settings
- `cipdip_server.yaml` - Server personality, assemblies, tags

See `docs/CONFIGURATION.md` for full reference.

## Documentation

- [Configuration Guide](docs/CONFIGURATION.md)
- [Examples](docs/EXAMPLES.md)
- [Compliance Testing](docs/COMPLIANCE_TESTING.md)
- [PCAP Usage](docs/PCAP_USAGE.md)
- [Reference Packets](docs/REFERENCE_PACKETS.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Hardware Setup](docs/HARDWARE_SETUP.md)
- [CIP Reference](docs/cip_reference.md)

## Project Structure

```
cipdip/
├── cmd/cipdip/       # CLI entry point
├── internal/
│   ├── tui/          # TUI dashboard and panels
│   ├── enip/         # EtherNet/IP framing
│   ├── cip/          # CIP protocol handling
│   ├── server/       # Server emulator
│   ├── scenario/     # Test scenarios
│   ├── pcap/         # PCAP analysis
│   └── validation/   # Packet validation
├── pcaps/            # Sample captures
├── catalogs/         # CIP service definitions
├── profiles/         # Device profiles
└── docs/             # Documentation
```

## Notes

- Default behavior is strict ODVA framing; vendor-variant profiles apply only when device identity matches
- TCP metrics require tshark (Wireshark) to be installed
- Use `cipdip help` or `cipdip <command> --help` for full CLI options

## License

Apache License 2.0
