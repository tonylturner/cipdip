# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Run Commands

```bash
# Build
go build ./cmd/cipdip

# Run tests
go test ./...

# Run single test
go test -run TestName ./internal/path/...

# Client scenario (strict ODVA by default)
./cipdip client --ip 10.0.0.50 --scenario baseline

# Server emulator
./cipdip server --personality adapter

# PCAP analysis
./cipdip pcap-summary --input pcaps/stress/ENIP.pcap

# Single CIP request (no config file needed)
./cipdip single --ip 10.0.0.50 --service 0x0E --class 0x01 --instance 0x01 --attribute 0x01

# Help
./cipdip help
./cipdip <command> --help
```

## Architecture

CIPDIP is a protocol-aware CIP/EtherNet-IP deep packet inspection test harness. It generates strict ODVA-framed traffic by default with optional vendor-variant profiles.

### Core Packages

| Package | Purpose |
|---------|---------|
| `cmd/cipdip` | CLI entry point using Cobra |
| `internal/enip` | EtherNet/IP framing, CPF items |
| `internal/cip/codec` | CIP encoding/decoding |
| `internal/cip/protocol` | CIP protocol types |
| `internal/cip/spec` | CIP spec labels and names |
| `internal/cip/client` | CIP client operations |
| `internal/cipclient` | EPATH parsing, validation |
| `internal/server/core` | Server emulator core |
| `internal/server/handlers` | CIP request handlers (standard + vendor-specific) |
| `internal/scenario` | Test scenarios (baseline, mixed, stress, io, edge, vendor_variants) |
| `internal/pcap` | PCAP parsing, replay, coverage analysis |
| `internal/reference` | Reference packet library |
| `internal/validation` | Loopback and Wireshark validation |
| `internal/ui` | TUI using bubbletea (workspace, wizards, catalog) |
| `internal/app` | CLI/TUI orchestration |
| `internal/config` | YAML config loading |
| `internal/metrics` | Latency, jitter, misclassification metrics |
| `internal/report` | Report generation models |

### Protocol Layers

- **ENIP layer**: `internal/enip` handles EtherNet/IP encapsulation and CPF (Common Packet Format)
- **CIP layer**: `internal/cip/*` handles CIP message routing, services, and paths
- **Server**: `internal/server/core` + `internal/server/handlers` with vendor logic under `handlers/vendors/*`

### Key Data Flow

1. Client reads YAML config (`cipdip_client.yaml` or `cipdip_server.yaml`)
2. Scenarios execute CIP requests via the client package
3. Server handlers process requests based on personality (adapter or logix_like)
4. Metrics collected for latency/jitter/misclassification analysis

## Protocol Posture

- **Default**: Strict ODVA-compliant ENIP/CIP framing
- **Optional**: Vendor-variant profiles for real-world deviations (only when identity matches)
- **Focus**: DPI falsification, Forward Open/I/O state handling, latency/jitter metrics

## Configuration

- `cipdip_client.yaml` - Client targets, I/O connections, protocol settings
- `cipdip_server.yaml` - Server personality, assemblies, tags
- See `docs/CONFIGURATION.md` for full reference

## Output Locations

- TUI workspaces: `workspaces/`
- Reports: `reports/`
- PCAP analysis: `notes/pcap/`
- Reference packets: `internal/reference/reference_packets_gen.go`

## Documentation Policy

- `docs/` is user-facing documentation only
- Internal/audit/plan content belongs in `notes/`

## Reference PCAP

`pcaps/stress/ENIP.pcap` identifies Rockwell Vendor ID 0x0001, Product `1756-ENBT/A`. Only apply `rockwell_enbt` profile when identity matches.
