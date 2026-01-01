# CIPDIP

**CIP/EtherNet-IP Scanner for DPI Testing**

CIPDIP is a Go-based command-line tool designed to generate repeatable, controllable CIP/EtherNet-IP traffic for firewall Deep Packet Inspection (DPI) research testing. It acts as both a CIP client/scanner and a CIP server/emulator, enabling comprehensive testing scenarios.

## Features

- **Multiple Traffic Scenarios**: baseline, mixed, stress, churn, io, edge_valid, edge_vendor, vendor_variants, mixed_state
- **Transport Support**: TCP 44818 (explicit messaging), UDP 2222 (I/O), UDP 44818 (discovery)
- **Config-Driven**: YAML-based configuration for flexible device targeting
- **Server Mode**: Emulator with adapter and logix-like personalities
- **Discovery**: ListIdentity discovery via separate subcommand
- **Structured Output**: CSV/JSON metrics and detailed logging

## Installation

### Build from Source

```bash
git clone https://github.com/tturner/cipdip.git
cd cipdip
go build ./cmd/cipdip
```

### Install Binary and Shell Completion

After building, you can install the binary to your PATH and set up shell completion:

```bash
# Install to PATH and set up completion for your shell
./cipdip install

# Or specify a custom install directory
./cipdip install --binary-path /usr/local/bin

# Force overwrite existing installation
./cipdip install --force
```

The install command will:
- Detect your shell (zsh, bash, fish, PowerShell)
- Install the binary to a directory in your PATH
- Set up tab completion for your shell
- Provide instructions for enabling completion

## Quick Start

### Client Mode (Scanner)

```bash
# Basic usage
cipdip client --ip 10.0.0.50 --scenario baseline

# With custom config and metrics output
cipdip client \
  --ip 10.0.0.50 \
  --scenario mixed \
  --config ./configs/cipdip_client.yaml \
  --metrics-file ./metrics.csv \
  --duration-seconds 300
```

### Server Mode (Emulator)

```bash
# Start adapter personality server
cipdip server --personality adapter --listen-ip 0.0.0.0

# Start logix-like personality server
cipdip server --personality logix_like --server-config ./configs/cipdip_server.yaml
```

### Discovery

```bash
# Discover CIP devices on network
cipdip discover --interface eth0 --timeout 5s
```

### Test Connectivity

```bash
# Test basic connectivity to a device
cipdip test --ip 10.0.0.50

# Test with custom port
cipdip test --ip 10.0.0.50 --port 44818
```

### Packet Analysis

```bash
# Analyze a captured packet file
cipdip pcap --input packet.bin --validate

# Compare two packets
cipdip pcap --input packet1.bin --compare packet2.bin

# Output in JSON format
cipdip pcap --input packet.bin --format json

# Summarize ENIP/CIP traffic in a PCAP
cipdip pcap-summary --input pcaps/stress/ENIP.pcap
```

### Reference Extraction

```bash
# Extract reference packets from PCAPs (pcaps/* by default)
cipdip extract-reference --baseline-dir pcaps --output internal/cipclient/reference_packets_gen.go
```

## Configuration

For detailed configuration documentation, see [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

### Client Config (`cipdip_client.yaml`)

```yaml
adapter:
  name: "CLICK C2-03CPU"
  port: 44818

read_targets:
  - name: "InputBlock1"
    service: "get_attribute_single"
    class: 0x04
    instance: 0x65
    attribute: 0x03

write_targets:
  - name: "OutputBlock1"
    service: "set_attribute_single"
    class: 0x04
    instance: 0x67
    attribute: 0x03
    pattern: "increment"
    initial_value: 0

io_connections:
  - name: "IOConn1"
    transport: "udp"
    o_to_t_rpi_ms: 20
    t_to_o_rpi_ms: 20
    o_to_t_size_bytes: 8
    t_to_o_size_bytes: 8
    priority: "scheduled"
    transport_class_trigger: 3
    class: 0x04
    instance: 0x65
```

### Server Config (`cipdip_server.yaml`)

```yaml
server:
  name: "Go CIP Emulator"
  personality: "adapter"
  listen_ip: "0.0.0.0"
  tcp_port: 44818
  udp_io_port: 2222
  enable_udp_io: false

adapter_assemblies:
  - name: "InputAssembly1"
    class: 0x04
    instance: 0x65
    attribute: 0x03
    size_bytes: 16
    update_pattern: "counter"
```

## Scenarios

- **baseline**: Low-frequency read-only polling (250ms default)
- **mixed**: Medium-frequency mixed reads/writes (100ms default)
- **stress**: High-frequency reads (20ms default)
- **churn**: Connection setup/teardown cycles (100ms default)
- **io**: Connected Class 1 I/O-style behavior (10ms default, UDP 2222)
- **edge_valid**: Protocol-valid edge cases for DPI falsification
- **edge_vendor**: Vendor-specific edge cases (tag/connection manager extras)
- **vendor_variants**: Replays traffic across protocol variants
- **mixed_state**: Interleaves UCMM and connected I/O traffic

## Command Reference

### `cipdip test`

Test basic connectivity to a CIP device.

**Required flags:**
- `--ip`: Target CIP adapter IP address

**Optional flags:**
- `--port`: TCP port (default: 44818)

**Example:**
```bash
cipdip test --ip 10.0.0.50
```

### `cipdip pcap`

Analyze EtherNet/IP packet captures for compliance and structure validation.

**Required flags:**
- `--input`: Input packet file (raw binary)

**Optional flags:**
- `--validate`: Validate ODVA compliance
- `--compare`: Compare with another packet file
- `--format`: Output format (text|json, default: text)
- `--output`: Output file (default: stdout)
- `--hexdump`: Display raw packet hex dump

**Examples:**
```bash
# Analyze and validate a packet
cipdip pcap --input capture.bin --validate

# Compare two packets
cipdip pcap --input packet1.bin --compare packet2.bin
```

### `cipdip client`

Scanner mode that connects to CIP targets and generates traffic.

**Required flags:**
- `--ip`: Target CIP adapter IP address
- `--scenario`: Scenario name (baseline|mixed|stress|churn|io|edge_valid|edge_vendor|vendor_variants|mixed_state)

**Optional flags:**
- `--port`: TCP port (default: 44818)
- `--interval-ms`: Base polling interval
- `--duration-seconds`: Run duration in seconds (default: 300)
- `--config`: Config file path (default: cipdip_client.yaml)
- `--log-file`: Log file path
- `--metrics-file`: Metrics output file path
- `--verbose`: Enable verbose output
- `--debug`: Enable debug output

### `cipdip server`

Server/emulator mode that acts as a CIP endpoint.

**Optional flags:**
- `--listen-ip`: Listen IP address (default: 0.0.0.0)
- `--listen-port`: Listen port (default: 44818)
- `--personality`: Server personality (adapter|logix_like, default: adapter)
- `--server-config`: Server config file path (default: cipdip_server.yaml)
- `--enable-udp-io`: Enable UDP I/O on port 2222 (default: false)

### `cipdip discover`

Discover CIP devices on the network using ListIdentity.

**Optional flags:**
- `--interface`: Network interface for broadcast
- `--timeout`: Discovery timeout duration
- `--output`: Output format (text|json)

### `cipdip help`

Show help information for commands.

### `cipdip version`

Print version information.

## Exit Codes

- `0`: Success
- `1`: CLI or usage error
- `2`: Runtime error (network failure, CIP error)

## Output

- **Default**: Minimal output to stdout, errors to stderr
- **Verbose**: Extra operational details
- **Debug**: Detailed logs, raw packet hex dumps
- **Metrics**: CSV/JSON format with operation details (plus `*.summary.csv` for percentiles/buckets)
- **Logs**: Detailed operational events (when `--log-file` specified)

## Requirements

- Go 1.21 or higher
- Network access to CIP devices
- YAML config files (examples provided in `configs/`)

## License

Apache License 2.0


