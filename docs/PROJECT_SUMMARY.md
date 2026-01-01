# CIPDIP Project Summary

## Overview

**CIPDIP** is a command-line tool written in Go for generating repeatable, controllable CIP/EtherNet-IP traffic for firewall Deep Packet Inspection (DPI) research. The tool can act as both a CIP client (scanner) and a CIP server (emulator), generating protocol-compliant traffic patterns for testing firewall DPI capabilities.

## Project Purpose

The primary goal is to generate realistic, ODVA-compliant EtherNet/IP traffic that can be used to:
- Test firewall DPI systems' ability to identify and classify CIP traffic
- Generate baseline traffic patterns for comparison
- Create repeatable test scenarios for DPI research
- Emulate CIP devices for testing client applications

## Key Features

### 1. Client/Scanner Mode
- **Traffic Scenarios**: Five distinct traffic patterns:
  - `baseline`: Low-frequency read-only polling (250ms interval)
  - `mixed`: Medium-frequency mixed reads/writes (100ms interval)
  - `stress`: High-frequency reads (20ms interval)
  - `churn`: Connection setup/teardown cycles
  - `io`: Connected Class 1 I/O-style behavior (10ms interval)
- **Configurable Targets**: YAML-based configuration for CIP paths (class/instance/attribute)
- **Metrics Collection**: Structured logging with CSV/JSON output
- **Packet Capture**: Built-in PCAP capture support

### 2. Server/Emulator Mode
- **Personalities**: Two emulation modes:
  - `adapter`: Assembly-style object model (like CLICK PLCs)
  - `logix_like`: Tag-based interface (like Allen-Bradley Logix controllers)
- **Protocol Support**: Full EtherNet/IP session management, UCMM, and connected messaging
- **I/O Support**: Optional UDP 2222 for Class 1 I/O data

### 3. Discovery Mode
- UDP broadcast `ListIdentity` requests
- Device discovery on EtherNet/IP networks

### 4. Baseline Test Suite
- Automated test suite that runs all scenarios against all server personalities
- Generates reference PCAP files for documentation
- Creates combined and per-scenario captures

## Architecture

### Core Components

```
cipdip/
├── cmd/cipdip/          # CLI commands (client, server, discover, baseline, etc.)
├── internal/
│   ├── cipclient/       # CIP/EtherNet-IP client library
│   ├── server/          # CIP server/emulator implementation
│   ├── scenario/         # Traffic scenario implementations
│   ├── config/          # YAML configuration parsing
│   ├── metrics/         # Metrics collection and export
│   ├── logging/         # Structured logging
│   ├── capture/         # PCAP capture functionality
│   └── pcap/            # PCAP analysis tools
└── configs/             # Example configuration files
```

### Protocol Stack

The tool implements a custom EtherNet/IP and CIP stack:

1. **Transport Layer**: TCP 44818 (explicit messaging), UDP 2222 (I/O data), UDP 44818 (discovery)
2. **EtherNet/IP Layer**: ENIP encapsulation (RegisterSession, SendRRData, SendUnitData, etc.)
3. **CIP Layer**: CIP services (Get/Set Attribute Single, ForwardOpen/Close, etc.)
4. **EPATH Encoding**: CIP Electronic Keying Path encoding/decoding

### Key Design Decisions

1. **Custom Stack**: Built a custom CIP/EtherNet-IP implementation rather than using existing libraries to:
   - Maintain full control over protocol compliance
   - Generate traffic specifically for DPI testing
   - Avoid unnecessary dependencies
   - Ensure ODVA specification compliance

2. **Subcommand Architecture**: Uses `spf13/cobra` for CLI with subcommands:
   - `cipdip client` - Run traffic scenarios
   - `cipdip server` - Run emulator
   - `cipdip discover` - Network discovery
   - `cipdip baseline` - Automated test suite
   - `cipdip pcap` - Packet analysis
   - `cipdip test` - Connectivity testing
   - `cipdip install` - Binary installation with shell completion

3. **YAML Configuration**: Separate config files for client and server:
   - `cipdip_client.yaml` - Client targets and I/O connections
   - `cipdip_server.yaml` - Server personalities and assemblies/tags

## How It Works

### Client Mode Flow

1. **Configuration Loading**: Loads `cipdip_client.yaml` with target CIP paths
2. **Connection**: Establishes TCP connection to target device (port 44818)
3. **Session Registration**: Sends `RegisterSession` ENIP command
4. **Scenario Execution**: Runs selected scenario (baseline, mixed, stress, churn, or io)
5. **Traffic Generation**: 
   - Sends CIP requests (Get/Set Attribute Single)
   - For I/O scenario: Establishes ForwardOpen connection, sends/receives I/O data
6. **Metrics Collection**: Records RTT, success/failure, status codes
7. **Cleanup**: Sends `UnregisterSession`, closes connection

### Server Mode Flow

1. **Configuration Loading**: Loads `cipdip_server.yaml` with personality configuration
2. **Listener Startup**: Starts TCP listener on port 44818 (optionally UDP 2222)
3. **Connection Handling**: Accepts incoming connections
4. **Session Management**: Tracks ENIP sessions (RegisterSession/UnregisterSession)
5. **Request Processing**:
   - Parses ENIP commands (SendRRData, SendUnitData)
   - Decodes CIP requests
   - Routes to personality handler (adapter or logix_like)
   - Generates appropriate responses
6. **Special Handling**: ForwardOpen/ForwardClose for I/O connections

### Traffic Scenarios

Each scenario generates different traffic patterns:

- **Baseline**: Periodic reads at 250ms intervals - simulates normal monitoring
- **Mixed**: Alternating reads and writes at 100ms - simulates control operations
- **Stress**: Rapid reads at 20ms - tests DPI under high load
- **Churn**: Repeated connect/disconnect cycles - tests connection handling
- **IO**: ForwardOpen connection with bidirectional I/O data at 10ms - simulates real-time I/O

## Protocol Compliance

The implementation follows ODVA EtherNet/IP specifications:

- **ENIP Commands**: RegisterSession (0x0065), UnregisterSession (0x0066), SendRRData (0x006F), SendUnitData (0x0070), ListIdentity (0x0063)
- **CIP Services**: Get_Attribute_Single (0x0E), Set_Attribute_Single (0x10), Forward_Open (0x54), Forward_Close (0x4E)
- **EPATH Encoding**: Proper segment encoding (class, instance, attribute)
- **Byte Order**: All multi-byte values use little-endian (per ENIP/CIP spec)
- **Session Management**: Proper session ID allocation and tracking

Compliance is validated through:
- Comprehensive test suite with ODVA specification audits
- Protocol compliance tests that validate byte-level correctness
- Packet capture analysis tools

## Usage Examples

### Basic Client Usage

```bash
# Run baseline scenario against a device
cipdip client --ip 10.0.0.50 --scenario baseline

# Run with packet capture
cipdip client --ip 10.0.0.50 --scenario mixed --pcap capture.pcap

# Run stress test with custom interval
cipdip client --ip 10.0.0.50 --scenario stress --interval-ms 10
```

### Server Usage

```bash
# Start adapter personality server
cipdip server --personality adapter

# Start with UDP I/O enabled
cipdip server --personality logix_like --enable-udp-io --pcap server.pcap
```

### Baseline Test Suite

```bash
# Run all scenarios against all personalities (generates reference PCAPs)
cipdip baseline

# Custom output directory and duration
cipdip baseline --output-dir ./my_captures --duration 5
```

### Discovery

```bash
# Discover devices on network
cipdip discover --interface eth0 --timeout 5
```

## Configuration

### Client Configuration (`cipdip_client.yaml`)

```yaml
adapter:
  name: "Test Adapter"
  port: 44818

read_targets:
  - name: "InputBlock1"
    service: "get_attribute_single"
    class: 0x04
    instance: 0x65
    attribute: 0x03

io_connections:
  - name: "IOConn1"
    transport: "udp"
    class: 0x04
    instance: 0x65
    o_to_t_rpi_ms: 20
    t_to_o_rpi_ms: 20
    o_to_t_size_bytes: 8
    t_to_o_size_bytes: 8
```

### Server Configuration (`cipdip_server.yaml`)

```yaml
server:
  personality: "adapter"
  listen_ip: "0.0.0.0"
  tcp_port: 44818
  enable_udp_io: false
  udp_io_port: 2222

adapter_assemblies:
  - name: "InputAssembly1"
    class: 0x04
    instance: 0x65
    attribute: 0x03
    size_bytes: 16
    update_pattern: "counter"
```

## Testing and Validation

### Test Coverage

- **Unit Tests**: Core protocol encoding/decoding
- **Integration Tests**: Client-server interactions
- **Compliance Tests**: ODVA specification validation
- **Scenario Tests**: All traffic scenarios with mock clients
- **Server Tests**: Lifecycle, session management, personality handling

### Compliance Validation

- Protocol compliance tests validate against ODVA specifications
- Packet capture analysis tools verify generated traffic
- Baseline test suite generates reference captures for comparison

## Technical Stack

- **Language**: Go 1.24+
- **Dependencies**:
  - `spf13/cobra` - CLI framework
  - `gopkg.in/yaml.v3` - YAML parsing
  - `google/gopacket` - Packet capture and analysis
- **Protocols**: Custom implementation of EtherNet/IP and CIP

## Output and Logging

- **Structured Logging**: Human-readable, CSV, or JSON formats
- **Metrics**: RTT, success/failure rates, status codes, target types
- **PCAP Capture**: Standard PCAP format for analysis in Wireshark
- **Verbose/Debug Modes**: Detailed output for troubleshooting

## Current Status

The tool is functional and includes:
- ✅ Full client mode with all 5 scenarios
- ✅ Server mode with adapter and logix_like personalities
- ✅ Discovery mode
- ✅ Baseline test suite
- ✅ PCAP capture and analysis
- ✅ Comprehensive test coverage
- ✅ ODVA compliance validation
- ✅ Documentation

## Future Enhancements

- Vendor-specific emulation modes (Rockwell, Schneider, Siemens)
- Additional CIP services and object classes
- Enhanced I/O data generation patterns
- Statistical analysis of captured traffic
- Integration with Wireshark dissector

## Key Files

- `cmd/cipdip/main.go` - CLI entry point
- `internal/cipclient/` - CIP/EtherNet-IP client library
- `internal/server/` - Server/emulator implementation
- `internal/scenario/` - Traffic scenario implementations
- `docs/COMPLIANCE.md` - Protocol compliance documentation
- `docs/CONFIGURATION.md` - Configuration guide

## Contact and Documentation

- Main documentation: `README.md`
- Configuration guide: `docs/CONFIGURATION.md`
- Compliance details: `docs/COMPLIANCE.md`
- Project plan: `project_plan.md`

