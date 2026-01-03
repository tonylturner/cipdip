# CIPDIP Usage Examples

This document provides practical examples of using CIPDIP for various scenarios.

## Basic Client Usage

### Baseline Scenario

Low-frequency read-only polling:

```bash
cipdip client --ip 10.0.0.50 --scenario baseline --duration-seconds 600
```

### Stress Testing

High-frequency reads to stress DPI:

```bash
cipdip client --ip 10.0.0.50 --scenario stress --interval-ms 10 --duration-seconds 300
```

### Unconnected Send (UCMM wrapper)

Embedded CIP requests wrapped in Unconnected Send:

```bash
cipdip client --ip 10.0.0.50 --scenario unconnected_send --duration-seconds 300
```

### Rockwell Edge Pack

Consolidated Rockwell (Logix + ENBT) edge cases:

```bash
cipdip client --ip 10.0.0.50 --scenario rockwell --duration-seconds 300

# Firewall DPI packs (vendor-specific scenarios)
cipdip client --ip 10.0.0.50 --scenario firewall_hirschmann --config configs/firewall_test_pack.yaml.example
cipdip client --ip 10.0.0.50 --scenario firewall_moxa --config configs/firewall_test_pack.yaml.example
cipdip client --ip 10.0.0.50 --scenario firewall_dynics --config configs/firewall_test_pack.yaml.example
cipdip client --ip 10.0.0.50 --scenario firewall_pack --config configs/firewall_test_pack.yaml.example

# Composed run: stress pattern through Moxa firewall targeting Rockwell-tagged targets
cipdip client --ip 10.0.0.50 --scenario stress --target-tags rockwell --firewall-vendor moxa

# One-off service/class/instance check (no YAML edits)
cipdip single --ip 10.0.0.50 --service 0x0E --class 0x01 --instance 0x01 --attribute 0x01

# ARP probe before raw/tcpreplay replays
cipdip arp --iface eth0 --target-ip 10.0.0.10
```

### I/O Scenario with UDP 2222

Connected Class 1 I/O traffic:

```bash
cipdip client --ip 10.0.0.50 --scenario io --duration-seconds 300
```

## Server Mode

### Adapter Personality

```bash
cipdip server --personality adapter
```

### Logix-like Personality

```bash
cipdip server --personality logix_like --enable-udp-io
```

## Discovery

### Basic Discovery

```bash
cipdip discover
```

### Discovery with Timeout

```bash
cipdip discover --timeout 10s --interface <iface>
```

## Packet Analysis

### Analyze Captured Packet

```bash
# Export packet from Wireshark, then:
cipdip pcap --input packet.bin --validate
```

### Compare Packets

```bash
cipdip pcap --input packet1.bin --compare packet2.bin
```

## Complete Testing Workflow

### 1. Start Server Emulator

```bash
# Terminal 1
cipdip server --personality adapter --enable-udp-io
```

### 2. Run Client Scenario

```bash
# Terminal 2
cipdip client --ip 127.0.0.1 --scenario mixed \
  --metrics-file metrics.csv \
  --log-file test.log \
  --verbose
```

### 3. Capture Packets

```bash
# Terminal 3
tcpdump -i <iface> -w capture.pcap port 44818
```

### 4. Analyze Packets

```bash
# Extract packet from pcap (using Wireshark)
# Then analyze:
cipdip pcap --input packet.bin --validate
```

## Configuration Examples

### Client Config for CLICK PLC

```yaml
# cipdip_client.yaml
adapter:
  name: "CLICK C2-03CPU"
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
    o_to_t_rpi_ms: 20
    t_to_o_rpi_ms: 20
    o_to_t_size_bytes: 8
    t_to_o_size_bytes: 8
    priority: "scheduled"
    transport_class_trigger: 3
    class: 0x04
    instance: 0x65
```

### Client Config with CIP Profiles + Evidence-Based Targets

```yaml
# cipdip_client.yaml
adapter:
  name: "Profile Coverage Target"
  port: 44818

cip_profiles:
  - "energy"
  - "safety"
  - "motion"

# Optional: override or extend with explicit targets
custom_targets:
  - name: "Modbus_Read_Holding_Registers"
    service: "custom"
    service_code: 0x4E
    class: 0x44
    instance: 0x0001
    attribute: 0x0000
    request_payload_hex: "00000100" # start=0x0000, qty=0x0001 (UINTs)
```

### Client Config for Unconnected Send

```yaml
# cipdip_client.yaml
edge_targets:
  - name: "ConnMgr_Unconnected_Send"
    service: "custom"
    service_code: 0x52
    class: 0x0006
    instance: 0x0001
    attribute: 0x0000
    request_payload_hex: ""
    expected_outcome: "any"
    force_status: 0x01
```

### Server Config for Adapter

```yaml
# cipdip_server.yaml
server:
  name: "CIPDIP Adapter Emulator"
  personality: "adapter"
  tcp_port: 44818
  udp_io_port: 2222

adapter_assemblies:
  - name: "InputAssembly1"
    class: 0x04
    instance: 0x65
    attribute: 0x03
    size_bytes: 16
    update_pattern: "counter"
```

## Advanced Usage

### Custom Metrics Output

```bash
cipdip client --ip 10.0.0.50 --scenario baseline \
  --metrics-file metrics.csv \
  --duration-seconds 300
```

### Verbose Logging

```bash
cipdip client --ip 10.0.0.50 --scenario mixed \
  --log-file detailed.log \
  --verbose
```

### Debug Mode

```bash
cipdip client --ip 10.0.0.50 --scenario stress \
  --debug \
  --log-file debug.log
```

## Integration with Testing Tools

### With tcpdump

```bash
# Capture while running scenario
tcpdump -i eth0 -w test.pcap port 44818 &
cipdip client --ip 10.0.0.50 --scenario baseline
kill %1
```

### With Wireshark

1. Start Wireshark capture on interface
2. Run `cipdip client` in another terminal
3. Stop capture
4. Export packet bytes from Wireshark
5. Analyze with `cipdip pcap`

## Troubleshooting

### Connection Issues

```bash
# Test connectivity first
cipdip discover --timeout 5s

# Then try client with verbose logging
cipdip client --ip 10.0.0.50 --scenario baseline --verbose
```

### Validate Configuration

```bash
# Check config file syntax
# (cipdip will report errors on load)
cipdip client --ip 10.0.0.50 --scenario baseline --config cipdip_client.yaml
```

### Analyze Problematic Packets

```bash
# Capture problematic traffic
# Extract packet
# Analyze
cipdip pcap --input error_packet.bin --validate
```

### Investigate Unknown CIP Services

```bash
# Dump first 5 occurrences of service 0x51
cipdip pcap-dump --input pcaps/stress/ENIP.pcap --service 0x51 --max 5 --payload
```

## See Also

- `README.md` - Main documentation
- `docs/PCAP_USAGE.md` - Packet analysis guide
- `docs/COMPLIANCE.md` - Protocol compliance

