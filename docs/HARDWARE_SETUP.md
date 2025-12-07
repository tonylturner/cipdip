# Hardware Setup Guide

This guide helps you prepare for testing CIPDIP with real hardware devices.

## Pre-Installation Checklist

Before installing your hardware, ensure you have:

- [ ] **Network Configuration**
  - Device IP address and subnet mask
  - Gateway/router configuration
  - Network interface on test machine configured

- [ ] **Device Documentation**
  - EtherNet/IP configuration guide
  - CIP object model documentation
  - Connection parameter requirements
  - Supported services list

- [ ] **CIPDIP Configuration**
  - Config file created (`cipdip_client.yaml`)
  - CIP paths identified (class/instance/attribute)
  - I/O connection parameters (if using `io` scenario)

- [ ] **Network Tools**
  - `ping` for basic connectivity
  - `tcpdump` or Wireshark for packet capture
  - `telnet` or `nc` for port testing

## First-Time Setup

### 1. Configure Device Network

Configure your device's EtherNet/IP settings:
- Set static IP address (or note DHCP-assigned IP)
- Enable EtherNet/IP protocol
- Note the TCP port (usually 44818)
- Configure any required security settings

### 2. Test Basic Connectivity

```bash
# Test network connectivity
ping <device-ip>

# Test EtherNet/IP port
telnet <device-ip> 44818
# or
nc -zv <device-ip> 44818
```

### 3. Discover Device

```bash
# Discover CIP devices on network
cipdip discover --timeout 10s

# Should show your device with:
# - IP address
# - Product name
# - Vendor ID
```

### 4. Test Connection

```bash
# Test basic EtherNet/IP connectivity
cipdip test --ip <device-ip>

# Should show:
# ✓ Connection successful
#   Session registered successfully
```

### 5. Create Configuration

Create `cipdip_client.yaml` based on device documentation:

```yaml
adapter:
  name: "Your Device Name"
  port: 44818

read_targets:
  - name: "Target1"
    service: "get_attribute_single"
    class: 0x04        # From device documentation
    instance: 0x65     # From device documentation
    attribute: 0x03    # From device documentation
```

### 6. Run Test Scenario

```bash
# Start with baseline scenario
cipdip client --ip <device-ip> --scenario baseline \
  --duration-seconds 60 \
  --verbose

# Check for errors in output
# Review metrics if specified
```

## Common Device Configurations

### CLICK C2-03CPU

**Typical Configuration:**
```yaml
adapter:
  name: "CLICK C2-03CPU"
  port: 44818

read_targets:
  - name: "InputAssembly"
    service: "get_attribute_single"
    class: 0x04
    instance: 0x65
    attribute: 0x03
```

**Notes:**
- Default port: 44818
- Supports UCMM (unconnected messaging)
- Check device documentation for exact assembly instances

### Rockwell/Allen-Bradley

**Typical Configuration:**
```yaml
adapter:
  name: "Allen-Bradley Controller"
  port: 44818

read_targets:
  - name: "InputTag"
    service: "get_attribute_single"
    class: 0x04
    instance: 0x65
    attribute: 0x03
```

**Notes:**
- May require specific connection parameters
- Check controller documentation for tag paths
- May support both adapter and tag-based access

## Troubleshooting First Connection

### Issue: "Connection timeout"

**Check:**
1. Device is powered on
2. IP address is correct
3. Network cable connected
4. Firewall not blocking port 44818

**Test:**
```bash
ping <device-ip>
cipdip test --ip <device-ip>
```

### Issue: "RegisterSession failed"

**Check:**
1. EtherNet/IP is enabled on device
2. Device is not in error state
3. Device supports EtherNet/IP (not just Modbus)

**Test:**
```bash
cipdip discover --timeout 10s
# Device should appear in discovery results
```

### Issue: "ForwardOpen failed"

**Check:**
1. Connection parameters in config
2. Device supports connected messaging
3. Connection path (class/instance) is correct

**Solution:**
- Try UCMM-only scenarios first (baseline, mixed, stress)
- Verify connection parameters with device documentation

## Recommended Testing Sequence

1. **Discovery Test**
   ```bash
   cipdip discover --timeout 10s
   ```

2. **Connectivity Test**
   ```bash
   cipdip test --ip <device-ip>
   ```

3. **Baseline Scenario** (low frequency, read-only)
   ```bash
   cipdip client --ip <device-ip> --scenario baseline --duration-seconds 60
   ```

4. **Mixed Scenario** (medium frequency, reads/writes)
   ```bash
   cipdip client --ip <device-ip> --scenario mixed --duration-seconds 60
   ```

5. **I/O Scenario** (if device supports connected I/O)
   ```bash
   cipdip client --ip <device-ip> --scenario io --duration-seconds 60
   ```

6. **Stress Test** (high frequency)
   ```bash
   cipdip client --ip <device-ip> --scenario stress --duration-seconds 60
   ```

## Capturing Packets for Analysis

### Setup Packet Capture

```bash
# Terminal 1: Start capture
tcpdump -i eth0 -w test.pcap port 44818

# Terminal 2: Run scenario
cipdip client --ip <device-ip> --scenario baseline

# Terminal 1: Stop capture (Ctrl+C)
```

### Analyze Packets

1. Open `test.pcap` in Wireshark
2. Filter for EtherNet/IP: `enip`
3. Export packet bytes (right-click → Export Packet Bytes)
4. Analyze with CIPDIP:
   ```bash
   cipdip pcap --input packet.bin --validate
   
   # Or view hex dump:
   cipdip pcap --input packet.bin --hexdump
```

## Configuration Tips

### Finding Correct CIP Paths

1. **Device Documentation**
   - Check EtherNet/IP object model
   - Look for assembly instances
   - Note class/instance/attribute values

2. **Discovery Information**
   - `cipdip discover` shows device info
   - May indicate supported features

3. **Trial and Error**
   - Start with common paths (class 0x04, instance 0x65)
   - Use verbose logging to see responses
   - Check error codes for hints

### Connection Parameters

For I/O connections, check device documentation for:
- **RPI values**: Typical range 10-100ms
- **Connection sizes**: Usually 8, 16, 32, or 64 bytes
- **Transport class**: Usually 1 or 3 for cyclic I/O
- **Priority**: Usually "scheduled" for I/O

## Safety Considerations

⚠️ **Important:** This tool is for DPI testing, not production use.

- Do not use on production systems
- Test in isolated lab environment
- Verify device can handle request rates
- Monitor device status during testing
- Use appropriate intervals to avoid overwhelming device

## Next Steps After Hardware Installation

1. **Run Discovery**
   ```bash
   cipdip discover --timeout 10s
   ```

2. **Test Connectivity**
   ```bash
   cipdip test --ip <device-ip>
   ```

3. **Run Baseline Scenario**
   ```bash
   cipdip client --ip <device-ip> --scenario baseline --verbose
   ```

4. **Review Results**
   - Check for errors
   - Review metrics
   - Adjust configuration as needed

5. **Capture Packets** (optional)
   - Use tcpdump/Wireshark
   - Analyze with `cipdip pcap`
   - Document findings

## See Also

- `docs/TROUBLESHOOTING.md` - Detailed troubleshooting guide
- `docs/EXAMPLES.md` - Usage examples
- `docs/PCAP_USAGE.md` - Packet analysis guide
- `README.md` - Main documentation

