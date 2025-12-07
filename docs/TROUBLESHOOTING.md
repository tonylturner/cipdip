# Troubleshooting Guide

This guide helps diagnose and resolve common issues when using CIPDIP with hardware devices.

## Connection Issues

### "Connection timeout" or "transport connect failed"

**Symptoms:**
```
error: transport connect to 10.0.0.50:44818: connection refused
```

**Possible Causes:**
1. Device is not powered on
2. Device IP address is incorrect
3. Network connectivity issue
4. Firewall blocking port 44818
5. Device is not configured for EtherNet/IP

**Solutions:**
```bash
# 1. Test basic connectivity
ping 10.0.0.50

# 2. Test EtherNet/IP connectivity
cipdip test --ip 10.0.0.50

# 3. Discover devices on network
cipdip discover --timeout 5s

# 4. Check if port is open
telnet 10.0.0.50 44818
# or
nc -zv 10.0.0.50 44818

# 5. Verify device configuration
# - Check device IP settings
# - Verify EtherNet/IP is enabled
# - Check device documentation for correct port
```

### "RegisterSession failed"

**Symptoms:**
```
error: RegisterSession failed with status: 0x00000001
```

**Possible Causes:**
1. Device does not support EtherNet/IP
2. Device is in a different mode
3. Protocol version mismatch
4. Device is busy or in error state

**Solutions:**
- Verify device supports EtherNet/IP (not just Modbus TCP, etc.)
- Check device status/error indicators
- Review device documentation for EtherNet/IP requirements
- Try with verbose logging: `cipdip client --ip 10.0.0.50 --scenario baseline --verbose`

### "ForwardOpen failed"

**Symptoms:**
```
error: forward open failed with status 0x01
```

**Possible Causes:**
1. Invalid connection parameters (RPI, size, etc.)
2. Device doesn't support connected messaging
3. Connection path is incorrect
4. Device already has maximum connections

**Solutions:**
- Check connection parameters in config file
- Verify device supports ForwardOpen (some devices only support UCMM)
- Review device documentation for connection requirements
- Try reducing RPI values
- Check connection path (class/instance) matches device configuration

## Configuration Issues

### "at least one of read_targets, write_targets, or custom_targets must be populated"

**Solution:**
- Add at least one target to your `cipdip_client.yaml` config file
- See `configs/cipdip_client.yaml.example` for examples

### "io_connections[0]: transport must be 'udp' or 'tcp'"

**Solution:**
- Set `transport: "udp"` or `transport: "tcp"` in your I/O connection config
- Default is "udp" if not specified

### "invalid service type"

**Solution:**
- Use one of: `get_attribute_single`, `set_attribute_single`, or `custom`
- For custom services, also specify `service_code`

## Scenario-Specific Issues

### "io scenario cannot run" - No I/O connections configured

**Solution:**
- Add `io_connections` section to your `cipdip_client.yaml`
- See example config for I/O connection format

### High error rate in metrics

**Possible Causes:**
1. Device cannot handle request rate
2. Network latency issues
3. Invalid CIP paths in config
4. Device resource constraints

**Solutions:**
- Increase `--interval-ms` to slow down requests
- Check network latency: `ping 10.0.0.50`
- Verify CIP paths (class/instance/attribute) in config
- Check device documentation for supported paths
- Use `--verbose` to see detailed error messages

## Network Issues

### UDP 2222 I/O connections not working

**Symptoms:**
- ForwardOpen succeeds but SendIOData/ReceiveIOData fails

**Possible Causes:**
1. Firewall blocking UDP 2222
2. Device doesn't support UDP I/O
3. Network routing issues

**Solutions:**
```bash
# Check UDP connectivity
nc -uv 10.0.0.50 2222

# Try TCP transport instead
# In config: transport: "tcp"

# Check firewall rules
# Allow UDP port 2222
```

### Discovery not finding devices

**Symptoms:**
```
cipdip discover
# No devices found
```

**Possible Causes:**
1. Devices not on same network segment
2. Broadcast not working (routing/VLAN issues)
3. Devices don't respond to ListIdentity
4. Firewall blocking UDP 44818

**Solutions:**
```bash
# Try longer timeout
cipdip discover --timeout 10s

# Try specific interface
cipdip discover --interface eth0 --timeout 5s

# Check network configuration
# - Verify devices are on same subnet
# - Check VLAN/routing configuration
# - Verify broadcast is enabled
```

## Debugging Tips

### Enable Verbose Logging

```bash
cipdip client --ip 10.0.0.50 --scenario baseline --verbose --log-file debug.log
```

### Enable Debug Logging

```bash
cipdip client --ip 10.0.0.50 --scenario baseline --debug --log-file debug.log
```

### Capture Packets

```bash
# Terminal 1: Capture packets
tcpdump -i eth0 -w capture.pcap port 44818

# Terminal 2: Run scenario
cipdip client --ip 10.0.0.50 --scenario baseline

# Analyze captured packets
# Export from Wireshark, then:
cipdip pcap --input packet.bin --validate

# Or view hex dump:
cipdip pcap --input packet.bin --hexdump
```

### Test Connectivity First

```bash
# Quick connectivity test
cipdip test --ip 10.0.0.50

# If successful, then run scenarios
cipdip client --ip 10.0.0.50 --scenario baseline
```

## Common Error Messages

### "not connected"
- **Cause:** Trying to use client before calling Connect()
- **Solution:** This is an internal error, should not occur in normal use

### "already connected"
- **Cause:** Trying to connect when already connected
- **Solution:** Call Disconnect() first, or create a new client

### "invalid connection"
- **Cause:** I/O connection object is nil or invalid
- **Solution:** Check ForwardOpen succeeded before using connection

### "data size exceeds O->T size"
- **Cause:** Trying to send more data than connection allows
- **Solution:** Check `o_to_t_size_bytes` in config matches data size

## Getting Help

1. **Check Logs:** Use `--verbose` or `--debug` with `--log-file` to capture detailed logs
2. **Test Connectivity:** Use `cipdip test` to verify basic connectivity
3. **Discover Devices:** Use `cipdip discover` to find devices on network
4. **Validate Config:** Check config file syntax and required fields
5. **Capture Packets:** Use tcpdump/Wireshark to analyze network traffic
6. **Review Documentation:** Check device-specific documentation for EtherNet/IP requirements

## Device-Specific Notes

### CLICK C2-03CPU

- Default port: 44818
- Supports UCMM (unconnected messaging)
- May require specific CIP paths - check device documentation
- I/O connections may require specific assembly instances

### Other Devices

- Check device documentation for:
  - Supported CIP services
  - Required connection parameters
  - Valid class/instance/attribute paths
  - Transport preferences (TCP vs UDP)

## See Also

- `README.md` - Main documentation
- `docs/EXAMPLES.md` - Usage examples
- `docs/PCAP_USAGE.md` - Packet analysis guide
- `configs/cipdip_client.yaml.example` - Example configuration

