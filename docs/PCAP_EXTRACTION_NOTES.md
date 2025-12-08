# PCAP Extraction Notes

## Real-World PCAP Files

The real-world PCAP files in `.cursorrules/pcaps/` contain ENIP/CIP traffic:

- `ENIP.pcap` (45MB) - Contains SendUnitData packets (command 0x0070)
- `EthernetIP-CIP.pcap` (2MB) - Contains SendUnitData packets (command 0x0070)

### Current Status

✅ **Packets Confirmed**: Using `tshark`, we can confirm these PCAPs contain ENIP packets:
- Command: `0x0070` (SendUnitData)
- Port: TCP 44818
- Packets are present and valid

✅ **Extraction Fixed**: The extraction code now successfully extracts packets from real-world PCAPs!

**Fix Applied**: The extraction function was updated to check `ApplicationLayer` first (for reassembled TCP streams) before falling back to `tcp.Payload`. This allows extraction from both baseline captures and real-world PCAPs.

**Extracted Packets from Real-World PCAPs**:
- `SendUnitData_Request` (82 bytes) - From real-world captures
- `RegisterSession_Response` (28 bytes) - From real-world captures  
- `ListIdentity_Request` (24 bytes) - From real-world captures

### Verification

To verify packets exist:
```bash
# Check for ENIP packets
tshark -r .cursorrules/pcaps/EthernetIP-CIP.pcap -Y "tcp.port == 44818" -T fields -e enip.command

# Check TCP payloads
tshark -r .cursorrules/pcaps/EthernetIP-CIP.pcap -Y "tcp.port == 44818 && tcp.len > 0" -T fields -e tcp.payload | head -1
```

### Next Steps

1. **Investigate TCP Payload Extraction**: Check if `tcp.Payload` is populated in gopacket for these PCAPs
2. **Try ApplicationLayer**: Use `packet.ApplicationLayer().Payload()` instead of `tcp.Payload`
3. **Manual Extraction**: Extract ENIP data directly from raw packet bytes if needed
4. **TCP Reassembly**: Implement TCP stream reassembly if packets are fragmented

### Baseline Captures

✅ **Working**: Baseline captures in `baseline_captures/` extract successfully:
- All 11 baseline PCAP files extract packets correctly
- 6 different packet types extracted
- 30 total reference packets extracted

## Summary

- ✅ Real-world PCAPs contain valid ENIP packets (confirmed via tshark)
- ⏳ Extraction code needs enhancement to handle real-world PCAP format
- ✅ Baseline captures work perfectly
- ✅ All extracted reference packets are supported by client and server

