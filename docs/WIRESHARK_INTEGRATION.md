# Wireshark Integration for Packet Validation

## What is Wireshark Integration?

**Wireshark integration** means using Wireshark's protocol dissector (via the `tshark` command-line tool) to validate that the packets CIPDIP generates are correctly formatted according to the ENIP/CIP protocol specifications.

## Why is This Valuable?

### 1. **Industry-Standard Validation**
- Wireshark has a well-tested, widely-used dissector for EtherNet/IP and CIP
- It's maintained by the Wireshark community and updated with protocol changes
- If Wireshark can parse our packets correctly, it's a strong indicator of ODVA compliance

### 2. **Catches Issues Our Validation Might Miss**
- Our current validation (`internal/cipclient/validation.go`) checks basic structure
- Wireshark's dissector has deeper protocol knowledge and can catch:
  - Incorrect field values
  - Invalid combinations of fields
  - Protocol-specific constraints we might not know about
  - Edge cases and subtle violations

### 3. **Real-World Compatibility**
- If Wireshark can parse our packets, real devices are more likely to accept them
- Wireshark is used by network engineers worldwide to debug CIP/ENIP traffic
- Passing Wireshark validation means our packets "look right" to industry-standard tools

## How Would It Work?

### Basic Flow

```
1. Generate packet using CIPDIP
   ↓
2. Write packet to temporary PCAP file
   ↓
3. Run tshark (Wireshark CLI) on the PCAP
   ↓
4. Check tshark output for:
   - Successful parsing (no errors)
   - Protocol field extraction
   - Any warnings or malformed packet indicators
   ↓
5. Report validation results
```

### Example Implementation

```go
// internal/validation/wireshark.go

package validation

import (
    "os/exec"
    "os"
    "fmt"
)

// ValidateWithWireshark validates a packet using Wireshark's dissector
func ValidateWithWireshark(packet []byte) error {
    // 1. Write packet to temp PCAP file
    tmpFile := "/tmp/cipdip_validate.pcap"
    // ... write packet to PCAP format ...
    
    // 2. Run tshark
    cmd := exec.Command("tshark", 
        "-r", tmpFile,           // Read from PCAP file
        "-T", "json",            // JSON output for parsing
        "-e", "enip.command",    // Extract ENIP command
        "-e", "enip.status",     // Extract ENIP status
        "-e", "cip.service",     // Extract CIP service
    )
    
    output, err := cmd.Output()
    if err != nil {
        return fmt.Errorf("tshark validation failed: %w", err)
    }
    
    // 3. Parse tshark output
    // Check for:
    // - Successful parsing (no "Malformed" warnings)
    // - Correct field extraction
    // - Protocol-specific validation
    
    // 4. Clean up
    os.Remove(tmpFile)
    
    return nil
}
```

### What Gets Validated?

1. **ENIP Encapsulation**
   - Command codes are recognized
   - Length fields are correct
   - Status fields are valid
   - Session IDs are properly formatted

2. **CIP Services**
   - Service codes are recognized
   - EPATH encoding is valid
   - Request/response structures are correct
   - Attribute IDs and data types are valid

3. **Protocol-Specific Rules**
   - ForwardOpen connection parameters
   - SendUnitData structure
   - RegisterSession protocol version

## Example: What Wireshark Would Catch

### Good Packet (Passes Validation)
```
Packet: RegisterSession request
tshark output:
  enip.command: 0x0065
  enip.length: 4
  enip.data: Protocol Version: 1, Option Flags: 0
  Status: ✅ Parsed successfully
```

### Bad Packet (Fails Validation)
```
Packet: RegisterSession with wrong protocol version
tshark output:
  enip.command: 0x0065
  Warning: "Invalid protocol version (expected 1, got 2)"
  Status: ⚠️ Malformed packet
```

## Integration Points

### 1. **In Tests**
```go
func TestRegisterSessionWiresharkValidation(t *testing.T) {
    packet := BuildRegisterSession(senderContext)
    err := validation.ValidateWithWireshark(packet)
    if err != nil {
        t.Errorf("Wireshark validation failed: %v", err)
    }
}
```

### 2. **In CI Pipeline**
```yaml
# .github/workflows/compliance.yml
- name: Validate packets with Wireshark
  run: |
    go test ./internal/cipclient/... -run TestWireshark
    # Fail CI if any packets don't pass Wireshark validation
```

### 3. **Optional Runtime Validation**
```go
// In client.go, before sending packet
if flags.validateWireshark {
    if err := validation.ValidateWithWireshark(packet); err != nil {
        logger.Warn("Packet failed Wireshark validation: %v", err)
        // Continue anyway, but log warning
    }
}
```

## Benefits

1. **Higher Confidence in ODVA Compliance**
   - Wireshark is the de-facto standard for protocol analysis
   - Passing Wireshark validation = strong compliance indicator

2. **Catch Bugs Early**
   - Detect protocol violations before they reach real devices
   - Find issues our own validation might miss

3. **Documentation**
   - Wireshark validation serves as proof of compliance
   - Can be included in test reports and documentation

4. **Continuous Validation**
   - Can run in CI on every commit
   - Prevents regressions in packet generation

## Limitations

1. **Requires Wireshark/tshark installed**
   - Need to check if tshark is available
   - May not be available in all CI environments

2. **PCAP File Format**
   - Need to write packets in PCAP format
   - Requires understanding PCAP structure

3. **Not a Replacement for Our Validation**
   - Should complement, not replace, our existing validation
   - Our validation is faster and doesn't require external tools

## Implementation Priority

**Priority:** High  
**Effort:** Medium (2-3 hours)  
**Impact:** Very High compliance confidence

This is one of the highest-impact improvements for ODVA compliance confidence because it leverages an industry-standard tool that's widely trusted in the industrial automation community.

## See Also

- `docs/AUDIT_RECOMMENDATIONS.md` - Detailed recommendations
- `docs/NEXT_STEPS.md` - Implementation roadmap
- `internal/cipclient/validation.go` - Current validation implementation

