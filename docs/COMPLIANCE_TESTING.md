# ODVA Compliance Testing Methodology

This document explains how CIPDIP's compliance tests validate ODVA protocol requirements.

## Testing Philosophy

Our compliance tests aim to validate **ODVA specification compliance**, not just implementation correctness. However, there are important limitations:

### What We Test Against

1. **ODVA Specification Requirements** (where documented):
   - Command codes (0x0065, 0x006F, 0x0070, etc.)
   - Service codes (0x0E, 0x10, 0x54, 0x4E, etc.)
   - EPATH encoding rules (8-bit vs 16-bit segments)
   - Packet structure requirements (24-byte header, field order, byte order)
   - Protocol version requirements (RegisterSession version = 1)

2. **Known ODVA-Compliant Values**:
   - Values verified from public documentation
   - Values verified from reverse engineering compliant devices
   - Values verified from Wireshark dissector implementations

3. **Implementation Validation**:
   - Our code produces the expected structures
   - Byte order is correct (big-endian)
   - Length fields match actual data
   - Required fields are present

### Limitations

1. **ODVA Spec Access**:
   - ODVA specifications are member documents, not publicly available
   - We rely on:
     - Public documentation snippets
     - Reverse engineering compliant devices
     - Wireshark dissector implementations
     - Community knowledge

2. **Incomplete Coverage**:
   - We test what we implement, not the full ODVA specification
   - Some ODVA requirements may not be tested if not implemented
   - Edge cases may be missed without full spec access

3. **Assumptions**:
   - Some test values are based on common practice rather than explicit spec requirements
   - We assume our understanding of the spec is correct

## Test Categories

### 1. Structure Validation Tests

These tests verify packet structures match ODVA requirements:

- **ENIP Header**: 24-byte header with correct field order
- **Byte Order**: All multi-byte fields use big-endian (ODVA requirement)
- **Length Fields**: Length fields match actual data (ODVA requirement)
- **Required Fields**: All required fields are present

**ODVA Reference**: EtherNet/IP Encapsulation Protocol Specification

### 2. Command Code Validation

Tests verify command codes match ODVA standard values:

- RegisterSession: 0x0065
- UnregisterSession: 0x0066
- SendRRData: 0x006F
- SendUnitData: 0x0070
- ListIdentity: 0x0063

**ODVA Reference**: EtherNet/IP Encapsulation Protocol Specification

### 3. Service Code Validation

Tests verify CIP service codes match ODVA standard values:

- Get_Attribute_Single: 0x0E
- Set_Attribute_Single: 0x10
- Forward_Open: 0x54
- Forward_Close: 0x4E
- (and 12 more)

**ODVA Reference**: CIP Specification Volume 1, Table 3-5.1

### 4. EPATH Encoding Validation

Tests verify EPATH encoding follows ODVA rules:

- 8-bit segments: 0x20 (class), 0x24 (instance), 0x30 (attribute)
- 16-bit segments: 0x21 (class), 0x25 (instance)
- Big-endian encoding for 16-bit values
- Boundary conditions (0xFF max for 8-bit, 0x0100 min for 16-bit)

**ODVA Reference**: CIP Specification Volume 1, Section 3-5.2

### 5. Protocol-Specific Structure Tests

Tests verify specific protocol structures:

- **RegisterSession**: Protocol version = 1, Option flags = 0
- **SendRRData**: Interface Handle = 0 for UCMM
- **ForwardOpen**: Connection Manager path (class 0x06, instance 0x01)
- **ForwardClose**: Connection Manager path validation

**ODVA Reference**: Various ODVA specification documents

## Improving Compliance Testing

To make our tests more spec-compliant:

1. **Obtain ODVA Specifications** (if possible):
   - Join ODVA as a member
   - Access official specification documents
   - Update tests with exact spec requirements

2. **Hardware Validation**:
   - Test against real ODVA-compliant devices
   - Compare our packets with device responses
   - Validate against multiple vendors

3. **Packet Capture Analysis**:
   - Capture packets from compliant devices
   - Compare our packets with known-good packets
   - Use Wireshark dissector for validation

4. **Community Validation**:
   - Share test results with ODVA community
   - Get feedback from protocol experts
   - Contribute improvements back

## Current Test Status

- ✅ **Structure Tests**: Validating packet structures against known ODVA requirements
- ✅ **Code Validation**: Command and service codes match ODVA standards
- ✅ **Encoding Tests**: EPATH encoding follows ODVA rules
- ✅ **Audit Tests**: 15+ new audit tests validate implementation against ODVA spec requirements
- ⚠️ **Spec Coverage**: Limited by spec access - testing known requirements
- ⚠️ **Edge Cases**: May miss edge cases without full spec access

### Audit Test Results

The new `compliance_audit_test.go` file contains 15+ tests that audit our implementation against actual ODVA specification requirements:

1. **ENIP Header Structure**: Validates 24-byte header, field order, byte order, length field semantics
2. **RegisterSession**: Validates protocol version=1, option flags=0, session ID=0 in request
3. **SendRRData Structure**: Validates Interface Handle=0 for UCMM, timeout field, length calculation
4. **SendUnitData Structure**: Validates Connection ID encoding, length calculation
5. **EPATH Encoding**: Validates 8-bit/16-bit segment types, big-endian encoding, boundary conditions
6. **ForwardOpen Structure**: Validates service code, Connection Manager path, RPI encoding (microseconds), connection parameters
7. **ForwardClose Structure**: Validates service code, Connection Manager path, connection path with connection ID
8. **CIP Response Structure**: Validates service code echo, status byte, payload structure
9. **ListIdentity**: Validates command code, length=0, session ID=0
10. **Connection Parameters**: Validates bit encoding for connection type, priority, size
11. **RPI Encoding**: Validates RPI is in microseconds (not milliseconds)
12. **ForwardOpen Response**: Validates response structure, connection ID extraction
13. **Service Code Values**: Validates all service codes match ODVA spec exactly
14. **Command Code Values**: Validates all command codes match ODVA spec exactly
15. **EPATH Segment Types**: Validates segment type byte encoding per ODVA spec

These tests found and fixed issues in:
- Path size calculation (was incorrectly rounding up)
- Connection parameter encoding validation

## Recommendations

1. **For Production Use**:
   - Test against real hardware before production deployment
   - Validate with multiple ODVA-compliant devices
   - Use packet capture analysis to verify compliance

2. **For Development**:
   - Continue adding tests based on discovered requirements
   - Document assumptions and their sources
   - Update tests when new spec information becomes available

3. **For Compliance**:
   - Consider ODVA membership for spec access
   - Participate in ODVA compliance programs
   - Get third-party validation if required

## See Also

- `docs/COMPLIANCE.md` - Compliance checklist and test results
- `internal/cipclient/compliance_test.go` - Compliance test implementation
- `internal/pcap/analyzer.go` - Packet capture analysis for validation

