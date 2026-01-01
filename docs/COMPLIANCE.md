# ODVA Protocol Compliance

This document describes the protocol compliance testing and validation for CIPDIP.

## Overview

CIPDIP implements a custom EtherNet/IP and CIP client following ODVA specifications. This document tracks compliance testing and validation efforts.

**Important**: Validate any compliance assumptions against current ODVA specs and device captures before relying on them for test conclusions.

## Compliance Test Results

### Packet Structure Validation

Packet structure tests cover:

- **ENIP Encapsulation Headers**: 24-byte header structure with correct field order and little-endian encoding
  - Length field consistency validation
  - Byte order (little-endian) verification for all fields
  - Session ID range validation (full uint32 range)
  - Sender context preservation
- **RegisterSession**: Protocol version and option flags correctly formatted
  - Protocol version = 1 (per ODVA spec)
  - Option flags = 0 (per ODVA spec)
  - Session ID = 0 in request
- **UnregisterSession**: Session ID correctly included, no data field
- **SendRRData**: Interface Handle (0 for UCMM), Timeout, and CIP data structure
  - Interface Handle = 0 validation (required for UCMM)
  - Length field matches data
  - Session ID preservation
- **SendUnitData**: Connection ID and CIP data structure
  - Connection ID little-endian encoding
  - Length field consistency
- **ListIdentity**: No data field, no session required
- **ForwardOpen**: Connection parameters, RPIs, priorities, and connection path
  - Service code 0x54 validation
  - Connection Manager path (class 0x06, instance 0x01)
  - Connection path encoding validation
- **ForwardClose**: Connection path structure
  - Service code 0x4E validation
  - Connection Manager path validation

### EPATH Encoding Validation

- **8-bit segments**: Class, Instance, Attribute segments correctly encoded
  - Segment type 0x20 (8-bit class), 0x24 (8-bit instance), 0x30 (8-bit attribute)
  - Boundary testing (0xFF max for 8-bit)
- **16-bit segments**: Large class/instance IDs encoded with proper segment type
  - Segment type 0x21 (16-bit class), 0x25 (16-bit instance)
  - Boundary testing (0x0100 min for 16-bit)
  - Little-endian encoding of 16-bit values
- **Connection paths**: ForwardOpen connection paths correctly formatted
- **Path length validation**: EPATH length matches expected structure

### CIP Service Code Validation

- **Service codes**: Service codes are validated against ODVA specification values (Volume 1, Table 3-5.1)
  - Get_Attribute_All: 0x01
  - Set_Attribute_All: 0x02
  - Get_Attribute_List: 0x03
  - Set_Attribute_List: 0x04
  - Reset: 0x05
  - Start: 0x06
  - Stop: 0x07
  - Create: 0x08
  - Delete: 0x09
  - Multiple_Service: 0x0A
  - Apply_Attributes: 0x0D
  - Get_Attribute_Single: 0x0E
  - Set_Attribute_Single: 0x10
  - Find_Next_Object_Instance: 0x11
  - Forward_Open: 0x54
  - Forward_Close: 0x4E

### Response Structure Validation

- **Success responses**: Status 0x00 parsing and payload handling
- **Error responses**: Error status codes and extended status handling
- **ForwardOpen responses**: Connection ID extraction
- **ForwardClose responses**: Status handling

## Test Coverage

### Unit Tests

- `compliance_test.go`: ODVA protocol compliance tests
  - ENIP header structure and byte order validation
  - Length field consistency checks
  - Command and status code validation
  - RegisterSession/UnregisterSession structure
  - SendRRData/SendUnitData structure
  - EPATH encoding (8-bit and 16-bit segments, boundary conditions)
  - CIP service code validation (all implemented services)
  - ForwardOpen/ForwardClose structure
  - ListIdentity structure
  - Error handling for invalid packets
  - Session ID range validation
  - Sender context preservation
  - CIP request encoding validation
- `compliance_audit_test.go`: ODVA compliance audit tests (byte-level structure and encoding)
- `response_test.go`: Response structure validation
- `cip_test.go`: CIP encoding/decoding
- `enip_test.go`: ENIP encapsulation

### Integration Tests

Integration tests are available but disabled by default. To run:

```bash
# Enable integration tests (requires running server)
go test -tags=integration ./internal/cipclient/...
```

Integration tests validate:
- Client-server communication
- ForwardOpen/ForwardClose against server
- I/O data exchange

## Protocol Compliance Coverage (strict_odva)

### ENIP Encapsulation
- 24-byte header structure (strictly enforced in strict_odva)
- Little-endian byte order (all multi-byte fields validated)
- Correct field order (Command, Length, SessionID, Status, SenderContext, Options)
- Data field follows header
- Length field consistency (matches actual data length)
- Session ID range validation (full uint32 range)
- Sender context preservation (8 bytes)
- Error handling for invalid/short packets

### RegisterSession/UnregisterSession
- RegisterSession: Protocol version (1) and option flags (0)
- RegisterSession: Length field = 4 bytes
- RegisterSession: Session ID = 0 in request
- UnregisterSession: Session ID in request
- UnregisterSession: Length field = 0 (no data)

### SendRRData (UCMM)
- Interface Handle = 0 (for UCMM, strictly validated)
- Timeout field present (2 bytes)
- CIP data follows timeout
- Length field matches data (6 + CIP data length)
- Session ID preservation

### SendUnitData (Connected Messaging)
- Connection ID (4 bytes, little-endian, validated)
- CIP data follows connection ID
- Length field matches data (4 + CIP data length)
- Session ID preservation

### EPATH Encoding
- 8-bit segment format (0x20, 0x24, 0x30)
- 16-bit segment format (0x21, 0x25, 0x31)
- Segment data in correct byte order (little-endian for 16-bit)
- Boundary conditions (0xFF max for 8-bit, 0x0100 min for 16-bit)
- Path length validation

### ForwardOpen
- Service code 0x54
- Connection Manager path (class 0x06, instance 0x01)
- Priority and tick time
- Connection timeout
- O->T and T->O RPIs (in microseconds)
- Connection parameters
- Transport class and trigger
- Connection path size and path

### ForwardClose
- Service code 0x4E
- Connection Manager path
- Connection path with connection ID

### CIP Service Codes
- Implemented service codes validated against ODVA spec
- Get_Attribute_Single: 0x0E
- Set_Attribute_Single: 0x10
- Forward_Open: 0x54
- Forward_Close: 0x4E
- Additional services: Get/Set Attribute All/List, Reset, Start, Stop, Create, Delete, etc.

### Status Codes
- Success: 0x00
- General error: 0x01
- Error status handling

## Known Limitations

1. **UDP 2222 Transport**: Supported for I/O connections. The `io` scenario defaults to UDP 2222 and can be set via `transport: "udp"` or `transport: "tcp"` in config.
2. **Extended Status Parsing**: Basic extended status support; full parsing may need enhancement.
3. **Connection Path Hex Parsing**: Implemented but may need additional validation.

## Validation Methodology

1. **Unit Tests**: Comprehensive byte-level validation of packet structure and encoding
   - 20+ compliance test cases covering all protocol layers
   - Edge case and boundary condition testing
   - Error handling validation
   - Byte order verification
   - Field range validation
2. **ODVA Specification Audit Tests**: 15+ tests that validate implementation against known ODVA specification requirements
   - Tests are written based on ODVA spec requirements, not just our implementation
   - Validates byte-level structure, field encoding, and protocol semantics
   - Intended to catch issues such as path size calculation errors
   - See `internal/cipclient/compliance_audit_test.go` for full audit test suite
3. **Integration Tests**: Test against server mode emulator
4. **Packet Capture**: Compare generated packets with Wireshark dissector (via `cipdip pcap` or `cipdip pcap-summary`)
5. **Hardware Testing**: Test against real CIP devices (when available)

**Important**: See `docs/COMPLIANCE_TESTING.md` for details on our testing methodology and limitations.

## References

- ODVA EtherNet/IP Encapsulation Protocol Specification
- ODVA Common Industrial Protocol (CIP) Specification
- ODVA CIP Connection Management Specification

## Future Work

- [ ] Packet capture analysis framework
- [ ] Wireshark dissector validation
- [ ] Hardware validation test suite
- [ ] Extended status code parsing
- [ ] Additional CIP service support

