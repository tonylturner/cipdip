# Vendor Implementation Research & Emulation

This document tracks research on vendor-specific EtherNet/IP and CIP implementations, focusing on deviations from the ODVA standard that could affect DPI testing.

## Purpose

Different vendors may implement EtherNet/IP/CIP with slight variations or non-standard behaviors. Understanding and optionally emulating these behaviors is valuable for:
- Comprehensive DPI testing coverage
- Testing firewall behavior with vendor-specific quirks
- Understanding real-world protocol variations

## Research Areas

### 1. Rockwell Automation (Allen-Bradley)

**Known Characteristics:**
- Extensive use of Class 1 I/O connections
- Specific ForwardOpen parameter preferences
- Custom service codes for some operations
- Vendor-specific object models (e.g., Logix controllers)

**Research Questions:**
- [ ] ForwardOpen parameter defaults and ranges
- [ ] Connection timeout handling
- [ ] EPATH encoding preferences (8-bit vs 16-bit)
- [ ] ListIdentity response format variations
- [ ] Custom service code usage
- [ ] Session management quirks

**References:**
- Rockwell Automation EtherNet/IP documentation
- Allen-Bradley controller documentation
- Wireshark packet captures (if available)

### 2. Schneider Electric (Modicon)

**Known Characteristics:**
- Modicon-specific object models
- Potential differences in connection management
- Custom attribute handling

**Research Questions:**
- [ ] Connection parameter handling
- [ ] Service code implementation
- [ ] EPATH encoding preferences
- [ ] ListIdentity variations

**References:**
- Schneider Electric Modicon documentation
- Modicon EtherNet/IP guides

### 3. Siemens

**Known Characteristics:**
- PROFINET integration with EtherNet/IP
- Potential protocol bridging behaviors
- Custom object models

**Research Questions:**
- [ ] EtherNet/IP implementation specifics
- [ ] Integration with PROFINET
- [ ] Connection management differences

**References:**
- Siemens EtherNet/IP documentation
- PROFINET/EtherNet/IP integration guides

### 4. Other Vendors

**To Research:**
- Omron
- Mitsubishi
- ABB
- Other major CIP/EtherNet/IP vendors

## Implementation Documentation Structure

Vendor-specific behaviors will be documented in markdown files and optionally in YAML config files for emulation:

**Documentation Files:**
- `docs/vendors/rockwell.md` - Rockwell-specific behaviors
- `docs/vendors/schneider.md` - Schneider-specific behaviors
- `docs/vendors/siemens.md` - Siemens-specific behaviors
- etc.

**Optional Config Files (for emulation):**
- `configs/vendors/rockwell.yaml` - Rockwell emulation settings
- `configs/vendors/schneider.yaml` - Schneider emulation settings
- etc.

No database required - just documentation and optional config files.

## Emulation Modes

Once research is complete, we can add optional emulation modes to the server:

- `--vendor rockwell`: Emulate Rockwell-specific behaviors
- `--vendor schneider`: Emulate Schneider-specific behaviors
- `--vendor siemens`: Emulate Siemens-specific behaviors

These modes would adjust:
- ForwardOpen/ForwardClose response formats
- EPATH encoding preferences
- Service code handling
- Connection parameter defaults
- ListIdentity response format

## Research Methodology

1. **Documentation Review**
   - Vendor technical documentation
   - Application notes
   - Protocol implementation guides

2. **Packet Capture Analysis**
   - Capture real vendor device traffic
   - Compare with ODVA standard
   - Identify deviations

3. **Community Resources**
   - ODVA forums
   - Industrial automation communities
   - GitHub projects using EtherNet/IP

4. **Testing**
   - Test against real hardware (when available)
   - Validate emulation accuracy
   - Document findings

## Status

**Current Status:** Research Phase  
**Last Updated:** 2025-01-27

### Completed Research
- None yet (starting Phase 13)

### In Progress
- Initial research framework
- Documentation structure

### Planned
- Vendor-specific behavior documentation
- Emulation mode implementation
- Test scenarios for vendor emulation

## Notes

- This is a research and enhancement phase, not a core requirement
- Emulation modes are optional and can be added incrementally
- Focus on behaviors that affect DPI testing scenarios
- Document all findings for future reference

