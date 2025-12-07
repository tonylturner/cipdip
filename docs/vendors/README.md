# Vendor Implementation Documentation

This directory contains documentation about vendor-specific EtherNet/IP and CIP implementations.

## Structure

Each vendor has its own markdown file documenting:
- Known behaviors and deviations from ODVA standard
- Packet structure variations
- Service code usage
- EPATH encoding preferences
- Connection management quirks
- Any other vendor-specific characteristics

## Files

- `rockwell.md` - Rockwell Automation (Allen-Bradley) implementations
- `schneider.md` - Schneider Electric (Modicon) implementations
- `siemens.md` - Siemens implementations
- `other.md` - Other vendor implementations

## Purpose

This documentation supports:
1. **Research**: Understanding vendor-specific behaviors
2. **Emulation**: Optional server emulation modes (if implemented)
3. **Testing**: Identifying behaviors that might affect DPI testing
4. **Reference**: Quick lookup of vendor-specific quirks

## Contributing

When researching vendors:
1. Document findings in the appropriate vendor file
2. Include packet capture examples (hex dumps)
3. Note any deviations from ODVA standard
4. Reference source documentation

## Status

**Current Status:** Research phase - documentation structure ready  
**Last Updated:** 2025-01-27

