# Vendor Implementation Documentation

This directory contains **vendor-specific EtherNet/IP (ENIP) + CIP implementation notes** used to:
- guide protocol stack implementation (client + emulator/server),
- design **repeatable DPI test scenarios**, and
- document interoperability behaviors observed in real industrial environments.

These documents consolidate **public vendor documentation**, observed on‑wire behavior, and practical engineering guidance. They are not reproductions of ODVA specifications.

## How to use these notes

- **Protocol implementation**
  - Treat each vendor file as a checklist of required services, EPATH forms, and connection behaviors.
- **Emulation**
  - Use vendor‑specific behaviors to shape emulator personalities (Identity Object, supported objects, error handling).
- **DPI evaluation**
  - Use the DPI sections to design tests that expose classification, state‑tracking, and performance weaknesses.

## Vendor coverage

Current coverage includes:
- Rockwell Automation (Allen‑Bradley)
- Schneider Electric (Modicon)
- Siemens (MultiFieldbus EtherNet/IP)
- Omron
- Keyence

## Common structure

Each vendor document includes:
- Vendor fingerprinting (Identity Object, discovery hints)
- Common device roles and families
- Service and EPATH usage
- Connection and I/O behavior
- Quirks and deviations
- DPI testing implications
- Public references

## Contribution guidance

When extending this research:
- Prefer primary vendor manuals and ODVA public publications.
- Capture *why* a behavior matters for interoperability or DPI.
- For packet‑level claims, record capture context and filters.

_Last updated: 2026-01-01_
