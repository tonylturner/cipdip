# Compliance Testing Guide

This document describes how CIPDIP tests EtherNet/IP and CIP compliance, how to run the tests, and how to interpret results. It replaces older, stale compliance notes.

## Scope

Compliance testing in CIPDIP targets the **strict_odva** protocol profile and focuses on:
- ENIP encapsulation structure (header, length, byte order)
- CIP request/response structure (service codes, status, path handling)
- EPATH encoding and parsing
- ForwardOpen/ForwardClose structure and state handling
- Reference packet comparisons using real-world captures

This is a DPI test harness, not a general CIP client. The goal is to ensure generated traffic is correct, deterministic, and representative of real devices, while clearly labeling any gaps.

## Sources of Truth

We prioritize the following sources for compliance validation:
1. ODVA specifications (where accessible)
2. Real-world captures from known devices (`pcaps/normal`, `pcaps/stress`)
3. Wireshark dissector behavior (when `tshark` is available)

Baseline captures in `baseline_captures/` are **regression artifacts** only. They are not considered compliance sources of truth.

## Test Types

### 1) Unit Tests (Byte-Level)
Located in `internal/cipclient/*_test.go` and `internal/cipclient/compliance_*_test.go`.

Coverage includes:
- ENIP header structure and length checks
- CIP service code encoding/decoding
- EPATH encoding and decoding (8-bit vs 16-bit segments)
- ForwardOpen/ForwardClose packet structure
- Response status and additional-status formatting

Run:
```bash
go test ./internal/cipclient
```

### 2) Reference Packet Validation
Reference packets are extracted from PCAPs and stored in `internal/reference/reference_packets_gen.go`.

Extraction:
```bash
cipdip extract-reference --real-world-dir pcaps --output internal/reference/reference_packets_gen.go
```

Validation:
```bash
go test ./internal/cipclient -run TestReferencePackets
```

If a reference packet is missing (e.g., `RegisterSession_Response`), treat that as **test coverage gap**, not protocol support failure.

### 3) PCAP Summary Checks
Summarize real-world captures to validate service coverage and path parsing:
```bash
cipdip pcap-summary --input pcaps/stress/ENIP.pcap
cipdip pcap-report --pcap-dir pcaps --output notes/pcap_summary_report.md
```

### 4) Optional Wireshark Validation
If `tshark` is installed, validate captured packets via Wireshark:
```bash
go test ./internal/validation
```

## Interpreting Results

1. **Strict ODVA framing** is required by default.
2. **Vendor-variant modes** are allowed only when explicitly enabled and when identity matches.
3. **Unknown services or missing references** must be labeled and tracked as test gaps.
4. **Baseline captures** must not be used to claim compliance.

## Known Limitations

- ODVA specifications may not be fully accessible. We document assumptions and update tests as evidence improves.
- Some vendor-specific services are context-dependent and need object class to label correctly.
- Reference coverage depends on available PCAPs; missing samples remain open items.

## Updating This Guide

When compliance tests change:
1. Update this document with new test commands or coverage.
2. Add a brief note to `docs/CHANGELOG.md`.
3. If new references are extracted, update `docs/REFERENCE_PACKETS.md`.

## See Also

- `docs/COMPLIANCE.md` - Compliance checklist and test coverage
- `docs/REFERENCE_PACKETS.md` - Current reference packet set
- `docs/PCAP_USAGE.md` - PCAP summary/report commands
