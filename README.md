# CIPDIP

![Go](https://img.shields.io/badge/go-1.24.3-00ADD8?logo=go)
![License](https://img.shields.io/github/license/tturner/cipdip)
![PCAP Validated](https://img.shields.io/badge/pcap-validated-brightgreen)
![CIP](https://img.shields.io/badge/protocol-CIP%20%2F%20EtherNet%2FIP-blue)

Protocol-aware CIP/EtherNet-IP DPI test harness. CIPDIP generates strict,
ODVA-framed traffic by default, with optional vendor-variant profiles for
known identities. It supports client/scanner scenarios, server/emulator mode,
PCAP analysis, and validation workflows.

## Quick Start

```bash
go build ./cmd/cipdip

# Client scenario (strict ODVA by default)
cipdip client --ip 10.0.0.50 --scenario baseline

# Server emulator
cipdip server --personality adapter

# PCAP summary
cipdip pcap-summary --input pcaps/stress/ENIP.pcap
```

## Examples

```bash
# Quick-start config generation
cipdip client --ip 10.0.0.50 --scenario mixed --quick-start

# Single request (no YAML edits)
cipdip single --ip 10.0.0.50 --service 0x0E --class 0x01 --instance 0x01 --attribute 0x01

# PCAP replay (app mode)
cipdip pcap-replay --input pcaps/stress/ENIP.pcap --server-ip 10.0.0.10
```

## Documentation

- `docs/CONFIGURATION.md`
- `docs/EXAMPLES.md`
- `docs/COMPLIANCE_TESTING.md`
- `docs/PCAP_USAGE.md`
- `docs/REFERENCE_PACKETS.md`
- `docs/TROUBLESHOOTING.md`
- `docs/HARDWARE_SETUP.md`
- `docs/cip_reference.md`

## Notes

- Default behavior is strict ODVA framing; vendor-variant profiles are intended
  for matched identities only.
- If you need full CLI flags, use `cipdip help` or `cipdip <command> --help`.

## License

Apache License 2.0


