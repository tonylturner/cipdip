# Contributing to CIPDIP

Thank you for your interest in contributing to CIPDIP.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/cipdip.git`
3. Create a feature branch: `git checkout -b feature/my-change`
4. Make your changes
5. Run tests: `go test ./...`
6. Commit and push your branch
7. Open a pull request against `main`

## Development

### Prerequisites

- Go 1.26+
- Optional: tshark (Wireshark CLI) for TCP metrics
- Optional: libpcap / npcap for packet capture

### Building

```bash
go build ./cmd/cipdip
```

### Testing

```bash
# Full test suite
go test ./...

# Single package
go test ./internal/transport/...

# Specific test
go test -run TestName ./internal/path/...
```

### Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep functions focused and testable
- Add tests for new functionality
- Use table-driven tests where appropriate

## What to Contribute

- Bug fixes with regression tests
- New test scenarios (see `internal/scenario/`)
- Vendor profile support (see `internal/server/handlers/vendors/`)
- Documentation improvements
- PCAP analysis features

## Reporting Issues

Please open an issue before submitting large changes so we can discuss the approach.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
