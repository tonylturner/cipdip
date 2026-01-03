# TUI Assumptions and Open Questions

This file captures gaps that must be reconciled against current CLI flags,
config files, and existing command behavior before full TUI integration.

## Assumptions
- Workspace is a new, TUI-only structure; no current CLI command expects it.
- `cipdip ui` should not execute any command unless a wizard explicitly runs it.
- `--no-run` is intended to allow layout discovery and validation only.

## Open Questions
- Which CLI commands should be mapped to wizard kinds in Phase 1 (pcap-replay,
  baseline, server start)?
- Which flags are safe defaults to hide behind "advanced" vs required fields?
- How should `summary.json` be produced for commands that do not emit structured output?
- Which existing YAML config formats should be wrapped as `spec/advanced`?
- Should `workspace.yaml` store a default target IP/port and interface name?
- How should TUI handle external tools (tshark, tcpreplay) availability checks?
