# CIPDIP Agent Notes

## Purpose
Protocol-aware CIP/EtherNet/IP DPI test harness focused on ODVA-correct traffic and vendor-variant edge cases (not a general CIP client).

## Protocol posture
- Default: strict ODVA-compliant ENIP/CIP framing and behavior.
- Optional modes: vendor-variant profiles for real-world deviations (only when identity matches).
- Key focus: DPI falsification, Forward Open/I-O state handling, latency/jitter/misclassification metrics.

## PCAP context
- Reference capture: `pcaps/stress/ENIP.pcap` identifies Rockwell Vendor ID 0x0001, Product `1756-ENBT/A`.
- Only apply `rockwell_enbt` or vendor-specific profiles when identity matches the capture.

## Architecture context (refactor complete)
- Protocol layers: `internal/enip`, `internal/cip/codec`, `internal/cip/protocol`, `internal/cip/spec`, `internal/cip/client`.
- Server: `internal/server/core` + `internal/server/handlers` with vendor logic under `handlers/vendor/*`.
- PCAP tooling: `internal/pcap`; reporting models in `internal/report`.
- Reference packets: `internal/reference` with generated `reference_packets_gen.go`.
- CLI/TUI orchestration: `internal/app`; UI should avoid protocol parsing directly.

## Current capabilities (context)
- Strict ODVA framing by default; vendor-variant profiles supported when identity matches.
- Client + server emulator with UCMM + connected I/O, Forward Open state tracking, and CPF enforcement.
- Scenario suite (baseline/mixed/stress/churn/io + edge/vendor/firewall packs) with metrics and CLI progress bars.
- PCAP pipeline: summary/report/coverage/classify/dump/replay/rewrite, plus reference extraction.
- TUI workspace model, wizards, catalog explorer, and run artifacts (resolved.yaml/summary.json).
- Reports directory (`reports/`) and workspace layout under `workspaces/`.
- Reference packet library extracted from pcaps; RegisterSession_Response still missing.
- Known PCAP identity: Rockwell 0x0001 / 1756-ENBT/A (use rockwell_enbt only when identity matches).

## Docs policy
- `docs/` is user-facing only.
- Internal/audit/status/plan content belongs in `notes/`.
- Keep `README.md` and `tasks.md` in repo root.

## Workspace + outputs
- Default TUI workspace root: `workspaces/` (e.g., `workspaces/workspace`).
- Reports outside workspaces go in `reports/` (e.g., emit/validate outputs).
- PCAP reports live under `notes/pcap/` (summary, coverage, vendor rollups).

## Local environment
- Current environment is Windows + PowerShell; prefer `rg` for search.
- Tooling must remain cross-platform (macOS/Linux/Windows). Add OS detection if required.
