# CIPDIP Agent Notes

## Purpose
Protocol-aware CIP/EtherNet/IP DPI test harness focused on ODVA-correct traffic and vendor-variant edge cases (not a general CIP client).

## Protocol posture
- Default: strict ODVA-compliant ENIP/CIP framing and behavior.
- Optional modes: vendor-variant profiles for real-world deviations (only when identity matches).
- Key focus: DPI falsification, Forward Open/I-O state handling, latency/jitter/misclassification metrics.

## PCAP context
- Reference capture: `pcaps/ENIP.pcap` identifies Rockwell Vendor ID 0x0001, Product `1756-ENBT/A`.
- Only apply `rockwell_enbt` or vendor-specific profiles when identity matches the capture.

## Docs policy
- `docs/` is user-facing only.
- Internal/audit/status/plan content belongs in `notes/`.
- Keep `README.md` and `tasks.md` in repo root.

## Local environment
- Current environment is Windows + PowerShell; prefer `rg` for search.
- Tooling must remain cross-platform (macOS/Linux/Windows). Add OS detection if required.
