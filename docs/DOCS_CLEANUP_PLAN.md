# Docs Cleanup Plan

## Goals
- Reduce stale or duplicate docs.
- Keep compliance-critical references current.
- Preserve vendor research templates until real captures exist.

## Inventory (proposed actions)
### Keep and update
- `docs/CONFIGURATION.md` - authoritative config reference; update with protocol mode section.
- `docs/COMPLIANCE.md` - compliance overview; align with strict ODVA vs vendor-variant modes.
- `docs/ODVA_COMPLIANCE_REALITY.md` - keep; update assumptions after strict-mode changes.
- `docs/COMPLIANCE_TESTING.md` - keep; update to reference strict-mode tests.
- `docs/PCAP_USAGE.md` - keep; note CPF framing changes.
- `docs/REFERENCE_PACKETS.md` - keep; update expected packet formats.
- `docs/REFERENCE_PACKET_SUPPORT.md` - keep; update scope and strict-mode status.
- `docs/WIRESHARK_INTEGRATION.md` - keep; update for strict-mode framing.
- `docs/TROUBLESHOOTING.md` - keep; verify Windows notes.
- `docs/HARDWARE_SETUP.md` - keep; verify Windows notes.

### Merge or retire (stale/overlapping)
- `docs/SUMMARY.md` -> merge key bits into `README.md`, then retire.
- `docs/PROJECT_SUMMARY.md` -> retire (overlaps with README + STATUS).
- `docs/NEXT_STEPS.md` -> retire (replaced by `tasks.md`).
- `docs/AUDIT_SUMMARY.md` -> retire (historic; summary now in `tasks.md`).
- `docs/AUDIT_RECOMMENDATIONS.md` -> retire or archive (superseded by DPI/ODVA roadmap).

### Keep (templates, mark pending)
- `docs/VENDOR_RESEARCH.md` - keep; mark “pending captures”.
- `docs/vendors/README.md` - keep; link from `docs/VENDOR_RESEARCH.md`.
- `docs/vendors/rockwell.md` - keep; mark “pending captures”.
- `docs/vendors/schneider.md` - keep; mark “pending captures”.
- `docs/vendors/siemens.md` - keep; mark “pending captures”.

## Approval workflow
1) Confirm which docs to merge/retire.
2) I’ll submit a PR-style change list with exact removals and edits.
3) If approved, I’ll perform deletes and update cross-links.
