# CIPDIP DPI Compliance + Vendor-Variant Plan

## Goals
- Enforce strict ODVA-compliant ENIP/CIP encoding/behavior by default.
- Add optional vendor-variant modes that mirror common deviations seen in field devices.
- Expand DPI falsification coverage (edge cases, Forward Open state, jitter/latency metrics).
- Audit and trim docs that are stale or superseded.
- Confirm Windows development/runtime considerations.

## Plan (tracked steps)
- [x] 1) Baseline compliance audit: confirm current encoding vs ODVA (endianness, EPATH path size, CPF items, SendRRData/SendUnitData format, ForwardOpen/Close semantics).
- [x] 2) Implement strict ODVA mode + explicit vendor-variant toggles (configurable).
- [x] 3) Add DPI stress scenarios and metrics (jitter, percentiles, misclassification).
- [x] 4) Tighten Forward Open state handling and I/O framing (CPF, sequence counts).
- [ ] 5) Docs audit: mark stale content, consolidate, and prune as approved. (plan drafted)
- [ ] 6) Windows sanity pass: paths, file permissions, build/test commands.

## Work Items
### Protocol compliance + modes
- [ ] Document "strict_odva" default mode and define behavior flags for each layer (ENIP, CIP, I/O).
- [x] Add "vendor_variant" mode family (e.g., "rockwell", "schneider", "siemens") with explicit deviations.
- [x] Add config validation to prevent incompatible combinations.
- [x] Add protocol_variants list support for vendor_variants scenario.
- [ ] Enforce CPF presence for UCMM/connected paths in strict_odva (allow legacy_compat exceptions).
- [ ] Require CIP path size for UCMM requests in strict_odva (based on PCAP evidence).
- [x] Add CIP service/class enums for reference coverage (error_response, member ops, Rockwell tag services, Connection Manager extras).
- [ ] Implement symbolic path segments and tag addressing support.
- [ ] Add Multiple_Service_Packet support (encode/decode).
- [ ] Add fragmentation support for Read/Write Tag Fragmented.
- [ ] Add basic CIP data type codec library (BOOL/INT/DINT/REAL/STRING).
- [ ] Add Identity Object attribute reads (Class 0x01, attributes 1-7) on server.
- [ ] Audit legacy code paths for stale assumptions (big-endian, non-CPF, pre-profile logic) and remove/guard them.

### ENIP/CIP encoding fixes
- [x] Verify/align byte order in ENIP encapsulation and CIP multi-byte fields.
- [x] Ensure CIP request includes path size (words) where required and path padding rules.
- [x] Ensure CIP response includes reserved/additional-status-size semantics per spec.
- [x] Add compliance tests to lock behavior for strict vs variant modes.

### Connected messaging + I/O
- [x] Track Forward Open state (connection IDs, owner, inactivity timeout).
- [x] Require active connection for SendUnitData; reject or drop when invalid.
- [x] Implement CPF items and sequence counters for class 1 I/O.
- [ ] Add I/O jitter/burst options for DPI stress.

### Scenarios + metrics
- [x] Add "edge_valid" scenario for spec-compliant edge cases.
- [x] Add "vendor_variants" scenario to replay known deviations safely.
- [x] Add "mixed_state" scenario (UCMM + connected I/O interleaving).
- [x] Extend metrics: percentiles, jitter, error class, expected/observed outcome.
- [ ] Add Rockwell ENBT replay pack (edge_targets + custom services from PCAP).
- [ ] Re-run reference extraction to populate response packets using updated PCAP parser.
- [x] Add optional edge scenarios for Rockwell tag services and Connection Manager extras.
- [x] Add validation hooks for error_response/restore/save/nop/member ops (strict ODVA checks).

### Docs cleanup
- [x] Relocate internal/audit docs to `notes/` and update references.
- [x] Add `AGENTS.md` with project context for future sessions.
- [x] Remove `.cursorrules` after capturing relevant guidance.
- [ ] Validate `docs/COMPLIANCE_TESTING.md` against current behavior (status list normalized to ASCII; continue line-by-line review).
- [ ] Consolidate internal plan/audit/status notes into fewer `notes/` docs, then review for accuracy.
- [ ] Re-run evaluations that feed audit notes (compliance audit tests, pcap-summary on reference captures) before updating consolidated notes.
- [ ] Line-by-line validation of all docs in `docs/` (excluding `docs/vendors/`) against current ODVA framing and implementation.
- [ ] Fix outdated ODVA compliance notes (e.g., COMPLIANCE_TESTING.md big-endian assumptions).
- [ ] Audit markdown docs for alignment (README.md, docs/CHANGELOG.md, notes/STATUS.md, notes/PROJECT_STATUS.md, notes/PROJECT_SUMMARY.md, notes/SUMMARY.md, docs/EXAMPLES.md).
- [ ] Align COMPLIANCE.md and COMPLIANCE_TESTING.md with little-endian framing + CPF/path-size expectations.
- [ ] Inventory docs with value status (active, stale, replace, remove).
- [ ] Consolidate compliance docs (reduce duplication, highlight strict vs variants).
- [ ] Remove or archive stale docs only after approval.

### Cross-platform note
- [ ] Check path handling and example commands across macOS/Linux/Windows.
- [ ] Confirm any scripts rely on OS-specific tools and provide alternatives or detection.

## Notes
- Docs folder is older; cleanup should be staged with a list of keep/remove candidates.
- Protocol accuracy is the primary objective; tooling changes should be scoped to DPI needs.
- PCAP on deck: `C:\Users\tony\Documents\GitHub\cipdip\pcaps\stress\ENIP.pcap` for reference extraction.
- Added pcap-summary and improved ENIP extraction to handle multi-frame TCP payloads.
- Re-run `cipdip pcap-summary --input pcaps/stress/ENIP.pcap` to update counts after response-code normalization.
- PCAP observations: CPF present in nearly all ENIP frames, CIP path size present in all UCMM requests, no 16-bit EPATH segments, heavy vendor-specific services (0x4B/0x4D/0x52/0x51).
- Vendor identified from PCAP: Rockwell (Vendor ID 0x0001), Product 1756-ENBT/A. Use `rockwell_enbt` profile only when identity matches.
- Re-evaluation run: `go test ./internal/cipclient` and `cipdip pcap-summary --input pcaps/stress/ENIP.pcap` (latest run successful).
- New PCAP batch summaries generated in `notes/pcap_summary_report.md` and vendor rollup in `notes/pcap_vendor_summary.md`.
- PCAP classification script: `analyze-cip-pcaps.ps1` (use for future noise/fuzz classification and folder placement).
- PCAP folders: `pcaps/normal` (compliance/regression), `pcaps/stress` (DPI stress), `pcaps/not_cip` (ignored).

## Audit findings (initial)
- CIP request encoding omits path size byte and assumes no reserved fields in responses; tests reflect the same.
- SendUnitData does not use CPF items or sequence counts for class 1 I/O framing.
- Forward Open/Close state is not tracked on the server and SendUnitData accepts any connection ID.

## Recent changes
- Protocol config and strict ODVA defaults added (profiles + overrides).
- ENIP/CIP encoding switched to strict framing (path size, response reserved/status-size, CPF).
- Vendor profiles scaffolded (Rockwell/Schneider/Siemens presets).
- Server tracks Forward Open connections and validates SendUnitData.
- Docs cleanup plan captured in `notes/DOCS_CLEANUP_PLAN.md`.
