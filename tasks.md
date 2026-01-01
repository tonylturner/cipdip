# CIPDIP DPI Compliance + Vendor-Variant Plan

## Goals
- Enforce strict ODVA-compliant ENIP/CIP encoding/behavior by default.
- Add optional vendor-variant modes that mirror common deviations seen in field devices.
- Expand DPI falsification coverage (edge cases, Forward Open state, jitter/latency metrics).
- Audit and trim docs that are stale or superseded.
- Confirm Windows development/runtime considerations.

## Plan (tracked steps)
- [x] 1) Baseline compliance audit: confirm current encoding vs ODVA (endianness, EPATH path size, CPF items, SendRRData/SendUnitData format, ForwardOpen/Close semantics).
- [ ] 2) Implement strict ODVA mode + explicit vendor-variant toggles (configurable). (in progress)
- [ ] 3) Add DPI stress scenarios and metrics (jitter, percentiles, misclassification).
- [ ] 4) Tighten Forward Open state handling and I/O framing (CPF, sequence counts).
- [ ] 5) Docs audit: mark stale content, consolidate, and prune as approved. (plan drafted)
- [ ] 6) Windows sanity pass: paths, file permissions, build/test commands.

## Work Items
### Protocol compliance + modes
- [ ] Document "strict_odva" default mode and define behavior flags for each layer (ENIP, CIP, I/O).
- [ ] Add "vendor_variant" mode family (e.g., "rockwell", "schneider", "siemens") with explicit deviations.
- [ ] Add config validation to prevent incompatible combinations.

### ENIP/CIP encoding fixes
- [ ] Verify/align byte order in ENIP encapsulation and CIP multi-byte fields.
- [ ] Ensure CIP request includes path size (words) where required and path padding rules.
- [ ] Ensure CIP response includes reserved/additional-status-size semantics per spec.
- [ ] Add compliance tests to lock behavior for strict vs variant modes.

### Connected messaging + I/O
- [ ] Track Forward Open state (connection IDs, owner, inactivity timeout).
- [ ] Require active connection for SendUnitData; reject or drop when invalid.
- [ ] Implement CPF items and sequence counters for class 1 I/O.
- [ ] Add I/O jitter/burst options for DPI stress.

### Scenarios + metrics
- [ ] Add "edge_valid" scenario for spec-compliant edge cases.
- [ ] Add "vendor_variants" scenario to replay known deviations safely.
- [ ] Add "mixed_state" scenario (UCMM + connected I/O interleaving).
- [ ] Extend metrics: percentiles, jitter, error class, expected/observed outcome.

### Docs cleanup
- [ ] Inventory docs with value status (active, stale, replace, remove).
- [ ] Consolidate compliance docs (reduce duplication, highlight strict vs variants).
- [ ] Remove or archive stale docs only after approval.

### Windows note
- [ ] Check Windows-specific path handling and example commands.
- [ ] Confirm any scripts rely on macOS-only tools and provide Windows alternatives.

## Notes
- Docs folder is older; cleanup should be staged with a list of keep/remove candidates.
- Protocol accuracy is the primary objective; tooling changes should be scoped to DPI needs.

## Audit findings (initial)
- CIP request encoding omits path size byte and assumes no reserved fields in responses; tests reflect the same.
- SendUnitData does not use CPF items or sequence counts for class 1 I/O framing.
- Forward Open/Close state is not tracked on the server and SendUnitData accepts any connection ID.

## Recent changes
- Protocol config and strict ODVA defaults added (profiles + overrides).
- ENIP/CIP encoding switched to strict framing (path size, response reserved/status-size, CPF).
- Docs cleanup plan captured in `docs/DOCS_CLEANUP_PLAN.md`.
