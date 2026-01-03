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
### Test coverage plan (exhaustive)
#### Phase 1: Protocol primitives + strictness (highest value)
- [x] Test: ENIP encode/decode (headers, length, status, session, sender context).
- [x] Test: ENIP CPF parsing/encoding (items, alignment, errors).
- [x] Test: CIP EPATH encoding/decoding (8/16-bit segments, symbolic, padding).
- [x] Test: CIP service request/response framing (path size, status, extended status).
- [x] Test: Error response handling + status code mapping.
- [x] Test: Strict ODVA vs vendor_variant behavioral deltas (encoding + accept/reject).
- [x] Test: CPF enforcement and CIP path size rules (strict mode).

#### Phase 2: Client/server behavior (runtime correctness)
- [x] Test: Client scenario execution (baseline/edge/mixed/vendor/IO) validates expected outcomes.
- [x] Test: Server request handling for all supported services and classes.
- [x] Test: Forward Open/Close request/response encode/decode.
- [x] Test: Forward Open state machine + timeout handling.
- [x] Test: Connected SendUnitData framing + sequence count.
- [x] Test: I/O path enforcement (connected-only, invalid connection IDs).
- [x] Test: Unconnected Send wrapper encode/decode (embedded CIP).
- [x] Test: Multiple Service Packet encode/decode + error aggregation.

#### Phase 3: Object/service coverage (CIP catalog)
- [x] Test: RegisterSession/ListIdentity/ListServices/ListInterfaces parsing.
- [x] Test: Identity Object attributes 1-7 read responses.
- [x] Test: Connection Manager services (0x54/0x4E/0x56/0x57/0x5A/0x5B).
- [x] Test: Vendor services (Rockwell 0x4B/0x4C/0x4D/0x52/0x53) with contextual class mapping.
- [x] Test: Symbol/Template services (0x52/0x53/0x4C) with fragmentation.
- [x] Test: File Object services (0x4B-0x51) behavior + error codes (when enabled).
- [x] Test: Event Log/Time Sync/Modbus/Motion/Safety class basic read/write flows (where supported).
- [x] Test: CIP data type codec (BOOL/INT/DINT/REAL/STRING primitives).

#### Phase 4: Tooling + CLI + PCAP pipeline
- [x] Test: Config parsing/validation (all flags + new profiles + tags).
- [x] Test: Scenario selection (tags, firewall vendor filters, preset selection).
- [x] Test: Metrics output (CSV/JSON, percentiles, jitter, outcome flags).
- [x] Test: PCAP extraction (metadata, request/response detection, TCP reassembly).
- [x] Test: PCAP replay (app/raw/tcpreplay) preflight + ARP/MAC rewrite paths.
- [x] Test: PCAP rewrite (IP/port/MAC, checksum updates, onlyENIP filter).
- [x] Test: PCAP summary/report/coverage/dump correctness.
- [x] Test: CLI help/required flags errors (pcap-summary, pcap-replay, single).
- [x] Test: Cross-platform path handling and tool discovery (tshark, tcpreplay, tcprewrite).
- [x] Test: Regression tests against reference_packets_gen.go for supported services/paths.

### Protocol compliance + modes
- [x] Document "strict_odva" default mode and define behavior flags for each layer (ENIP, CIP, I/O).
- [x] Add "vendor_variant" mode family (e.g., "rockwell", "schneider", "siemens") with explicit deviations.
- [x] Add config validation to prevent incompatible combinations.
- [x] Add protocol_variants list support for vendor_variants scenario.
- [x] Enforce CPF presence for UCMM/connected paths in strict_odva (allow legacy_compat exceptions).
- [x] Require CIP path size for UCMM requests in strict_odva (based on PCAP evidence).
- [x] Add CIP service/class enums for reference coverage (error_response, member ops, Rockwell tag services, Connection Manager extras).
- [x] Implement symbolic path segments and tag addressing support.
- [x] Add Multiple_Service_Packet support (encode/decode).
- [x] Add fragmentation support for Read/Write Tag Fragmented.
- [x] Add basic CIP data type codec library (BOOL/INT/DINT/REAL/STRING).
- [x] Add Identity Object attribute reads (Class 0x01, attributes 1-7) on server.
- [x] Audit legacy code paths for stale assumptions (big-endian, non-CPF, pre-profile logic) and remove/guard them.

### ENIP/CIP encoding fixes
- [x] Verify/align byte order in ENIP encapsulation and CIP multi-byte fields.
- [x] Ensure CIP request includes path size (words) where required and path padding rules.
- [x] Ensure CIP response includes reserved/additional-status-size semantics per spec.
- [x] Add compliance tests to lock behavior for strict vs variant modes.

### Connected messaging + I/O
- [x] Track Forward Open state (connection IDs, owner, inactivity timeout).
- [x] Require active connection for SendUnitData; reject or drop when invalid.
- [x] Implement CPF items and sequence counters for class 1 I/O.
- [x] Add I/O jitter/burst options for DPI stress.

### Server vNext emulator framework (new requirements)
#### Phase 1: ENIP/CPF/session correctness (core)
- [x] Add ENIP support toggles (ListIdentity/ListServices/ListInterfaces/RegisterSession/SendRRData/SendUnitData) with config gating.
- [x] Add session policy controls (require_register_session, max sessions, per-IP limit, idle timeout).
- [x] Implement TCP stream handling in server (split/coalesced ENIP frames).
- [x] Harden malformed ENIP/CPF handling (no panics; configurable strict/permissive CPF).
- [x] Add CPF policy controls (allow reorder/extra/missing items).

#### Phase 2: CIP policy + deterministic behavior
- [x] Add CIP policy allow/deny lists with default status + per-service/class overrides.
- [x] Add server targets to match client presets (rockwell/schneider/siemens/omron/keyence).

#### Phase 3: Fault injection + observability
- [x] Add fault injection controls (latency/jitter/spike, drop/close/stall, chunked TCP/coalesce).
- [x] Add server logging/metrics config (format/level/log_every_n/hex + metrics listener).

#### Phase 4: CLI + modes + tests
- [x] Add server CLI subcommands: start, targets, modes, validate-config, print-default-config.
- [x] Implement easy server modes (baseline/realistic/dpi-torture/perf) with precedence rules.
- [x] Add CLI tests (help no bind, targets list, validate-config, print-default-config).
- [x] Add unit tests: ENIP stream parsing, CPF strict/permissive, EPATH errors, fault injection (seeded).
- [x] Add integration tests: start ephemeral server, minimal client session, baseline/realistic/dpi-torture.
- [x] Add optional golden PCAP capture regression plan.

### Scenarios + metrics
- [x] Add "edge_valid" scenario for spec-compliant edge cases.
- [x] Add "vendor_variants" scenario to replay known deviations safely.
- [x] Add "mixed_state" scenario (UCMM + connected I/O interleaving).
- [x] Extend metrics: percentiles, jitter, error class, expected/observed outcome.
- [x] Add "unconnected_send" scenario for UCMM wrapper tests with embedded CIP requests.
- [x] Add optional force_status override for unconnected_send metrics.
- [x] Add Rockwell ENBT replay pack (edge_targets + custom services from PCAP).
- [x] Re-run reference extraction to populate response packets using updated PCAP parser.
- [x] Add optional edge scenarios for Rockwell tag services and Connection Manager extras.
- [x] Add validation hooks for error_response/restore/save/nop/member ops (strict ODVA checks).
- [x] Build a PCAP reference coverage matrix (services + class/instance paths) from current `pcaps/` and compare to client/server support.
- [x] Implement missing client/server handlers for any PCAP-referenced services/objects (track gaps explicitly).
- [x] Add regression tests that assert PCAP-referenced services/objects are supported by client + server.
- [x] Add firewall vendor scenarios (hirschmann/moxa/dynics) with a pack runner and tagged target selection.
- [x] Add composable scenario model (pattern + target set + firewall pack) to avoid N^3 scenario explosion.
- [x] Add one-off service/class/instance CLI helper for single checks (no YAML edits).
- [x] Add PCAP replay scenario (app/raw/tcpreplay) with optional timing and rewrite hooks.
- [x] Add PCAP-derived scenario presets for CL5000EIP actions (firmware change, reboot, etc.).
- [x] Document stateful firewall replay guidance for pcap-replay modes.
- [x] Add pcap-rewrite command for offline IP/port rewriting.
- [x] Add ARP probe helper command for L2 reachability before replays.
- [x] Add `pcap-rewrite` MAC rewrite options for L2 fidelity (src/dst MAC).
- [x] Add `pcap-rewrite` summary report (counts of packets rewritten, skipped, errors).
- [x] Add strict stateful preflight check (per-flow SYN/SYN-ACK/ACK validation) for replay modes.
- [x] Add `pcap-replay` preflight-only mode with summary + ARP validation (no traffic sent).
- [x] Expand PCAP replay plan coverage: document and track options (app/raw/tcpreplay) and when to use each.
- [x] Add L2 replay guidance + safeguards: ARP priming, optional DNS lookup, and route checks to ensure replays reach target.
- [x] Add self-healing replay behavior: retry ARP and re-resolve MACs if target changes mid-run; warn on MAC drift.
- [x] Add L2/L3 replay modes validation: confirm MAC rewrite + ARP flow works for routed vs bridged firewall paths.
- [x] Add pcap-replay verification step: optional post-run sanity report (flows sent, dropped, missing responses).

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
- [x] Check path handling and example commands across macOS/Linux/Windows.
- [x] Confirm any scripts rely on OS-specific tools and provide alternatives or detection.
- [x] Improve tshark discovery (TSHARK env + OS default locations) for PCAP tooling and validation.
- [x] Investigate Unknown CIP service 0x51 on class 0x00A1 (pcaps/stress/ENIP.pcap) and update contextual service mapping if evidence supports.
- [x] Consolidate PCAP analysis into Go CLI (`cipdip pcap-report` and `cipdip pcap-classify`), remove PowerShell scripts.

### TUI + UX (new)
#### Phase 0: Spec + design guardrails
- [x] Capture authoritative TUI spec and UX contracts in `notes/TUI_SPEC.md`.
- [x] Note assumptions/unknowns to validate against current CLI flags and configs.

#### Phase 1: CLI entry + workspace model (MVP)
- [x] Add `cipdip ui` command (Cobra) with flags: --workspace, --new-workspace, --no-run, --print-command.
- [x] Implement workspace layout creation and discovery (workspace.yaml, profiles/, catalogs/, pcaps/, runs/, reports/, tmp/).
- [x] Implement run artifact emission (resolved.yaml, command.txt, stdout.log, summary.json) for all TUI-triggered runs.
- [x] Implement command generation layer (spec+advanced+overrides -> CLI invocation).

#### Phase 1: Core UX flows
- [x] Command palette: search tasks, profiles, runs, catalog entries (grouped results).
- [x] Wizard flows: PCAP replay, baseline, server (review screen required).
- [x] Home screen: quick actions, configs list, recent runs list.
- [x] Catalog explorer UI: identity/browse/search, hex always visible.
- [x] Single-request flow (TUI) wired to `cipdip single <catalog-key>`.

#### Phase 1: Supporting models
- [x] Palette data model and search (tasks, profiles, runs, catalogs).
- [x] Review screen renderer for wizard summary output.
- [x] Catalog model loader (catalogs/*.yaml) and palette integration.
- [x] Bubble Tea shell for home/palette/catalog navigation.
- [x] In-TUI search overlay ("/" to search, Esc to clear).

#### Phase 1: Tests
- [x] Unit tests: workspace creation, profile resolution, command generation.
- [x] Integration tests: `cipdip ui --no-run` starts without panic; workspace selection works.
- [x] Snapshot tests (text) for wizard review screen command output.

#### Phase 2: Optional features
- [ ] Test plan builder (multi-step runner).
- [ ] Run comparison view (resolved.yaml + summary.json diff).

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
- PCAP classification: `cipdip pcap-classify` (tshark-based) and `cipdip pcap-report` (summary report, no tshark).
- Unknown CIP service 0x51 appears on class 0x00A1/instance 0x0001 with status 0x08 responses in CL5000EIP firmware-change pcaps and ENIP.pcap; evidence insufficient to map yet.
- pcap-dump spot checks: 0x4B targets class 0x0067, 0x4E targets class 0x0006/instance 0x0001, 0x55 not observed in ENIP.pcap.
- PCAP folders: `pcaps/normal` (compliance/regression), `pcaps/stress` (DPI stress), `pcaps/not_cip` (ignored).
- Reference extraction run: `cipdip extract-reference --real-world-dir pcaps --output internal/cipclient/reference_packets_gen.go`.
- Reference extraction now filters for little-endian ENIP headers; `RegisterSession_Response` still missing from real-world captures.
- Re-ran PCAP classification and summary reports for current `pcaps/` set (excluding baseline).

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
