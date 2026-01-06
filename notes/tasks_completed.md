# CIPDIP Completed Tasks (archive)

## Plan (tracked steps)
- [x] 1) Baseline compliance audit: confirm current encoding vs ODVA (endianness, EPATH path size, CPF items, SendRRData/SendUnitData format, ForwardOpen/Close semantics).
- [x] 2) Implement strict ODVA mode + explicit vendor-variant toggles (configurable).
- [x] 3) Add DPI stress scenarios and metrics (jitter, percentiles, misclassification).
- [x] 4) Tighten Forward Open state handling and I/O framing (CPF, sequence counts).

## Work Items
### Audit carryover (still relevant)
- [x] Add quick-start config generation or `--quick-start` flow when config is missing.
- [x] Add progress indicators for long-running CLI/TUI operations (counts + ETA).
- [x] Improve user-facing error messages with hints and next-step suggestions.
- [x] Decide whether `workspace.yaml` should store default target IP/port/interface for TUI flows.
- [x] Audit docs for stale paths/commands after refactor (e.g., internal/cipclient -> internal/cip/client, internal/pcap, internal/reference) and update as needed.
- [x] Decide whether to keep `docs/WIRESHARK_INTEGRATION.md` or merge its content into `docs/COMPLIANCE_TESTING.md`, then update accordingly.
### Test coverage plan (exhaustive)
- [x] Test: ENIP encode/decode (headers, length, status, session, sender context).
- [x] Test: ENIP CPF parsing/encoding (items, alignment, errors).
- [x] Test: CIP EPATH encoding/decoding (8/16-bit segments, symbolic, padding).
- [x] Test: CIP service request/response framing (path size, status, extended status).
- [x] Test: Error response handling + status code mapping.
- [x] Test: Strict ODVA vs vendor_variant behavioral deltas (encoding + accept/reject).
- [x] Test: CPF enforcement and CIP path size rules (strict mode).
- [x] Test: Client scenario execution (baseline/edge/mixed/vendor/IO) validates expected outcomes.
- [x] Test: Server request handling for all supported services and classes.
- [x] Test: Forward Open/Close request/response encode/decode.
- [x] Test: Forward Open state machine + timeout handling.
- [x] Test: Connected SendUnitData framing + sequence count.
- [x] Test: I/O path enforcement (connected-only, invalid connection IDs).
- [x] Test: Unconnected Send wrapper encode/decode (embedded CIP).
- [x] Test: Multiple Service Packet encode/decode + error aggregation.
- [x] Test: RegisterSession/ListIdentity/ListServices/ListInterfaces parsing.
- [x] Test: Identity Object attributes 1-7 read responses.
- [x] Test: Connection Manager services (0x54/0x4E/0x56/0x57/0x5A/0x5B).
- [x] Test: Vendor services (Rockwell 0x4B/0x4C/0x4D/0x52/0x53) with contextual class mapping.
- [x] Test: Symbol/Template services (0x52/0x53/0x4C) with fragmentation.
- [x] Test: File Object services (0x4B-0x51) behavior + error codes (when enabled).
- [x] Test: Event Log/Time Sync/Modbus/Motion/Safety class basic read/write flows (where supported).
- [x] Test: CIP data type codec (BOOL/INT/DINT/REAL/STRING primitives).
- [x] Test: Config parsing/validation (all flags + new profiles + tags).
- [x] Test: Scenario selection (tags, firewall vendor filters, preset selection).
- [x] Test: Metrics output (CSV/JSON, percentiles, jitter, outcome flags).
- [x] Test: PCAP extraction (metadata, request/response detection, TCP reassembly).
- [x] Test: PCAP summary/report/coverage/dump correctness.
- [x] Test: PCAP replay (app/raw/tcpreplay) preflight + ARP/MAC rewrite paths.
- [x] Test: PCAP rewrite (IP/port/MAC, checksum updates, onlyENIP filter).
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
- [x] Add ENIP support toggles (ListIdentity/ListServices/ListInterfaces/RegisterSession/SendRRData/SendUnitData) with config gating.
- [x] Add session policy controls (require_register_session, max sessions, per-IP limit, idle timeout).
- [x] Implement TCP stream handling in server (split/coalesced ENIP frames).
- [x] Harden malformed ENIP/CPF handling (no panics; configurable strict/permissive CPF).
- [x] Add CPF policy controls (allow reorder/extra/missing items).
- [x] Add CIP policy allow/deny lists with default status + per-service/class overrides.
- [x] Add server targets to match client presets (rockwell/schneider/siemens/omron/keyence).
- [x] Add fault injection controls (latency/jitter/spike, drop/close/stall, chunked TCP/coalesce).
- [x] Add server logging/metrics config (format/level/log_every_n/hex + metrics listener).
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
### CIP request payload framework (service-specific data)
- [x] Add catalog schema for payload metadata: `payload.type` + `payload.params` (default none).
- [x] Build ServiceDataBuilder table keyed by catalog key or (service,class) to append payload after EPATH.
- [x] Add CLI flags for payload params: `--tag`, `--elements`, `--offset`, `--type`, `--value`, `--file`, `--file-offset`, `--chunk`, `--modbus-fc`, `--modbus-addr`, `--modbus-qty`, `--pccc-hex`, `--route-slot`, `--ucmm-wrap`.
- [x] Implement Forward Open payload builder (Connection Manager 0x54) with sane defaults and CLI overrides (RPIs, sizes, connection path).
- [x] Implement Unconnected Send builder (0x52/CM) with UCMM wrapper, route path (slot), and embedded catalog request.
- [x] Implement Rockwell tag service payloads (read/write/fragmented) using symbolic EPATH segments (`--tag`, `--tag-path`).
- [x] Implement Rockwell template read payload (0x4C/0x006C) with offset/length params.
- [x] Implement File Object payloads (0x37 services 0x4B-0x51) with minimal valid fields and dummy defaults.
- [x] Implement Modbus Object payloads (0x44 services 0x4B-0x51) with function-specific fields and passthrough.
- [x] Implement Execute PCCC payload builder with raw hex + canned examples.
- [x] Add `--dry-run` to print CIP bytes and hex dump (service/path/payload).
- [x] Add `--mutate` payload variants (wrong length, missing fields, invalid offsets) with deterministic seed.
- [x] Add unit tests for each payload builder + validation for required fields.
### TUI + UX (new)
- [x] Capture authoritative TUI spec and UX contracts in `notes/TUI_SPEC.md`.
- [x] Note assumptions/unknowns to validate against current CLI flags and configs.
- [x] Add `cipdip ui` command (Cobra) with flags: --workspace, --new-workspace, --no-run, --print-command.
- [x] Implement workspace layout creation and discovery (workspace.yaml, profiles/, catalogs/, pcaps/, runs/, reports/, tmp/).
- [x] Implement run artifact emission (resolved.yaml, command.txt, stdout.log, summary.json) for all TUI-triggered runs.
- [x] Implement command generation layer (spec+advanced+overrides -> CLI invocation).
- [x] Command palette: search tasks, profiles, runs, catalog entries (grouped results).
- [x] Wizard flows: PCAP replay, baseline, server (review screen required).
- [x] Home screen: quick actions, configs list, recent runs list.
- [x] Catalog explorer UI: identity/browse/search, hex always visible.
- [x] Single-request flow (TUI) wired to `cipdip single <catalog-key>`.
- [x] Palette data model and search (tasks, profiles, runs, catalogs).
- [x] Review screen renderer for wizard summary output.
- [x] Catalog model loader (catalogs/*.yaml) and palette integration.
- [x] Bubble Tea shell for home/palette/catalog navigation.
- [x] In-TUI search overlay ("/" to search, Esc to clear).
- [x] Unit tests: workspace creation, profile resolution, command generation.
- [x] Integration tests: `cipdip ui --no-run` starts without panic; workspace selection works.
- [x] Snapshot tests (text) for wizard review screen command output.
- [x] Test plan builder (multi-step runner).
- [x] Run comparison view (resolved.yaml + summary.json diff).
- [x] Add config edit flow (`e`): open profile in $EDITOR or provide in-TUI editor for spec/advanced YAML.
- [x] Align home screen with spec: show quick actions + recent runs + configs list (compact) instead of minimal-only.
- [x] Wizard review screen: add Effective Behavior summary panel (e.g., replay mode, rewrite, ARP) per spec.
- [x] Profiles: implement spec/advanced layering + workspace defaults expansion order (spec->advanced->overrides).
- [x] Catalog explorer: group by object/class and show hex values in detail view; keep list compact with name+key.
- [x] Single-request wizard: auto-focus first field on open (avoid extra Enter/Tab), and allow preset target selection (done) to sync with IP field.

## Legacy backlog (pre-refactor)
- [x] Move reference packet library out of `internal/cipclient` so `internal/pcap` does not depend on the legacy package.
- [x] Unify client `PacketValidator` with `internal/validation.Validator` so spec rules stay authoritative and avoid drift.
- [x] Phase 11: move remaining PCAP CLI logic (classify analysis, replay preset resolution) into `internal/pcap` so commands stay thin.
- [x] Phase 11: move client/server CLI orchestration into internal services for reuse by UI (no protocol parsing in commands).

