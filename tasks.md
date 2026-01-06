# CIPDIP Task Tracker

## Priority: Protocol correctness + compliance
- [ ] Fix ForwardOpen/ForwardClose ODVA audit failures (tick time, timeout, RPI units, connection path sizing, byte order).
- [ ] Add spec rules for Multiple Service Packet and remaining class-specific payload shapes.
- [ ] Populate missing reference packets (RegisterSession_Response at minimum).
- [ ] Add compliance regression checks in CI (packet structure diffs).
- [ ] Add protocol coverage report (feature/test matrix; ties to spec rules and PCAP coverage).
- [ ] Enhance Wireshark validator to extract more ENIP/CIP fields from tshark output.

## Priority: UX + TUI
- [ ] Implement workspace.yaml defaults for target IP/port/interface and consume in TUI flows.
- [ ] Add TUI progress indicators for long-running operations (runs, replays, validations).
- [ ] Add explicit TUI feedback when external tools (tshark/tcpreplay) are missing.
- [ ] Add interactive discover/test modes (guided device selection).
- [ ] Improve config validation errors with field-specific hints/examples.
- [ ] Add CLI aliases (c/s/d/t) for common commands.

## Priority: Tests + fixtures
- [ ] Add integration tests with known-good request bytes under testdata for payload builders.
- [ ] Verify catalog entries without payload metadata still behave correctly (payload defaults = none).

## Ops + environment
- [ ] Windows sanity pass: paths, file permissions, build/test commands.
- [ ] Hardware validation test suite (requires lab devices).

# CIPDIP Backlog (deferred)

## Robustness + performance
- [ ] Add fuzz/property tests for ENIP/CIP encode/decode.
- [ ] Add parallel scenario execution option with rate limits.
- [ ] Evaluate connection pooling (only if it materially improves throughput).
- [ ] Evaluate buffer pooling for ENIP/CIP encoding (only if profiling shows pressure).

## Refactor follow-ups (file size splits)
- [ ] Split `internal/ui/tui.go` into focused UI modules.
- [ ] Split `internal/cip/client/compliance_audit_test.go` by feature.
- [ ] Split `internal/cip/client/compliance_test.go` by protocol area.
- [ ] Split `internal/cip/client/client.go` into session/requests/transport helpers.
- [ ] Split `internal/cip/client/payload_builder.go` per service family.
- [ ] Split `internal/config/config.go` into client/server/protocol/workspace sections.
- [ ] Split `internal/validation/wireshark.go` into discovery/exec/parse/report helpers.
- [ ] Split `internal/validation/pcap_eval.go` into evaluation/expectations/scoring helpers.
- [ ] Split `internal/validation/fixtures/specs.go` into spec groups.
- [ ] Split `internal/ui/wizard_form.go` into wizard types/forms/shared widgets.
- [ ] Split `internal/scenario/firewall.go` into scenario stages/helpers.
- [ ] Split `internal/app/emit_bytes.go` into emit/build/report helpers.
- [ ] Split `internal/server/core/protocol_compliance_test.go` by area.
- [ ] Split `internal/server/handlers/vendors/rockwell/logix.go` into tag/pccc/template handlers.
- [ ] Split `internal/app/client.go` into scenario orchestration helpers.
