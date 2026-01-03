# Golden PCAP Regression Plan (Optional)

Purpose
- Provide a stable, minimal set of real-world captures that exercise core ENIP/CIP behaviors.
- Use these captures for regression checks (pcap-summary, extract-reference, reference packet validation).
- Keep scope tight to avoid large files and long test times.

Selection Criteria
- Real-world sources only (not baseline_captures).
- Small, focused captures for each behavior (RegisterSession, SendRRData, ForwardOpen/Close, connected I/O).
- Prefer files with stable identities (known vendor/product) and minimal background noise.
- Include at least one stress capture (high retrans, CPF errors) for robustness checks.

Golden Set Layout
- pcaps/normal/golden/
  - register_session.pcap
  - get_attribute_single.pcap
  - set_attribute_single.pcap
  - forward_open_close.pcap
  - send_unit_data_io.pcap
  - list_identity.pcap
- pcaps/stress/golden/
  - cpf_edge_cases.pcap
  - tcp_reassembly_fragments.pcap

Acceptance Requirements
- Each capture must produce deterministic pcap-summary counts (commands, requests/responses).
- Extracted reference packets from golden set must validate with `ValidatePacketStructure`.
- Any mismatches must be tracked as expected deviations in a small allowlist.

Workflow
1) Add or update golden captures under `pcaps/*/golden/`.
2) Run:
   - `cipdip pcap-summary --input <golden pcap>`
   - `cipdip extract-reference --real-world-dir pcaps --output internal/cipclient/reference_packets_gen.go`
3) Run tests:
   - `go test ./internal/cipclient -run ReferencePackets`
   - `go test ./...`
4) Record summary deltas in `notes/pcap_summary_report.md`.

Governance
- Any new golden capture must document source, vendor identity, and intended behavior.
- Avoid replacing existing captures unless the behavior is better isolated.
- Keep total golden set under ~10 pcaps unless explicitly approved.
