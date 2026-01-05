# CIPDIP TUI & UX Specification

Version: 2.0
Audience: Implementation agent (Codex), CIPDIP maintainers
Status: Authoritative design specification
Scope: TUI + UX only (no protocol semantics)

---

## 0. Explicit Instruction to Implementation Agent (Codex)

This specification is intentionally opinionated but incomplete.

You are expected to:
- Take reasonable latitude where this document lacks knowledge of:
  - existing flags
  - internal edge cases
  - experimental features
- Preserve all existing Cobra commands and CLI behavior.
- Treat the CLI as the canonical interface.
- Prefer intent-level abstractions over exhaustive flag exposure.
- Defer to existing code correctness over this document if conflicts arise.
- Log assumptions where behavior is inferred.

This document defines UX contracts and system shape, not every option.

---

## 1. Problem Statement

CIPDIP has evolved into a powerful research platform with:
- dozens of subcommands
- commands with 20–40 flags
- YAML configs that are technically correct but expert-only
- deep domain coupling to CIP semantics (services, classes, attributes)

As new capabilities are added:
- server emulation
- application profiles (PLC / HMI / EWS)
- baseline + torture testing
- catalog-driven single-request probing

The CLI alone becomes insufficient for:
- discoverability
- safe execution
- repeatability
- comparison of results

The TUI exists to make CIPDIP usable without diluting correctness.

---

## 2. Design Goals

1. Make CIPDIP discoverable without reading code
2. Reduce cognitive load for common workflows
3. Produce repeatable, auditable runs by default
4. Preserve expert escape hatches
5. Avoid a "second product" divergence from CLI
6. Scale as commands and profiles increase

---

## 3. Non-Goals

- Full CLI flag parity in the TUI
- Replacing Cobra help or documentation
- Hiding CIP hex values or protocol reality
- Building a graphical UI

---

## 4. System Architecture

```
+-----------------+
|      User       |
+--------+--------+
         |
         | interactive intent selection
         v
+----------------------------+
|        CIPDIP TUI          |
|  (Bubble Tea + Huh Forms)  |
|                            |
|  - Palette                 |
|  - Wizards                 |
|  - Workspace Browser       |
|  - Catalog Explorer        |
+-------------+--------------+
              |
              | generates concrete CLI commands
              | and/or structured configs
              v
+----------------------------+
|        Cobra CLI           |
|  (canonical interface)    |
+-------------+--------------+
              |
              | shared runners
              v
+----------------------------+
|     Core CIPDIP Engine     |
+----------------------------+
```

The TUI never owns business logic.

---

## 5. Core UX Patterns (Integrated)

The TUI integrates three complementary patterns:
1. Command Palette (discovery)
2. Wizard Flows (safe construction)
3. Workspace Model (repeatability)

They are not separate modes — they reinforce each other.

---

## 6. Workspace Model (Foundational)

### 6.1 Workspace Definition

A workspace is the unit of repeatability.

It is a directory containing:
- inputs
- configs
- runs
- outputs
- notes

### 6.2 Directory Layout

```
workspace/
│
├── workspace.yaml
├── profiles/
│   ├── baseline-dpi-off.yaml
│   ├── baseline-dpi-on.yaml
│   └── replay-raw-auto.yaml
│
├── catalogs/
│   └── custom-cip.yaml      (optional)
│
├── pcaps/
│   └── stress/
│
├── runs/
│   ├── 2026-01-03_00-41_baseline-dpi-off/
│   │   ├── resolved.yaml
│   │   ├── command.txt
│   │   ├── stdout.log
│   │   ├── summary.json
│   │   └── artifacts/
│   │
│   └── 2026-01-03_01-02_baseline-dpi-on/
│
├── reports/
└── tmp/
```

### 6.3 Mandatory Run Artifacts

Every run must emit:
- `resolved.yaml` – fully expanded effective configuration
- `command.txt` – exact CLI invocation
- `stdout.log` – full output capture
- `summary.json` – structured result metadata

This is a hard requirement.

---

## 7. TUI Entry and Navigation

### 7.1 Entry Command

```
cipdip ui
```

Optional flags:
- `--workspace <path>`
- `--new-workspace <path>`
- `--no-run`
- `--print-command`

### 7.2 Global Keybindings

- `Enter` – select / confirm
- `Esc` – back
- `/` – focus command palette
- `r` – run selected config
- `e` – edit config
- `c` – copy generated command
- `d` – diff runs
- `q` – quit
- `?` – help overlay

Keybindings must be visible in the UI footer.

---

## 8. Home Screen (Workspace Context)

```
+------------------------------------------------------+
| cipdip UI | Workspace: dynics-lab                    |
+------------------------------------------------------+
| Search: ____________________________________________ |
|                                                      |
| Quick Actions:                                       |
|   - New Run (Wizard)                                 |
|   - Run Existing Config                              |
|   - Baseline (Guided)                                |
|   - Start Server Emulator                            |
|   - Explore CIP Catalog                              |
|                                                      |
| Configs:                                             |
|   baseline-dpi-off.yaml                              |
|   baseline-dpi-on.yaml                               |
|   replay-raw-auto.yaml                               |
|                                                      |
| Recent Runs:                                         |
|   2026-01-03_00-41_baseline-dpi-off                  |
|   2026-01-03_01-02_baseline-dpi-on                   |
+------------------------------------------------------+
```

---

## 9. Command Palette Pattern

The palette is the primary discovery mechanism.

### 9.1 Palette Search Scope

A single search input must match:
- Tasks (wizards)
- Profiles (YAML configs)
- Runs (execution history)
- Catalog entries (CIP operations)

Results are grouped and labeled by type.

### 9.2 Palette Example

```
Search: vendor id
---------------------------------
[Task] Explore CIP Catalog
[Catalog] identity.vendor_id
[Run] 2026-01-03_00-41_baseline
[Config] baseline-dpi-off.yaml
```

Selecting an item routes to the appropriate screen.

---

## 10. Wizard Pattern

Wizards are safe construction tools.

They serve two purposes:
- execute a multi-step activity
- generate a repeatable YAML config

### 10.1 Wizard Contract

Every wizard must:
1. Ask only what is required
2. Provide defaults from workspace
3. Hide advanced options initially
4. End with a review screen

### 10.2 Wizard Final Screen (Required)

```
+---------------- Review & Execute -------------------+
| Command:                                           |
| cipdip pcap-replay --preset cl5000eip:firmware ... |
|                                                     |
| Effective Behavior:                                |
| - Raw replay                                       |
| - ARP primed once                                  |
| - ENIP rewrite enabled                             |
|                                                     |
| Actions:                                           |
| [Run] [Save Config] [Copy Command] [Back]          |
+----------------------------------------------------+
```

---

## 11. Profile (Config) Model

### 11.1 Two-Layer YAML

Profiles must separate:
- spec: intent-level fields (wizard-owned)
- advanced: expert overrides

### 11.2 Example

```yaml
version: 1
kind: pcap_replay
name: replay-raw-auto

spec:
  engine: raw
  target:
    iface: eth0
    dst_ip: 192.168.10.20
  arp: prime
  rewrite: auto
  pace: 5ms
  report: true

advanced: {}
```

### 11.3 Mapping Rules

Each kind maps to one Cobra command.

Expansion order:
1. workspace defaults
2. spec
3. advanced
4. wizard overrides

---

## 12. CIP Catalog Concept

### 12.1 Purpose

The catalog provides named, searchable CIP operations.

It replaces:
- memorizing service codes
- remembering class/instance/attribute triples

### 12.2 Catalog Structure

```
Service
  |
Object (Class)
  |
Attribute / Operation
```

### 12.3 Catalog Explorer UI

```
+--------------- CIP Catalog ----------------+
| Search: identity                            |
|                                            |
| Identity Object (Class 0x01)                |
|   - Vendor ID (attr 0x01)                  |
|   - Product Name (attr 0x07)               |
|                                            |
| [Run] [Copy Command] [Add to Test Plan]    |
+--------------------------------------------+
```

Hex values must always be visible.

---

## 13. Friendly Single-Request Flow

### 13.1 CLI

```
cipdip single identity.vendor_id --ip 10.0.0.50
```

### 13.2 TUI Flow

1. Select catalog operation
2. Enter target IP/port
3. Optional payload (only if required)
4. Review
5. Run / Save step

---

## 14. Test Plan Builder (Optional, Phase 2)

Allows construction of multi-step tests:

```
steps:
  - single: identity.vendor_id
  - single: pccc.execute
  - sleep: 500ms
  - replay: baseline-raw.yaml
```

This reuses:
- catalog operations
- existing profiles

---

## 15. Run Comparison (Phase 2)

Compare two runs:
- resolved.yaml diff
- summary.json metrics
- captured artifacts

Primary use case:
- DPI off vs DPI on validation

---

## 16. Acceptance Criteria (Phase 1)

The implementation is acceptable when:
1. `cipdip ui` opens a workspace-aware TUI
2. Palette searches tasks, configs, runs, catalog
3. PCAP replay wizard works end-to-end
4. Baseline and server wizards exist
5. Catalog CLI and TUI browsing exist
6. `cipdip single <catalog-key>` works
7. All runs emit required artifacts

---

## 17. Summary

This TUI is not a replacement for the CLI.

It is a force multiplier:
- for learning
- for repeatability
- for research velocity

Preserve correctness. Optimize usability. Defer to CLI when uncertain.
