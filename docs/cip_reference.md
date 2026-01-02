# CIP / EtherNet/IP (ENIP) Reference Guide for Implementation + DPI Testing
_Last updated: 2026-01-01_

This document is a **consolidated protocol reference** to guide implementation of a CIP/ENIP stack (client + server/emulator) and to support **industrial firewall DPI evaluation**. It is written to be usable by an engineering agent (e.g., Codex) as a “single source” implementation guide and test-design reference.

> **Scope note:** The authoritative specifications are ODVA-controlled publications. This guide focuses on **publicly documented behavior**, **implementation-observable semantics**, and **engineering guidance** useful for building and testing a stack. It is not a substitute for ODVA volumes.

---

## 1) Terminology and core mental model

### Layering
- **CIP (Common Industrial Protocol):** object model + services + EPATH addressing + data types.
- **EtherNet/IP (ENIP):** CIP adapted to Ethernet. CIP requests/responses are carried inside an **Encapsulation Protocol** header over TCP/UDP.
- **Explicit messaging:** request/response style operations (most often TCP 44818).
- **Implicit I/O (“Class 1”):** cyclic I/O data (typically UDP 2222) negotiated via **Forward Open**.

### Common ports (typical deployments)
- **TCP 44818:** explicit messaging
- **UDP 44818:** discovery (e.g., ListIdentity)
- **UDP 2222:** I/O (implicit)

---

## 2) ENIP Encapsulation Protocol

### Encapsulation header (conceptual)
Each Encapsulation message includes a fixed header with at least:
- Command (what encapsulation operation)
- Length (payload length)
- Session handle (0 for some commands; nonzero after RegisterSession)
- Status
- Sender context (opaque 8 bytes)
- Options (usually 0)

### Key encapsulation commands (starter set)
- **ListIdentity** `0x0063` (UDP 44818)
- **ListInterfaces** `0x0064`
- **RegisterSession** `0x0065`
- **UnregisterSession** `0x0066`
- **SendRRData** `0x006F`
- **SendUnitData** `0x0070`

### Session lifecycle (TCP)
1. TCP connect
2. `RegisterSession` → obtain/use session handle
3. Exchange encapsulated CIP payloads (SendRRData / SendUnitData)
4. `UnregisterSession` (optional) and TCP close

### SendRRData vs SendUnitData (practical)
- **SendRRData:** commonly used for **unconnected** messaging (or when you want minimal connection state).
- **SendUnitData:** commonly used for **connected** messaging and/or after Forward Open.

### Common Packet Format (CPF)
Encapsulation payloads often contain a CPF list:
- Address item (e.g., null address or connected address)
- Data item (CIP bytes)

**Implementation tip:** Keep clean module boundaries:
- TCP framing → Encapsulation → CPF items → CIP decoding/encoding.

---

## 3) Discovery & Identity (asset realism)

### Why discovery matters for DPI
Many DPI engines and asset-ID pipelines behave differently if a device:
- responds to discovery correctly
- exposes plausible Identity object fields

### ListIdentity (UDP 44818)
ListIdentity typically returns:
- protocol version
- socket address info
- Identity metadata: vendor, product type/code, revision, status, serial, product name, state

**Implementation guidance**
- Implement broadcast discovery and direct discovery.
- Normalize Identity into a stable struct used across:
  - logs
  - metrics
  - emulator personalities

---

## 4) CIP Object Model & EPATH

### Object model
CIP addresses functions via:
- **Class ID** → which object class
- **Instance ID** → which instance
- **Attribute ID** → which attribute within that instance

A CIP request typically includes:
- **Service code**
- **EPATH** (class/instance/attribute and/or symbolic segments)
- optional request data

### EPATH basics (pragmatic)
Your stack should support:
- **Class/Instance/Attribute paths** (common for Assembly objects, Identity, etc.)
- **Symbolic paths** (common for controller data/tag access)
- Optional **element/index segments** for arrays (e.g., tag[i], multi-dim)

**Design tip:** EPATH parsing/encoding should be segment-based and tolerant:
- strict mode (fail fast, return errors)
- permissive mode (preserve unknown segments as raw bytes)

---

## 5) CIP services to implement first

### Common “generic” services (broad utility)
- `Get_Attributes_All` `0x01`
- `Set_Attributes_All` `0x02`
- `Get_Attribute_List` `0x03`
- `Set_Attribute_List` `0x04`
- `Reset` `0x05`
- `Multiple_Service_Packet` `0x0A`
- `Get_Attribute_Single` `0x0E`
- `Set_Attribute_Single` `0x10`
- Error response semantics (general + extended status)

### Reply service code convention (common pattern)
Replies typically set the high bit: `reply_service = request_service | 0x80`.

**Implementation guidance**
- Build a unified error model: CIP general status + optional extended status.
- Preserve raw request/response bytes for unknown services.

---

## 6) Connected messaging, Forward Open/Close, and I/O

### Forward Open (concept)
Forward Open negotiates a connection contract, often including:
- O→T and T→O connection IDs
- requested packet interval (RPI)
- connection sizes
- connection type (point-to-point vs multicast)
- timeout multiplier

Many implementations attempt “large/extended” variants first and fall back to standard.

### UDP 2222 I/O (implications)
I/O traffic is:
- cyclic and timing-sensitive
- most likely to show DPI-induced degradation (jitter, drops, stale data) before explicit messaging fails

**Implementation guidance**
- Model Forward Open state explicitly (connection IDs, sizes, RPIs).
- Provide optional enforcement:
  - enforce RPI
  - disconnect/timeout on missed cadence
  - simulate real adapter behavior

---

## 7) “Logix-style” tag access (common in practice)

### Frequently observed service codes
- `Read Tag` `0x4C`
- `Write Tag` `0x4D`
- `Read Modify Write` `0x4E`
- `Read Tag Fragmented` `0x52`
- `Write Tag Fragmented` `0x53`
- `Get Instance Attribute List` `0x55` (commonly used in practice)

### Multi-service packets
A common performance pattern is bundling multiple operations into:
- `Multiple_Service_Packet` `0x0A`

### Fragmentation
When payloads exceed negotiated limits, stacks use fragmented read/write services.

### Naming conventions (program-scoped)
A widely used program-scoped convention:
- `Program:<ProgramName>.<TagName>`

### Arrays + BOOL arrays
- arrays use element addressing (tag[index], tag[i,j])
- BOOL arrays often pack bits into larger words, affecting alignment and multi-element writes

**Implementation guidance**
- Build a clear “tag” layer:
  - symbolic path encoding
  - optional optimized forms (instance-based) when available
  - array index encoding
- Include strong test coverage for fragmentation and multi-service bundling.

---

## 8) CIP data types (pragmatic subset)

A useful starter set:
- BOOL, SINT, INT, DINT, LINT
- USINT, UINT, UDINT, ULINT
- REAL (float32), LREAL (float64)
- STRING (length-prefixed)
- BYTE/WORD/DWORD/LWORD bitstrings

**Implementation tips**
- Keep a dedicated codec library:
  - endianness rules (commonly little-endian primitives)
  - string encoding rules
  - array codecs and bounds checks
- Preserve unknown/raw bytes for forward compatibility.

---

## 9) DPI-oriented implementation checklist

### What DPI engines commonly key off
- Correct Encapsulation + session behavior (RegisterSession, SendRRData, SendUnitData)
- Correct CPF item structure
- Forward Open + connection state tracking
- CIP service code + EPATH validity
- Recognition of tag services and fragmentation/multi-service behavior

### Test scenario set (recommended)
1. **baseline_explicit:** low-rate reads only (e.g., Get_Attribute_Single)
2. **mixed_explicit:** reads+writes, occasional multi-service bundles
3. **stress_explicit:** high-rate reads (latency/jitter emphasis)
4. **churn:** repeated session open/close + connection setup/teardown
5. **io:** Forward Open + UDP 2222 cyclic with controlled RPI
6. **fragmentation:** force fragmented read/write by increasing payload sizes
7. **malformed_valid:** spec-valid but unusual segment/service combinations (heuristic DPI breakers)

### Metrics that make results credible
- Request→response latency distribution (p50/p95/p99)
- Jitter distribution (especially for IO)
- Error taxonomy:
  - timeout
  - reset
  - CIP general status errors
  - protocol violations
- Throughput: operations/sec by scenario
- For IO: packet drop rate vs RPI, late packets, connection timeouts

---

## 10) Emulator guidance (server mode)

### Personalities
- **adapter personality:** Assembly-object oriented behavior (common in I/O adapters)
- **logix-like personality:** tag read/write semantics and richer service set

### Identity realism (strongly recommended)
Include a configurable Identity model for:
- ListIdentity responses
- Identity Object attribute reads

### Strictness and fault injection (DPI falsification)
Add knobs for:
- strict_protocol: reject unknown/malformed requests with proper error codes
- permissive mode: respond “service not supported” cleanly
- fault injection:
  - fixed delay + jitter
  - drop N% of replies
  - inject CIP errors
  - close TCP after N requests (churn)

### Forward Open + IO contract
If you support UDP 2222 IO, implement:
- Forward Open handling
- deterministic connection ID allocation
- optional RPI enforcement
- timeout multiplier behavior
- point-to-point vs multicast options

### Write auditing (high value for DPI verification)
Log accepted writes with:
- timestamp
- client address
- target (assembly/tag)
- old/new value
- status/result

This lets you prove:
- firewall “blocked writes” vs what actually changed on the server.

---

## 11) Client guidance (scanner mode)

### Transport/session controls (recommended)
Client should support configuration for:
- bind_ip / interface selection
- timeouts and retries
- TCP nodelay/keepalive
- RegisterSession on/off
- SendRRData vs SendUnitData selection
- unconnected vs connected messaging preference

### Target model (recommended)
Represent targets as:
- service
- EPATH (structured or raw hex)
- encoder/decoder (data type, expected size)
- allowed status codes (expectations)

### Policy expectations layer (optional but powerful)
Allow declaring expected firewall policy outcomes:
- allow reads
- deny writes
- max ops/sec
Then compare observed outcomes to expected.

---

## 12) Capture and validation workflow (practical)

### Always archive “golden” captures
- RegisterSession → request/response pairs
- Forward Open negotiation → UDP 2222 flows
- Tag reads/writes with fragmentation and multi-service bundles

### Wireshark pivots
- ENIP: `enip`
- TCP explicit: `tcp.port == 44818`
- UDP IO: `udp.port == 2222`

### Naming convention for artifacts
`<dut>_<mode>_<scenario>_<rate>_<date>_<runid>.pcapng`

Example:
- `moxa_dpioff_baseline_250ms_2026-01-01_r01.pcapng`
- `tofino_dpiidonly_mixed_100ms_2026-01-01_r02.pcapng`
- `dynics_dpistrict_io_rpi20ms_2026-01-01_r03.pcapng`

---

## 13) Implementation architecture (Go-oriented)

Suggested module split:
- `encap/` — encapsulation header + commands
- `cpf/` — Common Packet Format item parsing/encoding
- `cip/` — services, status, EPATH segment parsing/encoding
- `types/` — CIP data type codecs
- `logix/` — symbolic paths, tag services, fragmentation/multi-service helpers
- `emulator/` — personalities, identity, write audit, fault injection
- `metrics/` — event model, latency/jitter stats, CSV/JSON emit

Operating modes:
- **strict**: validate lengths, enums, state transitions; return correct CIP errors
- **permissive**: decode best-effort; preserve unknown bytes; avoid crashing

---

## 14) “Full spec alignment” plan (when ready)
To align with official coverage beyond public docs:
- Obtain ODVA CIP/ENIP volumes via ODVA subscription/membership.
- Map your implemented service/segment coverage to ODVA conformance expectations.
- Use this guide as the engineering “glue” between observed behavior and formal spec text.

---

## 15) CIPDIP supported coverage (public-evidence baseline)

This section summarizes what CIPDIP currently supports using public sources (PCAPs + vendor docs) without assuming ODVA volumes.

### Class coverage (profiles + baseline)
- **Baseline classes:** Identity (0x01), Message Router (0x02), Assembly (0x04), Connection (0x05), Connection Manager (0x06), TCP/IP Interface (0xF5), Ethernet Link (0xF6), Port (0xF4).
- **Additional coverage:** File Object (0x37), Event Log (0x41), Time Sync (0x43), Modbus (0x44), Symbol (0x6B), Template (0x6C), Program Name / Parameter class (0x64, ambiguous in public docs).
- **Profiles:** Energy (0x4E/0x4F/0x50/0x53), Safety (0x39/0x3A/0x3B/0x3C/0x3D/0x3E/0x3F), Motion Axis (0x42).

### Service labeling (contextual)
Service codes in the 0x4B-0x53 range are context-sensitive and are labeled by class:
- **0x4B:** Execute PCCC (0x67), Energy Start Metering (0x4E), File Initiate Upload (0x37), Modbus Read Discrete Inputs (0x44), Motion Get Axis Attributes List (0x42), Safety Validator Reset Error Counters (0x3A).
- **0x4C:** Read Tag (Logix), Energy Stop Metering (0x4E), File Initiate Download (0x37), Modbus Read Coils (0x44), Motion Set Axis Attributes List (0x42), Template Read (0x6C).
- **0x4D:** Write Tag (Logix), File Initiate Partial Read (0x37), Modbus Read Input Registers (0x44).
- **0x4E:** Forward Close (Connection Manager), Read Modify Write (Logix), File Initiate Partial Write (0x37), Modbus Read Holding Registers (0x44).
- **0x4F:** File Upload Transfer (0x37), Modbus Write Coils (0x44).
- **0x50:** File Download Transfer (0x37), Modbus Write Holding Registers (0x44), Motion Get Motor Test Data (0x42).
- **0x51:** File Clear (0x37), Modbus Passthrough (0x44).
- **0x52/0x53:** Read/Write Tag Fragmented for Logix (0x6B/0x6C), Unconnected Send for Connection Manager (0x06/0x01), Motion Get Inertia Test Data (0x42).
- **0x54:** Forward Open (Connection Manager), Motion Get Hookup Test Data (0x42), Safety Reset (0x39).

### Payload handling notes
- For classes with public payload layouts (Logix Symbol/Template), CIPDIP supports raw payloads and decoding hooks.
- For classes with no public byte layouts (File Object, Time Sync, Event Log, Modbus, Motion, Safety), CIPDIP sends minimal safe probes or accepts raw payloads supplied via `custom_targets`.
- Use `custom_targets` with `request_payload_hex` when a specific payload format is required.

---

## Appendix A — Quick code tables (starter set)

### Encapsulation commands
| Name | Code |
|---|---|
| ListIdentity | 0x0063 |
| RegisterSession | 0x0065 |
| UnregisterSession | 0x0066 |
| SendRRData | 0x006F |
| SendUnitData | 0x0070 |

### Common CIP services
| Name | Code |
|---|---|
| Get_Attributes_All | 0x01 |
| Multiple_Service_Packet | 0x0A |
| Get_Attribute_Single | 0x0E |
| Set_Attribute_Single | 0x10 |

### Common tag services (observed)
| Name | Code |
|---|---|
| Read Tag | 0x4C |
| Write Tag | 0x4D |
| Read Modify Write | 0x4E |
| Read Tag Fragmented | 0x52 |
| Write Tag Fragmented | 0x53 |

---

End of document.
