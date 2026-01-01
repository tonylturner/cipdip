# Omron EtherNet/IP / CIP Implementation Notes
_Last updated: 2026-01-01_

## 1) Role of Omron in EtherNet/IP ecosystems
Omron controllers (NJ/NX series) are frequently deployed in mixed‑vendor EtherNet/IP environments, often interoperating with Rockwell scanners and adapters. Omron implementations are generally **spec‑faithful** but less tolerant of malformed or ambiguous traffic.

## 2) Identity and discovery behavior
- Omron devices respond cleanly to ListIdentity.
- Identity Object fields are populated conservatively and consistently.
- Devices often reject operations if the internal project/configuration state is incomplete.

**DPI implication:**  
Timeouts or rejections may reflect device state, not network interference.

## 3) Explicit messaging characteristics
- Heavy reliance on standard CIP services:
  - Get_Attribute_Single (0x0E)
  - Set_Attribute_Single (0x10)
- Less emphasis on Logix‑style tag services.
- Symbolic paths are supported but validated strictly.

## 4) Assembly and I/O usage
- Omron commonly uses Assembly Objects for cyclic data.
- Forward Open parameters are validated tightly:
  - mismatched sizes or unsupported RPIs are rejected.
- RPIs below practical thresholds may be refused.

**DPI implication:**  
Firewalls that alter timing or fragment messages can cause Forward Open failures that appear as “device rejects.”

## 5) Error handling philosophy
- Omron tends to return explicit CIP error statuses rather than silently dropping packets.
- Malformed requests are rejected early.

**Implementation guidance:**  
A strict‑mode emulator is useful to model Omron behavior accurately.

## 6) DPI‑relevant test scenarios
1. Forward Open with marginal RPI values.
2. Assembly‑only I/O with no explicit messaging.
3. Strict EPATH validation tests.
4. Recovery behavior after connection failure.

## 7) Public references
- Omron NJ/NX EtherNet/IP user manuals (publicly available via Omron documentation portal).
