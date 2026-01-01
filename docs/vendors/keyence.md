# Keyence EtherNet/IP / CIP Implementation Notes
_Last updated: 2026-01-01_

## 1) Why Keyence matters
Keyence devices are extremely common in discrete manufacturing and inspection systems. Their EtherNet/IP implementations are typically **minimal, fast, and performance‑sensitive**.

## 2) Identity and discovery
- Clean ListIdentity responses with minimal optional fields.
- Product identity is consistent but sparse.

**DPI implication:**  
Keyence traffic is a good baseline for “clean” ENIP classification.

## 3) Explicit messaging patterns
- High‑frequency polling using simple CIP services.
- Minimal service diversity; avoids complex or fragmented operations.
- Low tolerance for added latency.

**DPI implication:**  
Firewalls that add measurable latency or jitter can cause observable performance degradation even without packet loss.

## 4) I/O behavior
- Cyclic I/O traffic is often configured at aggressive RPIs.
- Devices expect consistent timing.

**Implementation guidance:**  
Use Keyence‑style behavior to test jitter amplification and scheduling artifacts introduced by DPI.

## 5) Error and recovery behavior
- Devices may fail fast rather than retry extensively.
- Connection churn is common during startup or reconfiguration.

## 6) DPI‑focused test scenarios
1. High‑frequency explicit reads (stress mode).
2. Aggressive RPI cyclic I/O.
3. Latency injection without packet loss.
4. Rapid connect/disconnect cycles.

## 7) Public references
- Keyence EtherNet/IP communication manuals (available via Keyence support portal).
