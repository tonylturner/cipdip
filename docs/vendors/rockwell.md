# Rockwell Automation (Allen‑Bradley) EtherNet/IP / CIP Implementation Notes
_Last updated: 2026-01-01_

## 1) Why Rockwell is “special” for CIP/ENIP stacks
Rockwell Logix controllers are the most common real-world EtherNet/IP endpoints you’ll run into, and they heavily use:
- **Logix “tag services”** (Read/Write Tag, fragmented variants, multi-service bundling)
- **symbolic addressing** and **symbol instance addressing**
- optional legacy **PCCC encapsulation** for compatibility with PLC‑5/SLC style data tables

These behaviors matter for both **client implementations** (what you must encode) and **DPI engines** (what they must correctly parse/classify).

## 2) Vendor fingerprinting (Identity Object + common expectations)
- Vendor ID is commonly documented as Rockwell Automation / Allen‑Bradley (widely observed in Identity Object).
- In practice, Rockwell product lines include ControlLogix, CompactLogix, Point I/O, Flex I/O, MicroLogix (legacy).

Implementation guidance:
- Your emulator should support realistic Identity metadata (vendor/product/revision/serial/product name), but you can still keep it configurable per personality.

## 3) Logix tag services (service codes + key semantics)

Rockwell data access is commonly performed with **tag services** that include:
- Read Tag (service **0x4C**)
- Write Tag (service **0x4D**)
- Read Tag Fragmented (service **0x52**)
- Write Tag Fragmented (service **0x53**)
- Read‑Modify‑Write (RMW) Tag (service **0x4E**)
- Multiple Service Packet (service **0x0A**) to combine requests in one frame

### 3.1 Tag type “service parameter” is required
Rockwell documents that Read/Write/Fragmented/RMW tag services require a **tag type service parameter** identifying the data type:
- atomic tags: **16-bit**
- structured tags: **two 16-bit values** / a 4‑byte sequence including a “structure handle”

It also provides a mapping of data type → tag type value and notes multi-byte values are transmitted low-byte first.  
Source: Logix 5000 Controllers Data Access manual (1756‑PM020I, September 2025).  
Ref: https://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf

### 3.2 BOOL wire semantics
Rockwell notes that when reading a BOOL tag:
- 0 is returned as **0x00**
- 1 is returned as **0xFF**

Source: Logix5000 Data Access manual examples (1756‑PM020D, June 2016).  
Ref: https://support.rockwellautomation.com/cc/okcsFattachCustom/get/1057724_5

### 3.3 Partial-read behavior
The older manual also notes a practical behavior: if all data does not fit in a reply packet, the controller may return:
- a “message too large / partial” style error (documented as **0x06** in that manual) *along with the data that fits*.

Ref: https://support.rockwellautomation.com/cc/okcsFattachCustom/get/1057724_5

**DPI implication:**  
A DPI engine may see “error” status even for a *successful partial read*. For testing, include scenarios that:
- request payload sizes that force fragmentation,
- confirm controller returns “some data + status,”
- verify firewall doesn’t misclassify all “error status” frames as malicious.

## 4) Tag scope + external access (practical access control)
Rockwell documents tag properties:
- Tag names (up to 40 chars)
- Scope: controller (global) vs program (local)
- “External Access” attribute controls whether a controller-scoped tag can be accessed externally; if set to None, it cannot be accessed from outside the controller.

Source: 1756‑PM020I (September 2025).  
Ref: https://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf

**DPI implication:**  
Some failures that look like DPI breakage are actually controller policy (“External Access = None”). In your test plan, always validate that the target tags/assemblies are externally accessible before attributing failures to DPI.

## 5) Legacy compatibility: PCCC encapsulated in EtherNet/IP
Rockwell documents that legacy PCCC commands may be carried in ways including:
- encapsulated inside an EtherNet/IP message (for backward compatibility)

Source: 1756‑PM020I (September 2025), “CIP Over the Controller Serial Port / PCCC Commands” section.  
Ref: https://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf

**DPI implication:**  
Industrial DPI engines sometimes treat PCCC-in-CIP as “odd” or “legacy” traffic and may:
- misclassify it,
- block it,
- or fail to parse it.

If your platform needs broad coverage, plan a dedicated scenario:
- Execute PCCC (legacy) vs native tag services
- Compare firewall classification + logging.

## 6) Recommended implementation checklist (Rockwell-focused)

### Must-have client features
- Tag services (0x4C/0x4D/0x52/0x53/0x4E)
- Multi-service packet bundling (0x0A)
- Symbolic segment encoding for tag paths
- Optional “symbol instance addressing” path forms
- Tag type service parameter encoding

### Must-have emulator features
- Configurable Identity object fields
- Tag type parameter enforcement modes (strict vs permissive)
- Fragmentation behavior:
  - return partial data + status
  - require continuation offset for fragmented reads
- Optional “external access” deny behavior (emulate: access denied vs timeout)

## 7) DPI test scenarios that tend to reveal issues
1. **Mixed reads+writes:** interleave 0x4C and 0x4D with moderate cadence.
2. **Fragmentation:** intentionally exceed “comfortable” payload sizes to force 0x52/0x53.
3. **Multi-service packet:** bundle multiple reads into 0x0A and compare DPI parsing.
4. **Churn:** rapid session + connection open/close cycles.
5. **Legacy path:** optional PCCC encapsulated traffic (if you implement it).

## 8) References (primary/public)
- Logix 5000 Controllers Data Access (1756‑PM020I, Sep 2025):  
  https://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf
- Logix5000 Data Access Programming Manual (1756‑PM020D, Jun 2016):  
  https://support.rockwellautomation.com/cc/okcsFattachCustom/get/1057724_5
- Rockwell EtherNet/IP white paper (older but useful context):  
  https://literature.rockwellautomation.com/idc/groups/literature/documents/wp/enet-wp001_-en-p.pdf
