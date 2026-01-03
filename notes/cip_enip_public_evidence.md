# CIP / EtherNet-IP (ENIP) Public Evidence Pack
_Last updated: 2026-01-01_

This document consolidates **publicly accessible evidence** (non–member-only) that supports
ODVA compliance claims for a **CIP / EtherNet-IP DPI test harness**.

**Purpose**
- Provide verifiable sources Codex can rely on when implementing or validating protocol behavior.
- Clearly distinguish **explicitly documented behavior** from **behavior inferred from dissector implementations**.
- Avoid reliance on ODVA member-only specification volumes.

---

## 1. ENIP Encapsulation Header (24-byte structure)

### Claim
- EtherNet/IP encapsulation header is **24 bytes**, fixed-length.
- Fields are encoded in **little-endian** order.

### Evidence (explicit documentation)

> “The EtherNet/IP header is a **24 byte fixed length header** … and is **ordered as little-endian** …”
>
> — *Securing EtherNet/IP Control Systems using Deep Packet Inspection*, ODVA Conference Paper (2014)

> “Data format for the Encapsulation Protocol is **Little-Endian**.”
>
> — *EtherNet/IP Quick Start for Vendors (PUB00213R0)*

### Field presence corroboration (dissector-based)
Wireshark exposes encapsulation header fields:
- command (uint16)
- length (uint16)
- session handle
- status
- sender context (8 bytes)
- options (uint32)

⚠ **Note:** Wireshark confirms field presence and type; byte offsets are inferred from standard usage,
not described textually in Wireshark docs.

**Sources**
- https://www.odva.org/wp-content/uploads/2022/06/2014_ODVA_Conference_Byres_Schweigert_Thomas_Securing_EtherNetIP_with_DPI_FINAL.pdf
- https://www.odva.org/wp-content/uploads/2020/05/PUB00213R0_EtherNetIP_Developers_Guide.pdf
- https://www.wireshark.org/docs/dfref/e/enip.html

---

## 2. CIP EPATH Encoding (8-bit vs 16-bit segments)

### Claim
- CIP supports **8-bit and 16-bit Class / Instance / Attribute segments**.
- Multi-byte values are encoded **low byte first (little-endian)**.
- Symbolic paths use **ANSI Extended Symbol segments**.

### Evidence (explicit documentation)

From *Logix 5000 Controllers Data Access* manual:

> “Representation … (**low byte first**).”

> “8-bit Class ID = 0x20 …  
> 16-bit Class ID = 0x21 00 Low High”

> “8-bit Instance ID = 0x24 …  
> 16-bit Instance ID = 0x25 00 Low High”

> “8-bit Attribute ID = 0x30 …  
> 16-bit Attribute ID = 0x31 00 Low High”

> “ANSI Extended Symbolic segment = 0x91 …”

### Scope note
This is a **Rockwell-published** manual, but the EPATH encoding rules are CIP-generic and widely implemented.

**Sources**
- https://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf

---

## 3. Forward Open / Forward Close and RPI Units

### Claim
- Forward Open negotiates connection parameters including RPIs.
- **RPI values are expressed in microseconds**.

### Evidence (explicit documentation)

From *Hilscher EtherNet/IP Adapter Protocol API*:

> “Requested Packet Interval … is specified in **units of microseconds**.”

(Statement applies independently to O→T and T→O RPIs.)

### Field presence and order (inferred)
Wireshark CIP Connection Manager dissector exposes parsed fields:
- O→T Connection ID
- T→O Connection ID
- O→T RPI
- T→O RPI
- timeout multiplier
- connection path

⚠ **Inference note:** Exact byte order of Forward Open fields is inferred from dissector behavior,
not described textually in public prose.

**Sources**
- https://www.hilscher.com/fileadmin/cms_upload/de/Resources/pdf/EtherNetIP_Adapter_V3_Protocol_API_04_EN.pdf
- https://www.wireshark.org/docs/dfref/c/cipcm.html
- https://www.odva.org/wp-content/uploads/2020/06/PUB00123R1_Common-Industrial_Protocol_and_Family_of_CIP_Networks.pdf

---

## 4. CPF Framing in SendRRData / SendUnitData

### Claim
- SendRRData and SendUnitData carry CIP messages using **Common Packet Format (CPF)**.
- CPF includes item count and one or more typed items:
  - UCMM (unconnected)
  - Connected Address Item (connected messaging)

### Evidence (dissector-based, public)

Wireshark exposes CPF fields:
- `enip.cpf.itemcount`
- `enip.cpf.typeid`
- `enip.cpf.length`
- `enip.cpf.data`

It further distinguishes:
- UCMM items (`enip.cpf.ucmm.*`)
- Connected Address Item (`enip.cpf.cai.connid`)

From ODVA public paper:

> “The most important commands are **SendRRData and SendUnitData**…  
> **All CIP messaging lies on top** of these commands.”

⚠ **Inference note:** CPF layout is confirmed via dissector field parsing; public prose does not
describe the byte-by-byte layout.

**Sources**
- https://www.wireshark.org/docs/dfref/e/enip.html
- https://www.odva.org/wp-content/uploads/2022/06/2014_ODVA_Conference_Byres_Schweigert_Thomas_Securing_EtherNetIP_with_DPI_FINAL.pdf

---

## 5. ListIdentity and UDP Discovery (UDP 44818)

### Claim
- ListIdentity uses **UDP port 44818**.
- Requests may be sent via **broadcast or unicast**.
- Responses include Identity Object fields.

### Evidence (explicit documentation)

From *EtherNet/IP Quick Start for Vendors*:

> “Encapsulation Protocol uses **TCP/UDP Port 44818**…  
> example … **List_Identity Command**.”

From Cisco Cyber Vision Active Discovery annex:

> “The List Identity request (0x00063) is sent to the **IPv4 broadcast address**  
> or directly to an **IPv4 address**.”

Wireshark ListIdentity response fields include:
- vendor ID
- device type
- product code
- revision
- status
- serial number
- product name
- device state

**Sources**
- https://www.odva.org/wp-content/uploads/2020/05/PUB00213R0_EtherNetIP_Developers_Guide.pdf
- https://www.cisco.com/c/en/us/td/docs/security/cyber_vision/publications/Active-Discovery/b_Cisco_cyber_vision_active_discovery_configuration/m_annex_active_discovery_protocols.pdf
- https://www.wireshark.org/docs/dfref/e/enip.html

---

## Summary: Evidence Classification

| Topic | Status |
|-----|------|
| ENIP header length + endianness | Explicitly documented |
| CIP EPATH 8/16-bit segments | Explicitly documented |
| RPI units (µs) | Explicitly documented |
| Forward Open field order | Inferred from dissector |
| CPF framing | Inferred from dissector |
| ListIdentity structure + port | Explicitly documented |

---

## Usage Guidance for Codex

When implementing or validating:
- Treat **explicitly documented items** as normative.
- Treat **dissector-inferred items** as de-facto interoperable behavior,
  validated across real devices and tools.
- Record inference vs documentation status in code comments where applicable.

---

End of document.
