# Schneider Electric (Modicon) EtherNet/IP / CIP Implementation Notes
_Last updated: 2026-01-01_

## 1) Where Schneider shows up in EtherNet/IP environments
Schneider Electric appears in EtherNet/IP networks most often via:
- Modicon PACs (e.g., M580 family)
- dedicated EtherNet/IP communication modules (e.g., BMENOC0301/0311)
- distributed I/O islands / interface modules

In mixed-vendor plants, Schneider endpoints are frequently:
- **scanner** (originator) when the PAC is consuming I/O from adapters
- **adapter** when using “local slave” functionality (publishing I/O to another scanner)

## 2) A concrete anchor document: BMENOC0301/0311 guide (2020)
A publicly available Schneider guide for BMENOC0301/0311 modules contains details useful for:
- implicit messaging (I/O) configuration guidance
- Forward Open counters and diagnostics
- Class 1 (I/O) and Class 3 (explicit) connection tracking
- RPI recommendations tied to CPU task cycle time

Ref (PDF, 09/2020):  
https://www.mroelectric.com/static/app/product/pdfs/BMENOC0311.pdf

## 3) Implicit messaging definition (useful for emulator + DPI docs)
The guide defines implicit messaging as:
- UDP/IP-based **Class 1 connected messaging** for EtherNet/IP
- maintains an open connection for scheduled control data transfer
- messages contain primarily data + a connection identifier (reduced object overhead)

Ref: BMENOC0311 guide glossary (implicit messaging).  
https://www.mroelectric.com/static/app/product/pdfs/BMENOC0311.pdf

**DPI implication:**  
A DPI engine that can only parse explicit CIP services but not track Class 1 connection IDs will often:
- log UDP 2222 as “unknown UDP”
- fail to associate it with a valid Forward Open
- mis-handle jitter/drop conditions.

## 4) Forward Open and connection statistics (diagnostics hooks)
The same guide includes diagnostics counters for Forward Open outcomes, such as:
- number of Forward Open requests received
- rejects due to bad format
- rejects due to lack of resources
- other rejects
It also tracks:
- number of Class 1 connections opened and currently opened
- number of Class 3 (explicit) connections opened and currently opened
- opening errors and timeout errors

Ref: BMENOC0311 guide (Forward Open / CIP connection diagnostics).  
https://www.mroelectric.com/static/app/product/pdfs/BMENOC0311.pdf

**Implementation guidance:**  
If you emulate Schneider-like behavior, these counters suggest a good design:
- keep explicit state for Forward Open parsing outcomes
- classify rejects by reason (format vs resources vs other)
- expose per-connection stats in metrics output

## 5) RPI guidance (practical tuning)
The guide provides a practical recommendation:
- recommended RPI for EtherNet/IP implicit connections ≈ **1/2 of the CPU MAST cycle time**
- if resulting RPI < 25ms, implicit connections may be adversely affected

Ref: BMENOC0311 guide, “EtherNet/IP Implicit Messaging” section.  
https://www.mroelectric.com/static/app/product/pdfs/BMENOC0311.pdf

**DPI implication:**  
When testing strict DPI, keep RPIs realistic (e.g., 20–50ms) and include:
- “too aggressive” RPI tests to see whether the firewall amplifies jitter/drops.

## 6) Max message sizes and capacity notes (planning constraints)
The BMENOC guide includes capacity figures such as:
- scanner number of devices (EtherNet/IP devices and local slaves)
- message size limits for input/output (excluding header)

Ref: BMENOC0311 guide, I/O communication specifications table.  
https://www.mroelectric.com/static/app/product/pdfs/BMENOC0311.pdf

**Implementation guidance:**  
Use these as “realistic ceilings” when you design stress tests:
- avoid impossible payload sizes for adapter emulation
- include “near max” tests to provoke fragmentation and DPI edge cases.

## 7) “Local slave” (adapter role) concept
The guide describes “local slave” as:
- functionality that allows a scanner to take the role of an adapter
- publishes data via implicit messaging connections
- often used for peer-to-peer exchanges between PACs

Ref: BMENOC0311 guide glossary (local slave).  
https://www.mroelectric.com/static/app/product/pdfs/BMENOC0311.pdf

**DPI implication:**  
A firewall may need to classify both:
- PAC as scanner (originator)
- PAC/module as adapter (target)
and apply different policies per direction (write allowance, connection ownership, etc.).

## 8) Recommended Schneider-focused test scenarios
1. **Explicit only (Class 3)**: attribute reads/writes to Assembly instances with moderate cadence.
2. **Implicit only (Class 1)**: Forward Open + UDP 2222 cyclic at realistic RPIs.
3. **RPI edge**: 25ms and below vs 50ms/100ms; measure jitter and timeout behavior.
4. **Resource exhaustion**: open many connections until rejects occur; classify rejects by reason.
5. **Local slave behavior**: emulate Schneider adapter role and validate scanner interoperability.

## 9) References (primary/public)
- BMENOC0301/0311 Ethernet Communications Module – Installation and Configuration Guide (09/2020):  
  https://www.mroelectric.com/static/app/product/pdfs/BMENOC0311.pdf
- Modicon M580 BMENOC product page (overview/availability):  
  https://www.se.com/us/en/product/BMENOC0301/network-module-modicon-m580-ethernet-ip-modbus-tcp/
