# Siemens EtherNet/IP / CIP Implementation Notes (MultiFieldbus + ET 200eco PN example)
_Last updated: 2026-01-01_

## 1) Context: Siemens and EtherNet/IP
Siemens is historically PROFINET-centric, but Siemens device families that support **EtherNet/IP** exist—often in:
- MultiFieldbus-capable distributed I/O devices
- Drives / motion platforms that offer EtherNet/IP interfaces for interoperability

A very useful public source for Siemens EtherNet/IP behavior is the Siemens documentation portal for **ET 200eco PN MultiFieldbus** devices, which explicitly lists supported CIP objects, attributes, and services.

## 2) Concrete reference: “Supported CIP objects for EtherNet/IP” (ET 200eco PN, V20)
This Siemens doc set provides implementer-grade detail for:
- which CIP objects are supported
- which services are implemented at class and instance level
- what attributes exist and their types/values

Entry point:
https://docs.tia.siemens.cloud/r/simatic_et_200eco_pn_manual_collection_itit_20/function-manuals/communication-function-manuals/multifieldbus/ethernet/ip/supported-cip-objects-for-ethernet/ip

## 3) Identity Object details (Class 0x01)
The Siemens Identity Object page includes:
- **Class code:** 0x01
- **Class services:** 0x01 (Get_Attributes_All), 0x05 (Reset), 0x0E (Get_Attribute_Single)
- **Instance attributes:** 1..7 (vendor, device type, product code, revision, status, serial, product label)
- Vendor example value: **0x04E3**
- Device type example value: **0x000C**
- Serial number note: “last 4 bytes of the MAC address”
- Device status bit definitions and operational notes (including a note that without a valid MultiFieldbus project, the CIP object may time out)

Ref:
https://docs.tia.siemens.cloud/r/simatic_et_200eco_pn_manual_collection_itit_20/function-manuals/communication-function-manuals/multifieldbus/ethernet/ip/supported-cip-objects-for-ethernet/ip/identity-object

**DPI implication:**  
These details are extremely useful for:
- emulator realism (serial generation rule, status bits)
- diagnosing “timeouts” that look like firewall drops but are device state/config issues.

## 4) Assembly Object details (Class 0x04)
The Siemens Assembly Object page includes:
- **Class code:** 0x04
- **Class services:** 0x0E
- **Instance services:** 0x0E (Get_Attribute_Single), 0x10 (Set_Attribute_Single)
- **Number of instances:** 4
- instance attribute 3 used for:
  - Output data (Set)
  - Input data (Retrieve)
  - Config data (Retrieve / reserved)
- Example instance mapping shown with instances like:
  - Output: 768 (0x300), 776 (0x308)
  - Input: 769 (0x301), 777 (0x309)
  - Config: 775 (0x307), 783 (0x30F)

Ref:
https://docs.tia.siemens.cloud/r/simatic_et_200eco_pn_manual_collection_itit_20/function-manuals/communication-function-manuals/multifieldbus/ethernet/ip/supported-cip-objects-for-ethernet/ip/assembly-object

**Implementation guidance:**  
For Siemens-style adapter emulation:
- implement Assembly object with instance-specific input/output/config roles
- enforce access rules (input retrieve-only vs output settable)

## 5) Connection Manager and network objects
The Siemens portal also includes pages for:
- Connection Manager Object
- TCP/IP Interface Object
- EtherNet Link Object
…with attributes and supported services.

These pages can be used to:
- build a richer emulator personality
- validate your client’s attribute reads for “device discovery” beyond ListIdentity

Refs:
- Connection Manager Object:  
  https://docs.tia.siemens.cloud/r/simatic_et_200eco_pn_manual_collection_itit_20/function-manuals/communication-function-manuals/multifieldbus/ethernet/ip/supported-cip-objects-for-ethernet/ip/connection-manager-object
- TCP/IP Interface Object:  
  https://docs.tia.siemens.cloud/r/simatic_et_200eco_pn_manual_collection_itit_20/function-manuals/communication-function-manuals/multifieldbus/ethernet/ip/supported-cip-objects-for-ethernet/ip/tcp/ip-interface-object
- EtherNet Link Object:  
  https://docs.tia.siemens.cloud/r/simatic_et_200eco_pn_manual_collection_itit_20/function-manuals/communication-function-manuals/multifieldbus/ethernet/ip/supported-cip-objects-for-ethernet/ip/ethernet-link-object

## 6) Siemens-focused DPI test implications
1. **Identity + status bits**: read Identity attributes and interpret “configured/owned” bits; validate timeouts vs device state.
2. **Assembly access rules**: attempt writes to retrieve-only input assemblies and confirm correct error handling (not silent drop).
3. **Generic module behavior**: Siemens docs include configuration as generic EtherNet/IP module; emulate minimal expected object set.
4. **Connection manager behavior**: validate Forward Open/Close handling and how DPI engines classify those transitions.

## 7) References (primary/public)
- Supported CIP objects for EtherNet/IP (ET 200eco PN MultiFieldbus, V20):  
  https://docs.tia.siemens.cloud/r/simatic_et_200eco_pn_manual_collection_itit_20/function-manuals/communication-function-manuals/multifieldbus/ethernet/ip/supported-cip-objects-for-ethernet/ip
- Identity Object (details + status bits + serial rule):  
  https://docs.tia.siemens.cloud/r/simatic_et_200eco_pn_manual_collection_itit_20/function-manuals/communication-function-manuals/multifieldbus/ethernet/ip/supported-cip-objects-for-ethernet/ip/identity-object
- Assembly Object (access rules + instance mapping examples):  
  https://docs.tia.siemens.cloud/r/simatic_et_200eco_pn_manual_collection_itit_20/function-manuals/communication-function-manuals/multifieldbus/ethernet/ip/supported-cip-objects-for-ethernet/ip/assembly-object
