# PCAP Summary Report

Generated: 2026-01-11T02:59:07Z

## ENIP.pcap

Source: pcaps/ENIP.pcap

```text
PCAP Summary:
  Total packets: 400688
  ENIP packets: 92869
  Requests: 67647
  Responses: 25222
  CPF used: 91479
  CPF missing: 193
  CIP requests: 24838
  CIP responses: 24730
  CIP payloads (UCMM): 49568
  I/O payloads (connected): 41911
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 24838
  CIP path size missing: 0
  Vendor ID: 0x0001
  Product Name: 1756-ENBT/A

Command Counts:
  SendRRData: 49667
  SendUnitData: 42005
  ListIdentity: 826
  ListServices: 102
  RegisterSession: 96
  ListInterfaces: 93
  UnregisterSession: 80

CIP Service Counts:
  Execute_PCCC: 13992
  Execute_PCCC_Response: 13895
  Write_Tag: 10491
  Write_Tag_Response: 10491
  Unconnected_Send: 279
  Get_Attribute_All_Response: 256
  Forward_Open: 32
  Unknown(0x54)_Response: 29
  Forward_Close: 27
  Read_Modify_Write_Response: 27
  Get_Attribute_List_Response: 25
  Get_Attribute_All: 9
  Get_Attribute_Single: 3
  Get_Attribute_Single_Response: 3
  Unknown(0x4B): 2
  Unknown(0x51): 2
  Unknown(0x51)_Response: 2
  Reset: 1
  Reset_Response: 1
  Set_Attribute_Single_Response: 1

CIP Request Validation (strict): 24838 total, 0 failed

Embedded CIP Service Counts:
  Get_Attribute_All: 254
  Get_Attribute_List: 25

Unknown CIP Service Details:
  Unknown(0x54): count=29 responses=29 status=[0x00:29]
  Unknown(0x51): count=4 responses=2 classes=[0x00A1:2] instances=[0x0001:2] status=[0x08:2]
  Unknown(0x4B): count=2 responses=0 classes=[0x00A1:2] instances=[0x0001:2]

Top Unknown Service+Class Pairs:
  0x4B/0x00A1 (2)
  0x51/0x00A1 (2)

Top Paths:
  0x0067/0x0001/0x0000 (13992)
  0x00A1/0x0001/0x0000 (10495)
  0x0006/0x0001/0x0000 (338)
  0x0001/0x0001/0x0000 (10)
  0x0001/0x0001/0x0064 (1)
  0x0001/0x0001/0x0065 (1)
  0x0001/0x0001/0x0066 (1)
```

