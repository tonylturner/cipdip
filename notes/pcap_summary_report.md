# PCAP Summary Report

Generated: 2026-01-01T21:29:36-05:00

## CL5000EIP-Change-Date-Attempt.pcap

Source: pcaps\normal\CL5000EIP-Change-Date-Attempt.pcap

```text
PCAP Summary:
  Total packets: 365
  ENIP packets: 267
  Requests: 267
  Responses: 0
  CPF used: 267
  CPF missing: 0
  CIP requests: 0
  CIP responses: 0
  CIP payloads (UCMM): 0
  I/O payloads (connected): 267
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 0
  CIP path size missing: 0

Command Counts:
  SendUnitData: 267
```

## CL5000EIP-Change-Port-Configuration-Attempt.pcap

Source: pcaps\normal\CL5000EIP-Change-Port-Configuration-Attempt.pcap

```text
PCAP Summary:
  Total packets: 3170
  ENIP packets: 16
  Requests: 8
  Responses: 8
  CPF used: 16
  CPF missing: 0
  CIP requests: 8
  CIP responses: 8
  CIP payloads (UCMM): 16
  I/O payloads (connected): 0
  EPATH 16-bit class: 2
  EPATH 16-bit instance: 2
  EPATH 16-bit attribute: 0
  CIP path size used: 8
  CIP path size missing: 0

Command Counts:
  SendRRData: 16

CIP Service Counts:
  Get_Attribute_Single: 5
  Get_Attribute_Single_Response: 5
  Get_Attribute_All: 2
  Get_Attribute_All_Response: 2
  Set_Attribute_Single: 1
  Set_Attribute_Single_Response: 1

Top Paths:
  0x00F5/0x0000/0x0001 (1)
  0x00F5/0x0001/0x0000 (1)
  0x00F6/0x0000/0x0001 (1)
  0x00F6/0x0001/0x0001 (1)
  0x00F6/0x0001/0x0002 (1)
  0x00F6/0x0001/0x0006 (1)
  0x0100/0x0100/0x0000 (1)
  0x3700/0xC800/0x0004 (1)
```

## CL5000EIP-Change-Time-Attempt.pcap

Source: pcaps\normal\CL5000EIP-Change-Time-Attempt.pcap

```text
PCAP Summary:
  Total packets: 728
  ENIP packets: 534
  Requests: 534
  Responses: 0
  CPF used: 534
  CPF missing: 0
  CIP requests: 0
  CIP responses: 0
  CIP payloads (UCMM): 0
  I/O payloads (connected): 534
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 0
  CIP path size missing: 0

Command Counts:
  SendUnitData: 534
```

## CL5000EIP-Control-Protocol-Change-Attempt.pcap

Source: pcaps\normal\CL5000EIP-Control-Protocol-Change-Attempt.pcap

```text
PCAP Summary:
  Total packets: 3597
  ENIP packets: 2270
  Requests: 2239
  Responses: 31
  CPF used: 2270
  CPF missing: 0
  CIP requests: 31
  CIP responses: 31
  CIP payloads (UCMM): 62
  I/O payloads (connected): 2208
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 31
  CIP path size missing: 0

Command Counts:
  SendUnitData: 2208
  SendRRData: 62

CIP Service Counts:
  Unconnected_Send: 21
  Get_Attribute_All_Response: 12
  Get_Attribute_List_Response: 9
  Forward_Close: 5
  Forward_Open: 5
  Forward_Open_Response: 5
  Read_Modify_Write_Response: 5

Embedded CIP Service Counts:
  Get_Attribute_All: 12
  Get_Attribute_List: 9

Top Paths:
  0x0006/0x0001/0x0000 (31)
```

## CL5000EIP-Firmware-Change-Failure.pcap

Source: pcaps\normal\CL5000EIP-Firmware-Change-Failure.pcap

```text
PCAP Summary:
  Total packets: 10576
  ENIP packets: 10500
  Requests: 5250
  Responses: 5250
  CPF used: 10500
  CPF missing: 0
  CIP requests: 5250
  CIP responses: 5250
  CIP payloads (UCMM): 10500
  I/O payloads (connected): 0
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 5250
  CIP path size missing: 0

Command Counts:
  SendRRData: 10500

CIP Service Counts:
  Write_Tag: 5248
  Write_Tag_Response: 5248
  Execute_PCCC_Response: 1
  Unknown(0x4B): 1
  Unknown(0x51): 1
  Unknown(0x51)_Response: 1

Unknown CIP Service Details:
  Unknown(0x51): count=2 responses=1 classes=[0x00A1:1] instances=[0x0001:1] status=[0x08:1]
  Unknown(0x4B): count=1 responses=0 classes=[0x00A1:1] instances=[0x0001:1]

Top Unknown Service+Class Pairs:
  0x4B/0x00A1 (1)
  0x51/0x00A1 (1)

Top Paths:
  0x00A1/0x0001/0x0000 (5250)
```

## CL5000EIP-Firmware-Change.pcap

Source: pcaps\normal\CL5000EIP-Firmware-Change.pcap

```text
PCAP Summary:
  Total packets: 10727
  ENIP packets: 10517
  Requests: 5263
  Responses: 5254
  CPF used: 10509
  CPF missing: 2
  CIP requests: 5258
  CIP responses: 5251
  CIP payloads (UCMM): 10509
  I/O payloads (connected): 0
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 5258
  CIP path size missing: 0

Command Counts:
  SendRRData: 10511
  ListInterfaces: 2
  ListServices: 2
  RegisterSession: 2

CIP Service Counts:
  Write_Tag: 5243
  Write_Tag_Response: 5243
  Get_Attribute_All: 9
  Get_Attribute_Single: 3
  Get_Attribute_Single_Response: 3
  Get_Attribute_All_Response: 2
  Execute_PCCC_Response: 1
  Reset: 1
  Reset_Response: 1
  Unknown(0x4B): 1
  Unknown(0x51): 1
  Unknown(0x51)_Response: 1

Unknown CIP Service Details:
  Unknown(0x51): count=2 responses=1 classes=[0x00A1:1] instances=[0x0001:1] status=[0x08:1]
  Unknown(0x4B): count=1 responses=0 classes=[0x00A1:1] instances=[0x0001:1]

Top Unknown Service+Class Pairs:
  0x4B/0x00A1 (1)
  0x51/0x00A1 (1)

Top Paths:
  0x00A1/0x0001/0x0000 (5245)
  0x0001/0x0001/0x0000 (10)
  0x0001/0x0001/0x0064 (1)
  0x0001/0x0001/0x0065 (1)
  0x0001/0x0001/0x0066 (1)
```

## CL5000EIP-IP-Address-Change-Attempt.pcap

Source: pcaps\normal\CL5000EIP-IP-Address-Change-Attempt.pcap

```text
PCAP Summary:
  Total packets: 4154
  ENIP packets: 1026
  Requests: 513
  Responses: 513
  CPF used: 942
  CPF missing: 4
  CIP requests: 471
  CIP responses: 471
  CIP payloads (UCMM): 942
  I/O payloads (connected): 0
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 471
  CIP path size missing: 0
  Vendor ID: 0x0001
  Product Name: 1756-ENBT/A

Command Counts:
  SendRRData: 946
  ListIdentity: 74
  ListInterfaces: 2
  ListServices: 2
  RegisterSession: 2

CIP Service Counts:
  Unconnected_Send: 440
  Get_Attribute_All_Response: 291
  Get_Attribute_Single_Response: 129
  Unknown(0x52)_Response: 51
  Get_Attribute_All: 31

Embedded CIP Service Counts:
  Get_Attribute_All: 311
  Get_Attribute_Single: 129

Unknown CIP Service Details:
  Unknown(0x52): count=51 responses=51 status=[0x01:51]

Top Paths:
  0x0006/0x0001/0x0000 (440)
  0x0066/0x0001/0x0000 (15)
  0x0001/0x0001/0x0000 (13)
  0x00F4/0x0000/0x0000 (3)
```

## CL5000EIP-Lock-PLC-Attempt.pcap

Source: pcaps\normal\CL5000EIP-Lock-PLC-Attempt.pcap

```text
PCAP Summary:
  Total packets: 1749
  ENIP packets: 294
  Requests: 294
  Responses: 0
  CPF used: 294
  CPF missing: 0
  CIP requests: 0
  CIP responses: 0
  CIP payloads (UCMM): 0
  I/O payloads (connected): 294
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 0
  CIP path size missing: 0

Command Counts:
  SendUnitData: 294
```

## CL5000EIP-Reboot-or-Restart.pcap

Source: pcaps\normal\CL5000EIP-Reboot-or-Restart.pcap

```text
PCAP Summary:
  Total packets: 972
  ENIP packets: 814
  Requests: 784
  Responses: 30
  CPF used: 814
  CPF missing: 0
  CIP requests: 30
  CIP responses: 30
  CIP payloads (UCMM): 60
  I/O payloads (connected): 754
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 30
  CIP path size missing: 0

Command Counts:
  SendUnitData: 754
  SendRRData: 60

CIP Service Counts:
  Unconnected_Send: 21
  Get_Attribute_All_Response: 12
  Get_Attribute_List_Response: 9
  Forward_Open: 5
  Forward_Open_Response: 5
  Forward_Close: 4
  Read_Modify_Write_Response: 4

Embedded CIP Service Counts:
  Get_Attribute_All: 12
  Get_Attribute_List: 9

Top Paths:
  0x0006/0x0001/0x0000 (30)
```

## CL5000EIP-Remote-Mode-Change-Attempt.pcap

Source: pcaps\normal\CL5000EIP-Remote-Mode-Change-Attempt.pcap

```text
PCAP Summary:
  Total packets: 727
  ENIP packets: 301
  Requests: 301
  Responses: 0
  CPF used: 301
  CPF missing: 0
  CIP requests: 0
  CIP responses: 0
  CIP payloads (UCMM): 0
  I/O payloads (connected): 301
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 0
  CIP path size missing: 0

Command Counts:
  SendUnitData: 301
```

## CL5000EIP-Software-Download.pcap

Source: pcaps\normal\CL5000EIP-Software-Download.pcap

```text
PCAP Summary:
  Total packets: 972
  ENIP packets: 814
  Requests: 784
  Responses: 30
  CPF used: 814
  CPF missing: 0
  CIP requests: 30
  CIP responses: 30
  CIP payloads (UCMM): 60
  I/O payloads (connected): 754
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 30
  CIP path size missing: 0

Command Counts:
  SendUnitData: 754
  SendRRData: 60

CIP Service Counts:
  Unconnected_Send: 21
  Get_Attribute_All_Response: 12
  Get_Attribute_List_Response: 9
  Forward_Open: 5
  Forward_Open_Response: 5
  Forward_Close: 4
  Read_Modify_Write_Response: 4

Embedded CIP Service Counts:
  Get_Attribute_All: 12
  Get_Attribute_List: 9

Top Paths:
  0x0006/0x0001/0x0000 (30)
```

## CL5000EIP-Software-Upload.pcap

Source: pcaps\normal\CL5000EIP-Software-Upload.pcap

```text
PCAP Summary:
  Total packets: 923
  ENIP packets: 791
  Requests: 760
  Responses: 31
  CPF used: 791
  CPF missing: 0
  CIP requests: 31
  CIP responses: 31
  CIP payloads (UCMM): 62
  I/O payloads (connected): 729
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 31
  CIP path size missing: 0

Command Counts:
  SendUnitData: 729
  SendRRData: 62

CIP Service Counts:
  Unconnected_Send: 18
  Get_Attribute_All_Response: 11
  Forward_Open: 7
  Forward_Open_Response: 7
  Get_Attribute_List_Response: 7
  Forward_Close: 6
  Read_Modify_Write_Response: 6

Embedded CIP Service Counts:
  Get_Attribute_All: 11
  Get_Attribute_List: 7

Top Paths:
  0x0006/0x0001/0x0000 (31)
```

## CL5000EIP-Unlock-PLC-Attempt.pcap

Source: pcaps\normal\CL5000EIP-Unlock-PLC-Attempt.pcap

```text
PCAP Summary:
  Total packets: 1749
  ENIP packets: 294
  Requests: 294
  Responses: 0
  CPF used: 294
  CPF missing: 0
  CIP requests: 0
  CIP responses: 0
  CIP payloads (UCMM): 0
  I/O payloads (connected): 294
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 0
  CIP path size missing: 0

Command Counts:
  SendUnitData: 294
```

## EthernetIP-CIP.pcap

Source: pcaps\normal\EthernetIP-CIP.pcap

```text
PCAP Summary:
  Total packets: 10880
  ENIP packets: 8799
  Requests: 8580
  Responses: 219
  CPF used: 8799
  CPF missing: 0
  CIP requests: 219
  CIP responses: 219
  CIP payloads (UCMM): 438
  I/O payloads (connected): 8361
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 219
  CIP path size missing: 0

Command Counts:
  SendUnitData: 8361
  SendRRData: 438

CIP Service Counts:
  Get_Attribute_All_Response: 219
  Unconnected_Send: 219

Embedded CIP Service Counts:
  Get_Attribute_All: 219

Top Paths:
  0x0006/0x0001/0x0000 (219)
```

## cip-eth-set-2.pcap

Source: pcaps\normal\cip-eth-set-2.pcap

```text
PCAP Summary:
  Total packets: 1
  ENIP packets: 1
  Requests: 0
  Responses: 1
  CPF used: 1
  CPF missing: 0
  CIP requests: 0
  CIP responses: 1
  CIP payloads (UCMM): 1
  I/O payloads (connected): 0
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 0
  CIP path size missing: 0

Command Counts:
  SendRRData: 1

CIP Service Counts:
  Set_Attribute_Single_Response: 1
```

## cip-multiple-1.pcap

Source: pcaps\normal\cip-multiple-1.pcap

```text
PCAP Summary:
  Total packets: 1
  ENIP packets: 1
  Requests: 1
  Responses: 0
  CPF used: 1
  CPF missing: 0
  CIP requests: 0
  CIP responses: 0
  CIP payloads (UCMM): 0
  I/O payloads (connected): 1
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 0
  CIP path size missing: 0

Command Counts:
  SendUnitData: 1
```

## cip-multiple-2.pcap

Source: pcaps\normal\cip-multiple-2.pcap

```text
PCAP Summary:
  Total packets: 1
  ENIP packets: 1
  Requests: 1
  Responses: 0
  CPF used: 1
  CPF missing: 0
  CIP requests: 0
  CIP responses: 0
  CIP payloads (UCMM): 0
  I/O payloads (connected): 1
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 0
  CIP path size missing: 0

Command Counts:
  SendUnitData: 1
```

## cip_challenge.pcap

Source: pcaps\normal\cip_challenge.pcap

```text
PCAP Summary:
  Total packets: 10880
  ENIP packets: 8799
  Requests: 8580
  Responses: 219
  CPF used: 8799
  CPF missing: 0
  CIP requests: 219
  CIP responses: 219
  CIP payloads (UCMM): 438
  I/O payloads (connected): 8361
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 219
  CIP path size missing: 0

Command Counts:
  SendUnitData: 8361
  SendRRData: 438

CIP Service Counts:
  Get_Attribute_All_Response: 219
  Unconnected_Send: 219

Embedded CIP Service Counts:
  Get_Attribute_All: 219

Top Paths:
  0x0006/0x0001/0x0000 (219)
```

## cip_only.pcap

Source: pcaps\normal\cip_only.pcap

```text
PCAP Summary:
  Total packets: 18798
  ENIP packets: 18798
  Requests: 14159
  Responses: 4639
  CPF used: 18798
  CPF missing: 0
  CIP requests: 4673
  CIP responses: 4639
  CIP payloads (UCMM): 9312
  I/O payloads (connected): 9486
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 4673
  CIP path size missing: 0

Command Counts:
  SendUnitData: 9486
  SendRRData: 9312

CIP Service Counts:
  Execute_PCCC: 4664
  Execute_PCCC_Response: 4631
  Forward_Open: 5
  Forward_Close: 4
  Forward_Open_Response: 4
  Read_Modify_Write_Response: 4

Top Paths:
  0x0067/0x0001/0x0000 (4664)
  0x0006/0x0001/0x0000 (9)
```

## cip_start_plc.pcap

Source: pcaps\normal\cip_start_plc.pcap

```text
PCAP Summary:
  Total packets: 1
  ENIP packets: 1
  Requests: 1
  Responses: 0
  CPF used: 1
  CPF missing: 0
  CIP requests: 0
  CIP responses: 0
  CIP payloads (UCMM): 0
  I/O payloads (connected): 1
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 0
  CIP path size missing: 0

Command Counts:
  SendUnitData: 1
```

## cip_stop_plc.pcap

Source: pcaps\normal\cip_stop_plc.pcap

```text
PCAP Summary:
  Total packets: 1
  ENIP packets: 1
  Requests: 1
  Responses: 0
  CPF used: 1
  CPF missing: 0
  CIP requests: 0
  CIP responses: 0
  CIP payloads (UCMM): 0
  I/O payloads (connected): 1
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 0
  CIP path size missing: 0

Command Counts:
  SendUnitData: 1
```

## cip_unlock_cpu.pcap

Source: pcaps\normal\cip_unlock_cpu.pcap

```text
PCAP Summary:
  Total packets: 1
  ENIP packets: 1
  Requests: 1
  Responses: 0
  CPF used: 1
  CPF missing: 0
  CIP requests: 0
  CIP responses: 0
  CIP payloads (UCMM): 0
  I/O payloads (connected): 1
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 0
  CIP path size missing: 0

Command Counts:
  SendUnitData: 1
```

## enip_test.pcap

Source: pcaps\normal\enip_test.pcap

```text
PCAP Summary:
  Total packets: 11
  ENIP packets: 2
  Requests: 1
  Responses: 1
  CPF used: 0
  CPF missing: 0
  CIP requests: 0
  CIP responses: 0
  CIP payloads (UCMM): 0
  I/O payloads (connected): 0
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 0
  CIP path size missing: 0
  Vendor ID: 0x0001
  Product Name: 1756-ENBT/A

Command Counts:
  ListIdentity: 2
```

## CL5000EIP-Software-Download-Failure.pcap

Source: pcaps\not_cip\CL5000EIP-Software-Download-Failure.pcap

```text
PCAP Summary:
  Total packets: 93
  ENIP packets: 0
  Requests: 0
  Responses: 0
  CPF used: 0
  CPF missing: 0
  CIP requests: 0
  CIP responses: 0
  CIP payloads (UCMM): 0
  I/O payloads (connected): 0
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 0
  CIP path size missing: 0
```

## CL5000EIP-Software-Upload-Failure.pcap

Source: pcaps\not_cip\CL5000EIP-Software-Upload-Failure.pcap

```text
PCAP Summary:
  Total packets: 187
  ENIP packets: 0
  Requests: 0
  Responses: 0
  CPF used: 0
  CPF missing: 0
  CIP requests: 0
  CIP responses: 0
  CIP payloads (UCMM): 0
  I/O payloads (connected): 0
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 0
  CIP path size missing: 0
```

## CL5000EIP-View-Device-Status.pcap

Source: pcaps\not_cip\CL5000EIP-View-Device-Status.pcap

```text
PCAP Summary:
  Total packets: 30
  ENIP packets: 0
  Requests: 0
  Responses: 0
  CPF used: 0
  CPF missing: 0
  CIP requests: 0
  CIP responses: 0
  CIP payloads (UCMM): 0
  I/O payloads (connected): 0
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 0
  CIP path size missing: 0
```

## ENIP.pcap

Source: pcaps\stress\ENIP.pcap

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
  Forward_Open_Response: 29
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

Embedded CIP Service Counts:
  Get_Attribute_All: 254
  Get_Attribute_List: 25

Unknown CIP Service Details:
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

## cip_unclean.pcap

Source: pcaps\stress\cip_unclean.pcap

```text
PCAP Summary:
  Total packets: 40356
  ENIP packets: 38333
  Requests: 28567
  Responses: 9766
  CPF used: 37596
  CPF missing: 0
  CIP requests: 9346
  CIP responses: 9278
  CIP payloads (UCMM): 18624
  I/O payloads (connected): 18972
  EPATH 16-bit class: 0
  EPATH 16-bit instance: 0
  EPATH 16-bit attribute: 0
  CIP path size used: 9346
  CIP path size missing: 0
  Vendor ID: 0x0001
  Product Name: 1766-L32BWAA B/15.00

Command Counts:
  SendUnitData: 18972
  SendRRData: 18624
  ListIdentity: 735
  RegisterSession: 2

CIP Service Counts:
  Execute_PCCC: 9328
  Execute_PCCC_Response: 9262
  Forward_Open: 10
  Forward_Close: 8
  Forward_Open_Response: 8
  Read_Modify_Write_Response: 8

Top Paths:
  0x0067/0x0001/0x0000 (9328)
  0x0006/0x0001/0x0000 (18)
```

