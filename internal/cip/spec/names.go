package spec

import (
	"fmt"

	"github.com/tonylturner/cipdip/internal/cip/protocol"
)

var cipServiceNames = map[uint8]string{
	0x01: "Get_Attribute_All",
	0x02: "Set_Attribute_All",
	0x03: "Get_Attribute_List",
	0x04: "Set_Attribute_List",
	0x05: "Reset",
	0x06: "Start",
	0x07: "Stop",
	0x08: "Create",
	0x09: "Delete",
	0x0A: "Multiple_Service_Packet",
	0x0D: "Apply_Attributes",
	0x0E: "Get_Attribute_Single",
	0x10: "Set_Attribute_Single",
	0x11: "Find_Next_Object_Instance",
	0x14: "Error_Response",
	0x15: "Restore",
	0x16: "Save",
	0x17: "No_Op",
	0x18: "Get_Member",
	0x19: "Set_Member",
	0x1A: "Insert_Member",
	0x1B: "Remove_Member",
	0x1C: "Group_Sync",
	0x4B: "Execute_PCCC",
	0x4C: "Read_Tag",
	0x4D: "Write_Tag",
	0x4E: "Read_Modify_Write",
	0x4F: "Upload_Transfer",
	0x50: "Download_Transfer",
	0x51: "Clear_File",
	0x52: "Unconnected_Send",
	0x53: "Write_Tag_Fragmented",
	0x54: "Forward_Open",
	0x55: "Get_Instance_Attribute_List",
	0x56: "Get_Connection_Data",
	0x57: "Search_Connection_Data",
	0x5A: "Get_Connection_Owner",
	0x5B: "Large_Forward_Open",
}

// ServiceName returns a default display name for a CIP service code.
func ServiceName(code protocol.CIPServiceCode) string {
	if name, ok := cipServiceNames[uint8(code)]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%02X)", uint8(code))
}

// IsKnownService returns true when a service code is recognized.
func IsKnownService(code protocol.CIPServiceCode) bool {
	_, ok := cipServiceNames[uint8(code)]
	return ok
}

var cipClassNames = map[uint16]string{
	0x01: "Identity",
	0x02: "Message_Router",
	0x03: "DeviceNet",
	0x04: "Assembly",
	0x05: "Connection",
	0x06: "Connection_Manager",
	0x07: "Register",
	0x08: "Discrete_Input",
	0x09: "Discrete_Output",
	0x0A: "Analog_Input",
	0x0B: "Analog_Output",
	0x0F: "Parameter",
	0x10: "Parameter_Group",
	0x37: "File",
	0x39: "Safety_Supervisor",
	0x3A: "Safety_Validator",
	0x42: "Motion_Axis",
	0x43: "Time_Sync",
	0x44: "Modbus",
	0x4E: "Energy_Base",
	0x4F: "Energy_Electrical",
	0x50: "Energy_Non_Electrical",
	0x67: "PCCC",
	0x6B: "Symbol",
	0x6C: "Template",
	0xF4: "Port",
	0xF5: "TCP_IP_Interface",
	0xF6: "Ethernet_Link",
}

// ClassName returns a display name for a CIP class code.
func ClassName(code uint16) string {
	if name, ok := cipClassNames[code]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%02X)", code)
}

// IsKnownClass returns true when a class code is recognized.
func IsKnownClass(code uint16) bool {
	_, ok := cipClassNames[code]
	return ok
}
