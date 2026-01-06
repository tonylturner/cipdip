package spec

import (
	"fmt"

	"github.com/tturner/cipdip/internal/cip/protocol"
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
