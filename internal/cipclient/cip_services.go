package cipclient

import "fmt"

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
	0x53: "Write_Tag_Fragmented",
	0x55: "Get_Instance_Attribute_List",
	0x56: "Get_Connection_Data",
	0x57: "Search_Connection_Data",
	0x5A: "Get_Connection_Owner",
	0x5B: "Large_Forward_Open",
	0x54: "Forward_Open",
}

const (
	connectionManagerClass = 0x0006
	connectionManagerInst  = 0x0001
	pcccObjectClass        = 0x0067
	symbolObjectClass      = 0x006B
	templateObjectClass    = 0x006C
)

// labelCIPService returns a contextual label for a service code.
// Context is required because vendor-specific services (notably 0x4B–0x63)
// are ambiguous without object class context.
func labelCIPService(service uint8, path CIPPath, isResponse bool) (string, bool) {
	baseName, ok := cipServiceNames[service]
	if !ok {
		baseName = fmt.Sprintf("Unknown(0x%02X)", service)
	}

	switch service {
	case 0x4B:
		if path.Class != 0 && path.Class != pcccObjectClass {
			baseName = fmt.Sprintf("Unknown(0x%02X)", service)
		}
	case 0x4E:
		if path.Class == connectionManagerClass {
			baseName = "Forward_Close"
		}
	case 0x52:
		if path.Class == connectionManagerClass && path.Instance == connectionManagerInst {
			baseName = "Unconnected_Send"
		} else if path.Class == symbolObjectClass || path.Class == templateObjectClass {
			baseName = "Read_Tag_Fragmented"
		} else {
			baseName = fmt.Sprintf("Unknown(0x%02X)", service)
		}
	}

	if isResponse {
		baseName += "_Response"
	}
	return baseName, baseName != fmt.Sprintf("Unknown(0x%02X)", service) && baseName != fmt.Sprintf("Unknown(0x%02X)_Response", service)
}

func isUnknownServiceLabel(label string) bool {
	return len(label) >= 8 && label[:7] == "Unknown"
}
