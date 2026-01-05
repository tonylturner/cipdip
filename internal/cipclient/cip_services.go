package cipclient

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
	fileObjectClass        = 0x0037
)

// labelCIPService returns a contextual label for a service code.
// Context is required because vendor-specific services (notably 0x4B???0x63)
// are ambiguous without object class context.
func labelCIPService(service uint8, path protocol.CIPPath, isResponse bool) (string, bool) {
	baseName, ok := cipServiceNames[service]
	if !ok {
		baseName = fmt.Sprintf("Unknown(0x%02X)", service)
	}

	switch service {
	case 0x4B:
		if path.Class == CIPClassEnergyBase {
			baseName = "Energy_Start_Metering"
		} else if path.Class == fileObjectClass {
			baseName = "Initiate_Upload"
		} else if path.Class == CIPClassModbus {
			baseName = "Modbus_Read_Discrete_Inputs"
		} else if path.Class == CIPClassMotionAxis {
			baseName = "Motion_Get_Axis_Attributes_List"
		} else if path.Class == CIPClassSafetyValidator {
			baseName = "Safety_Reset_Error_Counters"
		} else if path.Class != 0 && path.Class != pcccObjectClass {
			baseName = fmt.Sprintf("Unknown(0x%02X)", service)
		}
	case 0x4C:
		if path.Class == CIPClassEnergyBase {
			baseName = "Energy_Stop_Metering"
		} else if path.Class == fileObjectClass {
			baseName = "Initiate_Download"
		} else if path.Class == CIPClassModbus {
			baseName = "Modbus_Read_Coils"
		} else if path.Class == CIPClassMotionAxis {
			baseName = "Motion_Set_Axis_Attributes_List"
		} else if path.Class == templateObjectClass {
			baseName = "Template_Read"
		}
	case 0x4D:
		if path.Class == fileObjectClass {
			baseName = "Initiate_Partial_Read"
		} else if path.Class == CIPClassModbus {
			baseName = "Modbus_Read_Input_Registers"
		}
	case 0x4E:
		if path.Class == connectionManagerClass {
			baseName = "Forward_Close"
		} else if path.Class == fileObjectClass {
			baseName = "Initiate_Partial_Write"
		} else if path.Class == CIPClassModbus {
			baseName = "Modbus_Read_Holding_Registers"
		}
	case 0x4F:
		if path.Class == fileObjectClass {
			baseName = "Upload_Transfer"
		} else if path.Class == CIPClassModbus {
			baseName = "Modbus_Write_Coils"
		} else {
			baseName = fmt.Sprintf("Unknown(0x%02X)", service)
		}
	case 0x50:
		if path.Class == fileObjectClass {
			baseName = "Download_Transfer"
		} else if path.Class == CIPClassModbus {
			baseName = "Modbus_Write_Holding_Registers"
		} else if path.Class == CIPClassMotionAxis {
			baseName = "Motion_Get_Motor_Test_Data"
		} else {
			baseName = fmt.Sprintf("Unknown(0x%02X)", service)
		}
	case 0x51:
		if path.Class == fileObjectClass {
			baseName = "Clear_File"
		} else if path.Class == CIPClassModbus {
			baseName = "Modbus_Passthrough"
		} else {
			baseName = fmt.Sprintf("Unknown(0x%02X)", service)
		}
	case 0x52:
		if path.Class == connectionManagerClass && path.Instance == connectionManagerInst {
			baseName = "Unconnected_Send"
		} else if path.Class == symbolObjectClass || path.Class == templateObjectClass {
			baseName = "Read_Tag_Fragmented"
		} else if path.Class == CIPClassMotionAxis {
			baseName = "Motion_Get_Inertia_Test_Data"
		} else {
			baseName = fmt.Sprintf("Unknown(0x%02X)", service)
		}
	case 0x54:
		if path.Class == connectionManagerClass {
			baseName = "Forward_Open"
		} else if path.Class == CIPClassMotionAxis {
			baseName = "Motion_Get_Hookup_Test_Data"
		} else if path.Class == CIPClassSafetySupervisor {
			baseName = "Safety_Reset"
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
