package spec

import (
	"fmt"

	"github.com/tonylturner/cipdip/internal/cip/protocol"
)

const (
	connectionManagerClass = CIPClassConnectionManager
	connectionManagerInst  = 0x0001
	pcccObjectClass        = CIPClassPCCCObject
	symbolObjectClass      = CIPClassSymbolObject
	templateObjectClass    = CIPClassTemplateObject
	fileObjectClass        = CIPClassFileObject
)

// LabelService returns a contextual label for a service code.
// Context is required because vendor-specific services are ambiguous without object class context.
func LabelService(service uint8, path protocol.CIPPath, isResponse bool) (string, bool) {
	baseName := ServiceName(protocol.CIPServiceCode(service))
	unknownLabel := fmt.Sprintf("Unknown(0x%02X)", service)
	if baseName == unknownLabel {
		baseName = unknownLabel
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
			baseName = unknownLabel
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
			baseName = unknownLabel
		}
	case 0x50:
		if path.Class == fileObjectClass {
			baseName = "Download_Transfer"
		} else if path.Class == CIPClassModbus {
			baseName = "Modbus_Write_Holding_Registers"
		} else if path.Class == CIPClassMotionAxis {
			baseName = "Motion_Get_Motor_Test_Data"
		} else {
			baseName = unknownLabel
		}
	case 0x51:
		if path.Class == fileObjectClass {
			baseName = "Clear_File"
		} else if path.Class == CIPClassModbus {
			baseName = "Modbus_Passthrough"
		} else {
			baseName = unknownLabel
		}
	case 0x52:
		if path.Class == connectionManagerClass && path.Instance == connectionManagerInst {
			baseName = "Unconnected_Send"
		} else if path.Class == symbolObjectClass || path.Class == templateObjectClass {
			baseName = "Read_Tag_Fragmented"
		} else if path.Class == CIPClassMotionAxis {
			baseName = "Motion_Get_Inertia_Test_Data"
		} else {
			baseName = unknownLabel
		}
	case 0x54:
		if path.Class == connectionManagerClass {
			baseName = "Forward_Open"
		} else if path.Class == CIPClassMotionAxis {
			baseName = "Motion_Get_Hookup_Test_Data"
		} else if path.Class == CIPClassSafetySupervisor {
			baseName = "Safety_Reset"
		} else {
			baseName = unknownLabel
		}
	}

	if isResponse {
		baseName += "_Response"
	}
	return baseName, baseName != unknownLabel && baseName != unknownLabel+"_Response"
}

// IsUnknownServiceLabel reports if the label is an Unknown placeholder.
func IsUnknownServiceLabel(label string) bool {
	return len(label) >= 8 && label[:7] == "Unknown"
}
