package modbus

// Modbus function codes.

const (
	// Bit access
	FcReadCoils          FunctionCode = 0x01 // Read 1-2000 coils
	FcReadDiscreteInputs FunctionCode = 0x02 // Read 1-2000 discrete inputs

	// 16-bit register access
	FcReadHoldingRegisters FunctionCode = 0x03 // Read 1-125 holding registers
	FcReadInputRegisters   FunctionCode = 0x04 // Read 1-125 input registers

	// Single write
	FcWriteSingleCoil     FunctionCode = 0x05 // Write a single coil (ON/OFF)
	FcWriteSingleRegister FunctionCode = 0x06 // Write a single holding register

	// Multiple write
	FcWriteMultipleCoils     FunctionCode = 0x0F // Write 1-1968 coils
	FcWriteMultipleRegisters FunctionCode = 0x10 // Write 1-123 holding registers

	// Read-write
	FcMaskWriteRegister         FunctionCode = 0x16 // Mask write to a holding register
	FcReadWriteMultipleRegisters FunctionCode = 0x17 // Read+write in a single transaction

	// Diagnostics
	FcReadExceptionStatus FunctionCode = 0x07
	FcDiagnostics         FunctionCode = 0x08
	FcReportSlaveID       FunctionCode = 0x11
)

// String returns a human-readable name for the function code.
func (fc FunctionCode) String() string {
	switch fc {
	case FcReadCoils:
		return "Read_Coils"
	case FcReadDiscreteInputs:
		return "Read_Discrete_Inputs"
	case FcReadHoldingRegisters:
		return "Read_Holding_Registers"
	case FcReadInputRegisters:
		return "Read_Input_Registers"
	case FcWriteSingleCoil:
		return "Write_Single_Coil"
	case FcWriteSingleRegister:
		return "Write_Single_Register"
	case FcWriteMultipleCoils:
		return "Write_Multiple_Coils"
	case FcWriteMultipleRegisters:
		return "Write_Multiple_Registers"
	case FcMaskWriteRegister:
		return "Mask_Write_Register"
	case FcReadWriteMultipleRegisters:
		return "Read_Write_Multiple_Registers"
	case FcReadExceptionStatus:
		return "Read_Exception_Status"
	case FcDiagnostics:
		return "Diagnostics"
	case FcReportSlaveID:
		return "Report_Slave_ID"
	default:
		return "Unknown"
	}
}

// IsRead returns true for read function codes.
func (fc FunctionCode) IsRead() bool {
	switch fc {
	case FcReadCoils, FcReadDiscreteInputs, FcReadHoldingRegisters,
		FcReadInputRegisters, FcReadExceptionStatus, FcReportSlaveID:
		return true
	default:
		return false
	}
}

// IsWrite returns true for write function codes.
func (fc FunctionCode) IsWrite() bool {
	switch fc {
	case FcWriteSingleCoil, FcWriteSingleRegister,
		FcWriteMultipleCoils, FcWriteMultipleRegisters,
		FcMaskWriteRegister:
		return true
	default:
		return false
	}
}

// IsKnownFunction returns true for recognized Modbus function codes.
func IsKnownFunction(fc FunctionCode) bool {
	switch fc {
	case FcReadCoils, FcReadDiscreteInputs, FcReadHoldingRegisters,
		FcReadInputRegisters, FcWriteSingleCoil, FcWriteSingleRegister,
		FcWriteMultipleCoils, FcWriteMultipleRegisters,
		FcMaskWriteRegister, FcReadWriteMultipleRegisters,
		FcReadExceptionStatus, FcDiagnostics, FcReportSlaveID:
		return true
	default:
		return false
	}
}
