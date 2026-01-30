package pccc

// PCCC function codes used with CmdExtended (CMD 0x0F).

const (
	// FncEcho requests an echo response from the processor.
	FncEcho FunctionCode = 0x06

	// FncSetCPUMode changes the processor operating mode.
	FncSetCPUMode FunctionCode = 0x3A

	// FncTypedRead performs a typed logical read (most common read).
	// Data: byte_count(1), file_number(1), file_type(1), element(1), [sub_element(1)]
	FncTypedRead FunctionCode = 0x68

	// FncTypedWrite performs a typed logical write (most common write).
	// Data: byte_count(1), file_number(1), file_type(1), element(1), [sub_element(1)], data...
	FncTypedWrite FunctionCode = 0x67

	// FncTypedRead3Addr performs a protected typed logical read with 3 address fields.
	// Uses byte_size, file_number, file_type, element_number, sub_element_number.
	FncTypedRead3Addr FunctionCode = 0xA2

	// FncTypedWrite3Addr performs a protected typed logical write with 3 address fields.
	FncTypedWrite3Addr FunctionCode = 0xAB

	// FncWordRangeRead reads a range of words from a file.
	FncWordRangeRead FunctionCode = 0x01

	// FncWordRangeWrite writes a range of words to a file.
	FncWordRangeWrite FunctionCode = 0x00

	// FncBitWrite performs a protected bit write operation.
	FncBitWrite FunctionCode = 0x26

	// FncBitRead performs a protected bit read operation.
	FncBitRead FunctionCode = 0x29

	// FncReadModifyWrite reads, modifies, and writes bits in a single operation.
	FncReadModifyWrite FunctionCode = 0x26

	// FncDiagnosticRead reads diagnostic counters.
	FncDiagnosticRead FunctionCode = 0x41

	// FncChangeMode switches between program/run/test modes.
	// Mode values: 0x01=Program, 0x06=Run, 0x07=Test
	FncChangeMode FunctionCode = 0x80

	// FncReadSLCFileInfo reads SLC file directory information.
	FncReadSLCFileInfo FunctionCode = 0x87
)

// String returns a human-readable name for the function code.
func (f FunctionCode) String() string {
	switch f {
	case FncEcho:
		return "Echo"
	case FncSetCPUMode:
		return "Set_CPU_Mode"
	case FncTypedRead:
		return "Typed_Read"
	case FncTypedWrite:
		return "Typed_Write"
	case FncTypedRead3Addr:
		return "Typed_Read_3Addr"
	case FncTypedWrite3Addr:
		return "Typed_Write_3Addr"
	case FncWordRangeRead:
		return "Word_Range_Read"
	case FncWordRangeWrite:
		return "Word_Range_Write"
	case FncBitRead:
		return "Bit_Read"
	case FncBitWrite:
		return "Bit_Write"
	case FncDiagnosticRead:
		return "Diagnostic_Read"
	case FncChangeMode:
		return "Change_Mode"
	case FncReadSLCFileInfo:
		return "Read_SLC_File_Info"
	default:
		return "Unknown"
	}
}

// IsRead returns true if the function code is a read operation.
func (f FunctionCode) IsRead() bool {
	switch f {
	case FncTypedRead, FncTypedRead3Addr, FncWordRangeRead, FncBitRead,
		FncDiagnosticRead, FncReadSLCFileInfo, FncEcho:
		return true
	default:
		return false
	}
}

// IsWrite returns true if the function code is a write operation.
func (f FunctionCode) IsWrite() bool {
	switch f {
	case FncTypedWrite, FncTypedWrite3Addr, FncWordRangeWrite, FncBitWrite:
		return true
	default:
		return false
	}
}

// HasFunctionCode returns true if the command uses a function code byte.
func (c Command) HasFunctionCode() bool {
	return c == CmdExtended
}
