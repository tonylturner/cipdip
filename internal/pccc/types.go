package pccc

// PCCC (Programmable Controller Communication Commands) protocol types.
// Implements the AB DF1/PCCC protocol layer as tunneled through CIP
// Execute PCCC (service 0x4B) to PCCC Object (class 0x67).

// Command represents a PCCC command code (CMD byte).
type Command uint8

const (
	// CmdProtectedWrite is a protected write command (no function code).
	CmdProtectedWrite Command = 0x01
	// CmdUnprotectedRead is an unprotected read command.
	CmdUnprotectedRead Command = 0x02
	// CmdProtectedRead is a protected read command (no function code).
	CmdProtectedRead Command = 0x05
	// CmdUnprotectedWrite is an unprotected write command.
	CmdUnprotectedWrite Command = 0x08
	// CmdExtended is the extended command (uses function codes).
	CmdExtended Command = 0x0F
)

// FunctionCode represents a PCCC function code (FNC byte) used with CmdExtended.
type FunctionCode uint8

// FileType represents a PCCC data file type code.
type FileType uint8

const (
	FileTypeOutput  FileType = 0x82 // O - Output
	FileTypeInput   FileType = 0x83 // I - Input
	FileTypeStatus  FileType = 0x84 // S - Status
	FileTypeBit     FileType = 0x85 // B - Bit/Binary
	FileTypeTimer   FileType = 0x86 // T - Timer
	FileTypeCounter FileType = 0x87 // C - Counter
	FileTypeControl FileType = 0x88 // R - Control
	FileTypeInteger FileType = 0x89 // N - Integer (16-bit)
	FileTypeFloat   FileType = 0x8A // F - Float (32-bit)
	FileTypeString  FileType = 0x8D // ST - String
	FileTypeASCII   FileType = 0x8E // A - ASCII
	FileTypeLong    FileType = 0x91 // L - Long Integer (32-bit)
)

// SubElement represents a named sub-element offset within a structured file type.
type SubElement uint8

const (
	// Timer sub-elements (T file)
	SubTimerControl SubElement = 0 // Control word (EN, TT, DN bits)
	SubTimerPRE     SubElement = 1 // Preset value
	SubTimerACC     SubElement = 2 // Accumulated value

	// Counter sub-elements (C file)
	SubCounterControl SubElement = 0 // Control word (CU, CD, DN, OV, UN bits)
	SubCounterPRE     SubElement = 1 // Preset value
	SubCounterACC     SubElement = 2 // Accumulated value

	// Control sub-elements (R file)
	SubControlControl SubElement = 0 // Control word (EN, EU, DN, EM, ER, UL, IN, FD bits)
	SubControlLEN     SubElement = 1 // Length
	SubControlPOS     SubElement = 2 // Position
)

// Request represents a PCCC request message.
type Request struct {
	Command  Command
	Status   uint8 // Always 0 for requests
	TNS      uint16
	Function FunctionCode // Only present when Command == CmdExtended
	Data     []byte
}

// Response represents a PCCC response message.
type Response struct {
	Command  Command
	Status   uint8
	TNS      uint16
	Function FunctionCode
	ExtSTS   uint8 // Extended status (valid when Status != 0)
	Data     []byte
}

// Address represents a parsed PCCC data table address.
type Address struct {
	FileType    FileType
	FileNumber  uint8
	Element     uint16
	SubElement  uint8
	BitNumber   int8 // -1 if no bit specified
	HasBit      bool
	HasSub      bool
	RawAddress  string // Original parsed string
}

// ByteSize returns the element size in bytes for this file type.
func (ft FileType) ByteSize() int {
	switch ft {
	case FileTypeOutput, FileTypeInput, FileTypeStatus, FileTypeBit,
		FileTypeInteger:
		return 2
	case FileTypeFloat, FileTypeLong:
		return 4
	case FileTypeTimer, FileTypeCounter, FileTypeControl:
		return 6 // 3 words
	case FileTypeString:
		return 84 // 82 data bytes + 2 length bytes
	case FileTypeASCII:
		return 2
	default:
		return 2
	}
}

// String returns the file type letter prefix.
func (ft FileType) String() string {
	switch ft {
	case FileTypeOutput:
		return "O"
	case FileTypeInput:
		return "I"
	case FileTypeStatus:
		return "S"
	case FileTypeBit:
		return "B"
	case FileTypeTimer:
		return "T"
	case FileTypeCounter:
		return "C"
	case FileTypeControl:
		return "R"
	case FileTypeInteger:
		return "N"
	case FileTypeFloat:
		return "F"
	case FileTypeString:
		return "ST"
	case FileTypeASCII:
		return "A"
	case FileTypeLong:
		return "L"
	default:
		return "?"
	}
}

// String returns a human-readable name for the command.
func (c Command) String() string {
	switch c {
	case CmdProtectedWrite:
		return "Protected_Write"
	case CmdUnprotectedRead:
		return "Unprotected_Read"
	case CmdProtectedRead:
		return "Protected_Read"
	case CmdUnprotectedWrite:
		return "Unprotected_Write"
	case CmdExtended:
		return "Extended"
	default:
		return "Unknown"
	}
}
