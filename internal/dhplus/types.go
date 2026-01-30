package dhplus

// DH+ (Data Highway Plus) frame types and constants.
//
// DH+ is a pre-CIP protocol used in Allen-Bradley PLC-2, PLC-3, PLC-5, and
// SLC-500 systems. DH+ frames transported over EtherNet/IP appear as PCCC
// payloads inside CIP Execute PCCC service (0x4B) or as raw data in
// SendUnitData packets from bridged connections.
//
// DH+ frame structure (6-byte header + variable data):
//   DST (1 byte) - Destination node address (0-63 octal, 0-77 decimal)
//   SRC (1 byte) - Source node address (0-63 octal, 0-77 decimal)
//   CMD (1 byte) - Command byte
//   STS (1 byte) - Status byte
//   TNS (2 bytes) - Transaction Number Sequence (little-endian)
//   DATA (variable) - Command-specific payload

// MaxNodeAddress is the maximum valid DH+ node address (octal 77 = decimal 63).
const MaxNodeAddress = 63

// HeaderSize is the fixed DH+ frame header size in bytes.
const HeaderSize = 6

// CommandCode represents a DH+ command byte.
type CommandCode uint8

const (
	// CmdProtectedWrite is a protected write (PLC-2 compatible).
	CmdProtectedWrite CommandCode = 0x00
	// CmdUnprotectedRead performs an unprotected read.
	CmdUnprotectedRead CommandCode = 0x01
	// CmdProtectedRead performs a protected read (PLC-2 compatible).
	CmdProtectedRead CommandCode = 0x02
	// CmdProtectedBitWrite performs a protected bit write.
	CmdProtectedBitWrite CommandCode = 0x05
	// CmdUnprotectedWrite performs an unprotected write.
	CmdUnprotectedWrite CommandCode = 0x08
	// CmdUploadAll performs a processor upload.
	CmdUploadAll CommandCode = 0x0A
	// CmdUpload performs an upload (partial).
	CmdUpload CommandCode = 0x0B
	// CmdDownload performs a download.
	CmdDownload CommandCode = 0x0F
	// CmdDownloadAll performs a complete processor download.
	CmdDownloadAll CommandCode = 0x11
	// CmdTypedRead is a typed logical read (PLC-5/SLC).
	CmdTypedRead CommandCode = 0x68
	// CmdTypedWrite is a typed logical write (PLC-5/SLC).
	CmdTypedWrite CommandCode = 0x67
	// CmdWordRangeRead reads a word range.
	CmdWordRangeRead CommandCode = 0xA1
	// CmdWordRangeWrite writes a word range.
	CmdWordRangeWrite CommandCode = 0xA2
	// CmdDiagnosticStatus reads diagnostic counters.
	CmdDiagnosticStatus CommandCode = 0x06
)

// Frame represents a single DH+ frame.
type Frame struct {
	Dst     uint8       // Destination node (0-63)
	Src     uint8       // Source node (0-63)
	Command CommandCode // Command byte
	Status  uint8       // Status byte (0 for requests)
	TNS     uint16      // Transaction number sequence
	Data    []byte      // Command-specific payload
}

// String returns a human-readable name for the DH+ command.
func (c CommandCode) String() string {
	switch c {
	case CmdProtectedWrite:
		return "Protected_Write"
	case CmdUnprotectedRead:
		return "Unprotected_Read"
	case CmdProtectedRead:
		return "Protected_Read"
	case CmdProtectedBitWrite:
		return "Protected_Bit_Write"
	case CmdUnprotectedWrite:
		return "Unprotected_Write"
	case CmdUploadAll:
		return "Upload_All"
	case CmdUpload:
		return "Upload"
	case CmdDownload:
		return "Download"
	case CmdDownloadAll:
		return "Download_All"
	case CmdTypedRead:
		return "Typed_Read"
	case CmdTypedWrite:
		return "Typed_Write"
	case CmdWordRangeRead:
		return "Word_Range_Read"
	case CmdWordRangeWrite:
		return "Word_Range_Write"
	case CmdDiagnosticStatus:
		return "Diagnostic_Status"
	default:
		return "Unknown"
	}
}

// IsRequest returns true if the status byte indicates a request frame.
func (f Frame) IsRequest() bool {
	return f.Status == 0
}

// IsResponse returns true if the status byte indicates a response frame.
func (f Frame) IsResponse() bool {
	return f.Status != 0 || f.Command&0x40 != 0
}

// IsRead returns true for read commands.
func (c CommandCode) IsRead() bool {
	switch c {
	case CmdUnprotectedRead, CmdProtectedRead, CmdTypedRead, CmdWordRangeRead,
		CmdDiagnosticStatus, CmdUploadAll, CmdUpload:
		return true
	default:
		return false
	}
}

// IsWrite returns true for write commands.
func (c CommandCode) IsWrite() bool {
	switch c {
	case CmdProtectedWrite, CmdProtectedBitWrite, CmdUnprotectedWrite,
		CmdTypedWrite, CmdWordRangeWrite, CmdDownload, CmdDownloadAll:
		return true
	default:
		return false
	}
}
