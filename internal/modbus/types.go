package modbus

// Modbus protocol types.
//
// Supports three transport modes:
//   - TCP (MBAP header): Standard Modbus/TCP (port 502)
//   - RTU over TCP: Binary framing with CRC-16 over TCP
//   - ASCII over TCP: ':' delimited hex encoding with LRC over TCP
//
// Also supports CIP-tunneled Modbus (class 0x44) for EtherNet/IP integration.

import "encoding/binary"

// TransportMode identifies the Modbus framing mode.
type TransportMode int

const (
	ModeTCP   TransportMode = iota // MBAP header (standard Modbus/TCP)
	ModeRTU                        // RTU framing with CRC-16
	ModeASCII                      // ASCII framing with LRC
)

// FunctionCode represents a Modbus function code.
type FunctionCode uint8

// MBAPHeader is the Modbus Application Protocol header for TCP mode.
type MBAPHeader struct {
	TransactionID uint16 // Client-assigned ID for request/response correlation
	ProtocolID    uint16 // Always 0x0000 for Modbus
	Length        uint16 // Byte count of UnitID + PDU
	UnitID        uint8  // Slave/unit identifier
}

// MBAPHeaderSize is the fixed MBAP header size (7 bytes).
const MBAPHeaderSize = 7

// Request represents a Modbus request PDU.
type Request struct {
	TransactionID uint16       // From MBAP (TCP) or implicit (RTU/ASCII)
	UnitID        uint8        // Slave address
	Function      FunctionCode // Function code
	Data          []byte       // Function-specific data
}

// Response represents a Modbus response PDU.
type Response struct {
	TransactionID uint16       // Matching request transaction ID
	UnitID        uint8        // Slave address
	Function      FunctionCode // Function code (bit 7 set = exception)
	Data          []byte       // Function-specific data or exception code
}

// ExceptionCode represents a Modbus exception code.
type ExceptionCode uint8

const (
	ExceptionIllegalFunction    ExceptionCode = 0x01
	ExceptionIllegalDataAddress ExceptionCode = 0x02
	ExceptionIllegalDataValue   ExceptionCode = 0x03
	ExceptionSlaveDeviceFailure ExceptionCode = 0x04
	ExceptionAcknowledge        ExceptionCode = 0x05
	ExceptionSlaveDeviceBusy    ExceptionCode = 0x06
	ExceptionGatewayPathUnavail ExceptionCode = 0x0A
	ExceptionGatewayTargetFail  ExceptionCode = 0x0B
)

// IsException returns true if the response function code indicates an exception.
func (r Response) IsException() bool {
	return r.Function&0x80 != 0
}

// ExceptionCode returns the exception code from an exception response.
func (r Response) ExceptionCode() ExceptionCode {
	if r.IsException() && len(r.Data) > 0 {
		return ExceptionCode(r.Data[0])
	}
	return 0
}

// EncodeMBAPHeader encodes an MBAP header into 7 bytes.
func EncodeMBAPHeader(h MBAPHeader) []byte {
	buf := make([]byte, MBAPHeaderSize)
	binary.BigEndian.PutUint16(buf[0:2], h.TransactionID)
	binary.BigEndian.PutUint16(buf[2:4], h.ProtocolID)
	binary.BigEndian.PutUint16(buf[4:6], h.Length)
	buf[6] = h.UnitID
	return buf
}

// DecodeMBAPHeader decodes an MBAP header from bytes.
func DecodeMBAPHeader(data []byte) (MBAPHeader, error) {
	if len(data) < MBAPHeaderSize {
		return MBAPHeader{}, errTooShort("MBAP header", len(data), MBAPHeaderSize)
	}
	return MBAPHeader{
		TransactionID: binary.BigEndian.Uint16(data[0:2]),
		ProtocolID:    binary.BigEndian.Uint16(data[2:4]),
		Length:        binary.BigEndian.Uint16(data[4:6]),
		UnitID:        data[6],
	}, nil
}

// String returns a human-readable label for the transport mode.
func (m TransportMode) String() string {
	switch m {
	case ModeTCP:
		return "TCP"
	case ModeRTU:
		return "RTU"
	case ModeASCII:
		return "ASCII"
	default:
		return "Unknown"
	}
}

// String returns a human-readable name for the exception code.
func (e ExceptionCode) String() string {
	switch e {
	case ExceptionIllegalFunction:
		return "Illegal_Function"
	case ExceptionIllegalDataAddress:
		return "Illegal_Data_Address"
	case ExceptionIllegalDataValue:
		return "Illegal_Data_Value"
	case ExceptionSlaveDeviceFailure:
		return "Slave_Device_Failure"
	case ExceptionAcknowledge:
		return "Acknowledge"
	case ExceptionSlaveDeviceBusy:
		return "Slave_Device_Busy"
	case ExceptionGatewayPathUnavail:
		return "Gateway_Path_Unavailable"
	case ExceptionGatewayTargetFail:
		return "Gateway_Target_Failed"
	default:
		return "Unknown"
	}
}
