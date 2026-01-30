package modbus

// CIP-tunneled Modbus decoder.
//
// Some EtherNet/IP devices expose Modbus registers via CIP class 0x44
// (Modbus Object). The CIP payload contains a raw Modbus PDU
// (function code + data, no MBAP header, no CRC).
//
// This file decodes and encodes Modbus PDUs extracted from CIP
// service requests/responses targeting class 0x44.

import "fmt"

// CIPModbusClass is the CIP class ID for the Modbus Object.
const CIPModbusClass uint16 = 0x44

// DecodeCIPTunnelRequest extracts a Modbus Request from a CIP payload
// targeting class 0x44. The payload is a raw Modbus PDU (FC + data).
// unitID is taken from the CIP instance or provided explicitly.
func DecodeCIPTunnelRequest(payload []byte, unitID uint8) (Request, error) {
	if len(payload) < 1 {
		return Request{}, errTooShort("CIP Modbus payload", len(payload), 1)
	}
	return Request{
		UnitID:   unitID,
		Function: FunctionCode(payload[0]),
		Data:     cloneBytes(payload[1:]),
	}, nil
}

// EncodeCIPTunnelRequest encodes a Modbus Request as a raw PDU suitable
// for embedding in a CIP request payload to class 0x44.
func EncodeCIPTunnelRequest(req Request) []byte {
	buf := make([]byte, 0, 1+len(req.Data))
	buf = append(buf, byte(req.Function))
	buf = append(buf, req.Data...)
	return buf
}

// DecodeCIPTunnelResponse extracts a Modbus Response from a CIP response
// payload originating from class 0x44.
func DecodeCIPTunnelResponse(payload []byte, unitID uint8) (Response, error) {
	if len(payload) < 1 {
		return Response{}, errTooShort("CIP Modbus response payload", len(payload), 1)
	}
	return Response{
		UnitID:   unitID,
		Function: FunctionCode(payload[0]),
		Data:     cloneBytes(payload[1:]),
	}, nil
}

// EncodeCIPTunnelResponse encodes a Modbus Response as a raw PDU suitable
// for embedding in a CIP response payload from class 0x44.
func EncodeCIPTunnelResponse(resp Response) []byte {
	buf := make([]byte, 0, 1+len(resp.Data))
	buf = append(buf, byte(resp.Function))
	buf = append(buf, resp.Data...)
	return buf
}

// IsCIPModbusPayload attempts to detect whether a CIP payload likely
// contains a Modbus PDU. Checks the first byte for a known function code.
func IsCIPModbusPayload(payload []byte) bool {
	if len(payload) < 1 {
		return false
	}
	fc := FunctionCode(payload[0])
	// Check for normal or exception function codes.
	return IsKnownFunction(fc) || IsKnownFunction(fc&0x7F)
}

// DescribeCIPModbus returns a human-readable description of a CIP-tunneled
// Modbus PDU (useful for logging and diagnostics).
func DescribeCIPModbus(payload []byte) string {
	if len(payload) < 1 {
		return "empty Modbus PDU"
	}
	fc := FunctionCode(payload[0])
	isExc := fc&0x80 != 0
	baseFc := fc & 0x7F
	if isExc {
		exc := "unknown"
		if len(payload) >= 2 {
			exc = ExceptionCode(payload[1]).String()
		}
		return fmt.Sprintf("Modbus Exception: %s (%s)", FunctionCode(baseFc).String(), exc)
	}
	return fmt.Sprintf("Modbus %s (%d data bytes)", fc.String(), len(payload)-1)
}
