package modbus

import (
	"encoding/binary"
	"testing"
)

func TestEncodeDecodeRequestTCP(t *testing.T) {
	req := Request{
		TransactionID: 0x0042,
		UnitID:        0x01,
		Function:      FcReadHoldingRegisters,
		Data:          ReadHoldingRegistersRequest(0x0000, 10),
	}
	frame := EncodeRequestTCP(req)

	decoded, err := DecodeRequestTCP(frame)
	if err != nil {
		t.Fatalf("DecodeRequestTCP: %v", err)
	}
	if decoded.TransactionID != req.TransactionID {
		t.Errorf("TransactionID = 0x%04X, want 0x%04X", decoded.TransactionID, req.TransactionID)
	}
	if decoded.UnitID != req.UnitID {
		t.Errorf("UnitID = %d, want %d", decoded.UnitID, req.UnitID)
	}
	if decoded.Function != req.Function {
		t.Errorf("Function = 0x%02X, want 0x%02X", decoded.Function, req.Function)
	}
	if len(decoded.Data) != len(req.Data) {
		t.Fatalf("Data len = %d, want %d", len(decoded.Data), len(req.Data))
	}
	for i, b := range decoded.Data {
		if b != req.Data[i] {
			t.Errorf("Data[%d] = 0x%02X, want 0x%02X", i, b, req.Data[i])
		}
	}
}

func TestEncodeDecodeResponseTCP(t *testing.T) {
	resp := Response{
		TransactionID: 0x0042,
		UnitID:        0x01,
		Function:      FcReadHoldingRegisters,
		Data:          []byte{0x04, 0x00, 0x0A, 0x00, 0x14}, // byte count + 2 regs
	}
	frame := EncodeResponseTCP(resp)

	decoded, err := DecodeResponseTCP(frame)
	if err != nil {
		t.Fatalf("DecodeResponseTCP: %v", err)
	}
	if decoded.TransactionID != resp.TransactionID {
		t.Errorf("TransactionID = 0x%04X, want 0x%04X", decoded.TransactionID, resp.TransactionID)
	}
	if decoded.Function != resp.Function {
		t.Errorf("Function = 0x%02X, want 0x%02X", decoded.Function, resp.Function)
	}
}

func TestDecodeRequestTCPTooShort(t *testing.T) {
	_, err := DecodeRequestTCP([]byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestDecodeRequestTCPBadProtocolID(t *testing.T) {
	frame := make([]byte, 12)
	binary.BigEndian.PutUint16(frame[0:2], 1)    // txn ID
	binary.BigEndian.PutUint16(frame[2:4], 0x01)  // bad protocol ID
	binary.BigEndian.PutUint16(frame[4:6], 4)     // length
	frame[6] = 0x01                                // unit ID
	frame[7] = byte(FcReadCoils)                   // FC
	binary.BigEndian.PutUint16(frame[8:10], 0)     // start addr
	binary.BigEndian.PutUint16(frame[10:12], 10)   // quantity

	_, err := DecodeRequestTCP(frame)
	if err == nil {
		t.Fatal("expected error for bad protocol ID")
	}
}

func TestExceptionResponse(t *testing.T) {
	frame := EncodeExceptionResponse(0x01, 0x01, FcReadCoils, ExceptionIllegalFunction)

	resp, err := DecodeResponseTCP(frame)
	if err != nil {
		t.Fatalf("DecodeResponseTCP: %v", err)
	}
	if !resp.IsException() {
		t.Error("expected exception response")
	}
	if resp.ExceptionCode() != ExceptionIllegalFunction {
		t.Errorf("ExceptionCode = %d, want %d", resp.ExceptionCode(), ExceptionIllegalFunction)
	}
}

func TestReadCoilsRequestData(t *testing.T) {
	data := ReadCoilsRequest(0x0013, 0x0025)
	if len(data) != 4 {
		t.Fatalf("len = %d, want 4", len(data))
	}
	addr := binary.BigEndian.Uint16(data[0:2])
	qty := binary.BigEndian.Uint16(data[2:4])
	if addr != 0x0013 {
		t.Errorf("addr = 0x%04X, want 0x0013", addr)
	}
	if qty != 0x0025 {
		t.Errorf("qty = 0x%04X, want 0x0025", qty)
	}
}

func TestWriteSingleCoilRequest(t *testing.T) {
	data := WriteSingleCoilRequest(0x00AC, true)
	if len(data) != 4 {
		t.Fatalf("len = %d, want 4", len(data))
	}
	val := binary.BigEndian.Uint16(data[2:4])
	if val != 0xFF00 {
		t.Errorf("coil ON = 0x%04X, want 0xFF00", val)
	}

	dataOff := WriteSingleCoilRequest(0x00AC, false)
	valOff := binary.BigEndian.Uint16(dataOff[2:4])
	if valOff != 0x0000 {
		t.Errorf("coil OFF = 0x%04X, want 0x0000", valOff)
	}
}

func TestWriteSingleRegisterRequest(t *testing.T) {
	data := WriteSingleRegisterRequest(0x0001, 0x0003)
	if len(data) != 4 {
		t.Fatalf("len = %d, want 4", len(data))
	}
	addr := binary.BigEndian.Uint16(data[0:2])
	val := binary.BigEndian.Uint16(data[2:4])
	if addr != 0x0001 {
		t.Errorf("addr = 0x%04X, want 0x0001", addr)
	}
	if val != 0x0003 {
		t.Errorf("val = 0x%04X, want 0x0003", val)
	}
}

func TestWriteMultipleRegistersRequest(t *testing.T) {
	regData := []byte{0x00, 0x0A, 0x01, 0x02}
	data := WriteMultipleRegistersRequest(0x0001, 2, regData)
	if len(data) != 9 { // 2 addr + 2 qty + 1 byte count + 4 data
		t.Fatalf("len = %d, want 9", len(data))
	}
	if data[4] != 4 { // byte count
		t.Errorf("byte count = %d, want 4", data[4])
	}
}

func TestMaskWriteRegisterRequest(t *testing.T) {
	data := MaskWriteRegisterRequest(0x0004, 0x00F2, 0x0025)
	if len(data) != 6 {
		t.Fatalf("len = %d, want 6", len(data))
	}
	andMask := binary.BigEndian.Uint16(data[2:4])
	orMask := binary.BigEndian.Uint16(data[4:6])
	if andMask != 0x00F2 {
		t.Errorf("AND mask = 0x%04X, want 0x00F2", andMask)
	}
	if orMask != 0x0025 {
		t.Errorf("OR mask = 0x%04X, want 0x0025", orMask)
	}
}

func TestDecodeReadRegistersResponse(t *testing.T) {
	// 4 bytes = 2 registers
	data := []byte{0x04, 0x00, 0x0A, 0x00, 0x14}
	regs, err := DecodeReadRegistersResponse(data)
	if err != nil {
		t.Fatalf("DecodeReadRegistersResponse: %v", err)
	}
	if len(regs) != 2 {
		t.Fatalf("len = %d, want 2", len(regs))
	}
	if regs[0] != 0x000A {
		t.Errorf("regs[0] = 0x%04X, want 0x000A", regs[0])
	}
	if regs[1] != 0x0014 {
		t.Errorf("regs[1] = 0x%04X, want 0x0014", regs[1])
	}
}

func TestDecodeReadRegistersResponseOddCount(t *testing.T) {
	data := []byte{0x03, 0x00, 0x0A, 0x00}
	_, err := DecodeReadRegistersResponse(data)
	if err == nil {
		t.Fatal("expected error for odd byte count")
	}
}

func TestDecodeReadCoilsResponse(t *testing.T) {
	data := []byte{0x03, 0xCD, 0x6B, 0x05}
	coils, err := DecodeReadCoilsResponse(data)
	if err != nil {
		t.Fatalf("DecodeReadCoilsResponse: %v", err)
	}
	if len(coils) != 3 {
		t.Fatalf("len = %d, want 3", len(coils))
	}
	if coils[0] != 0xCD {
		t.Errorf("coils[0] = 0x%02X, want 0xCD", coils[0])
	}
}

func TestIsModbusTCP(t *testing.T) {
	// Valid MBAP + FC 0x03
	frame := EncodeRequestTCP(Request{
		TransactionID: 1,
		UnitID:        1,
		Function:      FcReadHoldingRegisters,
		Data:          ReadHoldingRegistersRequest(0, 10),
	})
	if !IsModbusTCP(frame) {
		t.Error("expected IsModbusTCP = true for valid frame")
	}

	// Too short
	if IsModbusTCP([]byte{0x00, 0x01}) {
		t.Error("expected IsModbusTCP = false for short data")
	}

	// Wrong protocol ID
	bad := make([]byte, len(frame))
	copy(bad, frame)
	binary.BigEndian.PutUint16(bad[2:4], 0x0001)
	if IsModbusTCP(bad) {
		t.Error("expected IsModbusTCP = false for bad protocol ID")
	}
}

func TestMBAPHeaderRoundTrip(t *testing.T) {
	h := MBAPHeader{
		TransactionID: 0xABCD,
		ProtocolID:    0x0000,
		Length:        0x0006,
		UnitID:        0xFF,
	}
	encoded := EncodeMBAPHeader(h)
	decoded, err := DecodeMBAPHeader(encoded)
	if err != nil {
		t.Fatalf("DecodeMBAPHeader: %v", err)
	}
	if decoded != h {
		t.Errorf("decoded = %+v, want %+v", decoded, h)
	}
}

func TestCloneBytesIsolation(t *testing.T) {
	orig := []byte{1, 2, 3}
	req := Request{
		TransactionID: 1,
		UnitID:        1,
		Function:      FcReadCoils,
		Data:          orig,
	}
	frame := EncodeRequestTCP(req)
	decoded, err := DecodeRequestTCP(frame)
	if err != nil {
		t.Fatal(err)
	}
	// Modify original - should not affect decoded
	orig[0] = 0xFF
	if decoded.Data[0] == 0xFF {
		t.Error("decoded data was not cloned")
	}
}
