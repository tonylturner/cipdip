package modbus

import (
	"encoding/binary"
	"testing"
)

func newTestStore() *DataStore {
	cfg := DataStoreConfig{
		CoilCount:            100,
		DiscreteInputCount:   100,
		InputRegisterCount:   100,
		HoldingRegisterCount: 100,
	}
	return NewDataStore(cfg)
}

func TestReadHoldingRegisters(t *testing.T) {
	ds := newTestStore()
	_ = ds.SetHoldingRegister(0, 0x000A)
	_ = ds.SetHoldingRegister(1, 0x0014)

	req := Request{
		TransactionID: 1,
		UnitID:        1,
		Function:      FcReadHoldingRegisters,
		Data:          ReadHoldingRegistersRequest(0, 2),
	}
	resp := ds.HandleRequest(req)
	if resp.IsException() {
		t.Fatalf("unexpected exception: %v", resp.ExceptionCode())
	}

	regs, err := DecodeReadRegistersResponse(resp.Data)
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

func TestReadInputRegisters(t *testing.T) {
	ds := newTestStore()
	_ = ds.SetInputRegister(5, 0x1234)

	req := Request{
		TransactionID: 1,
		UnitID:        1,
		Function:      FcReadInputRegisters,
		Data:          ReadInputRegistersRequest(5, 1),
	}
	resp := ds.HandleRequest(req)
	if resp.IsException() {
		t.Fatalf("unexpected exception: %v", resp.ExceptionCode())
	}

	regs, err := DecodeReadRegistersResponse(resp.Data)
	if err != nil {
		t.Fatal(err)
	}
	if regs[0] != 0x1234 {
		t.Errorf("regs[0] = 0x%04X, want 0x1234", regs[0])
	}
}

func TestReadCoils(t *testing.T) {
	ds := newTestStore()
	_ = ds.SetCoil(0, true)
	_ = ds.SetCoil(1, false)
	_ = ds.SetCoil(2, true)
	_ = ds.SetCoil(7, true)

	req := Request{
		TransactionID: 1,
		UnitID:        1,
		Function:      FcReadCoils,
		Data:          ReadCoilsRequest(0, 8),
	}
	resp := ds.HandleRequest(req)
	if resp.IsException() {
		t.Fatalf("unexpected exception: %v", resp.ExceptionCode())
	}
	coils, err := DecodeReadCoilsResponse(resp.Data)
	if err != nil {
		t.Fatal(err)
	}
	// Coils 0,2,7 = bits 0,2,7 = 0b10000101 = 0x85
	if coils[0] != 0x85 {
		t.Errorf("coils[0] = 0x%02X, want 0x85", coils[0])
	}
}

func TestReadDiscreteInputs(t *testing.T) {
	ds := newTestStore()
	_ = ds.SetDiscreteInput(0, true)
	_ = ds.SetDiscreteInput(3, true)

	req := Request{
		TransactionID: 1,
		UnitID:        1,
		Function:      FcReadDiscreteInputs,
		Data:          ReadDiscreteInputsRequest(0, 8),
	}
	resp := ds.HandleRequest(req)
	if resp.IsException() {
		t.Fatalf("unexpected exception: %v", resp.ExceptionCode())
	}
	data, err := DecodeReadCoilsResponse(resp.Data)
	if err != nil {
		t.Fatal(err)
	}
	// bits 0,3 = 0b00001001 = 0x09
	if data[0] != 0x09 {
		t.Errorf("data[0] = 0x%02X, want 0x09", data[0])
	}
}

func TestWriteSingleCoil(t *testing.T) {
	ds := newTestStore()

	req := Request{
		TransactionID: 1,
		UnitID:        1,
		Function:      FcWriteSingleCoil,
		Data:          WriteSingleCoilRequest(5, true),
	}
	resp := ds.HandleRequest(req)
	if resp.IsException() {
		t.Fatalf("unexpected exception: %v", resp.ExceptionCode())
	}

	val, _ := ds.GetCoil(5)
	if !val {
		t.Error("coil 5 should be true")
	}

	// Write OFF
	req.Data = WriteSingleCoilRequest(5, false)
	resp = ds.HandleRequest(req)
	if resp.IsException() {
		t.Fatalf("unexpected exception: %v", resp.ExceptionCode())
	}
	val, _ = ds.GetCoil(5)
	if val {
		t.Error("coil 5 should be false")
	}
}

func TestWriteSingleCoilBadValue(t *testing.T) {
	ds := newTestStore()

	badData := make([]byte, 4)
	binary.BigEndian.PutUint16(badData[0:2], 0)
	binary.BigEndian.PutUint16(badData[2:4], 0x1234) // invalid: not 0x0000 or 0xFF00
	req := Request{
		TransactionID: 1,
		UnitID:        1,
		Function:      FcWriteSingleCoil,
		Data:          badData,
	}
	resp := ds.HandleRequest(req)
	if !resp.IsException() {
		t.Fatal("expected exception for bad coil value")
	}
	if resp.ExceptionCode() != ExceptionIllegalDataValue {
		t.Errorf("exception = %v, want IllegalDataValue", resp.ExceptionCode())
	}
}

func TestWriteSingleRegister(t *testing.T) {
	ds := newTestStore()

	req := Request{
		TransactionID: 1,
		UnitID:        1,
		Function:      FcWriteSingleRegister,
		Data:          WriteSingleRegisterRequest(10, 0xABCD),
	}
	resp := ds.HandleRequest(req)
	if resp.IsException() {
		t.Fatalf("unexpected exception: %v", resp.ExceptionCode())
	}

	val, _ := ds.GetHoldingRegister(10)
	if val != 0xABCD {
		t.Errorf("register 10 = 0x%04X, want 0xABCD", val)
	}
}

func TestWriteMultipleRegisters(t *testing.T) {
	ds := newTestStore()

	values := make([]byte, 4)
	binary.BigEndian.PutUint16(values[0:2], 0x000A)
	binary.BigEndian.PutUint16(values[2:4], 0x0102)

	req := Request{
		TransactionID: 1,
		UnitID:        1,
		Function:      FcWriteMultipleRegisters,
		Data:          WriteMultipleRegistersRequest(0, 2, values),
	}
	resp := ds.HandleRequest(req)
	if resp.IsException() {
		t.Fatalf("unexpected exception: %v", resp.ExceptionCode())
	}

	v0, _ := ds.GetHoldingRegister(0)
	v1, _ := ds.GetHoldingRegister(1)
	if v0 != 0x000A {
		t.Errorf("register 0 = 0x%04X, want 0x000A", v0)
	}
	if v1 != 0x0102 {
		t.Errorf("register 1 = 0x%04X, want 0x0102", v1)
	}
}

func TestWriteMultipleCoils(t *testing.T) {
	ds := newTestStore()

	// Write 10 coils starting at address 20
	// Coil values: 1,0,1,1, 0,0,1,0, 1,1 = 0xCD, 0x03 (bit order)
	req := Request{
		TransactionID: 1,
		UnitID:        1,
		Function:      FcWriteMultipleCoils,
		Data:          WriteMultipleCoilsRequest(20, 10, []byte{0x0D, 0x03}),
	}
	resp := ds.HandleRequest(req)
	if resp.IsException() {
		t.Fatalf("unexpected exception: %v", resp.ExceptionCode())
	}

	// Check coil 20 (bit 0 of first byte = 1)
	v, _ := ds.GetCoil(20)
	if !v {
		t.Error("coil 20 should be true")
	}
	// Check coil 21 (bit 1 = 0)
	v, _ = ds.GetCoil(21)
	if v {
		t.Error("coil 21 should be false")
	}
	// Check coil 22 (bit 2 = 1)
	v, _ = ds.GetCoil(22)
	if !v {
		t.Error("coil 22 should be true")
	}
	// Check coil 28 (bit 0 of second byte = 1)
	v, _ = ds.GetCoil(28)
	if !v {
		t.Error("coil 28 should be true")
	}
}

func TestMaskWriteRegister(t *testing.T) {
	ds := newTestStore()
	_ = ds.SetHoldingRegister(4, 0x0012)

	// Mask: result = (0x0012 AND 0x00F2) OR (0x0025 AND NOT 0x00F2)
	//             = 0x0012 OR (0x0025 AND 0xFF0D)
	//             = 0x0012 OR 0x0005
	//             = 0x0017
	req := Request{
		TransactionID: 1,
		UnitID:        1,
		Function:      FcMaskWriteRegister,
		Data:          MaskWriteRegisterRequest(4, 0x00F2, 0x0025),
	}
	resp := ds.HandleRequest(req)
	if resp.IsException() {
		t.Fatalf("unexpected exception: %v", resp.ExceptionCode())
	}

	val, _ := ds.GetHoldingRegister(4)
	if val != 0x0017 {
		t.Errorf("register 4 = 0x%04X, want 0x0017", val)
	}
}

func TestAddressOutOfRange(t *testing.T) {
	ds := newTestStore()

	// Read holding registers beyond range
	req := Request{
		TransactionID: 1,
		UnitID:        1,
		Function:      FcReadHoldingRegisters,
		Data:          ReadHoldingRegistersRequest(99, 10), // 99+10 > 100
	}
	resp := ds.HandleRequest(req)
	if !resp.IsException() {
		t.Fatal("expected exception for address out of range")
	}
	if resp.ExceptionCode() != ExceptionIllegalDataAddress {
		t.Errorf("exception = %v, want IllegalDataAddress", resp.ExceptionCode())
	}
}

func TestQuantityOutOfRange(t *testing.T) {
	ds := newTestStore()

	// Quantity 0 for reading
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:2], 0)
	binary.BigEndian.PutUint16(data[2:4], 0) // quantity 0
	req := Request{
		TransactionID: 1,
		UnitID:        1,
		Function:      FcReadHoldingRegisters,
		Data:          data,
	}
	resp := ds.HandleRequest(req)
	if !resp.IsException() {
		t.Fatal("expected exception for quantity 0")
	}
	if resp.ExceptionCode() != ExceptionIllegalDataValue {
		t.Errorf("exception = %v, want IllegalDataValue", resp.ExceptionCode())
	}
}

func TestUnknownFunctionCode(t *testing.T) {
	ds := newTestStore()

	req := Request{
		TransactionID: 1,
		UnitID:        1,
		Function:      0x50, // unknown
		Data:          []byte{0x00},
	}
	resp := ds.HandleRequest(req)
	if !resp.IsException() {
		t.Fatal("expected exception for unknown function code")
	}
	if resp.ExceptionCode() != ExceptionIllegalFunction {
		t.Errorf("exception = %v, want IllegalFunction", resp.ExceptionCode())
	}
}

func TestSettersOutOfRange(t *testing.T) {
	ds := newTestStore()

	if err := ds.SetCoil(200, true); err == nil {
		t.Error("expected error for coil out of range")
	}
	if err := ds.SetDiscreteInput(200, true); err == nil {
		t.Error("expected error for discrete input out of range")
	}
	if err := ds.SetInputRegister(200, 1); err == nil {
		t.Error("expected error for input register out of range")
	}
	if err := ds.SetHoldingRegister(200, 1); err == nil {
		t.Error("expected error for holding register out of range")
	}
}

func TestDefaultDataStoreConfig(t *testing.T) {
	cfg := DefaultDataStoreConfig()
	if cfg.CoilCount != 9999 {
		t.Errorf("CoilCount = %d, want 9999", cfg.CoilCount)
	}
	ds := NewDataStore(cfg)
	if err := ds.SetHoldingRegister(9998, 42); err != nil {
		t.Errorf("SetHoldingRegister: %v", err)
	}
}

func TestWriteMultipleRegistersQuantityTooHigh(t *testing.T) {
	ds := newTestStore()

	data := make([]byte, 5)
	binary.BigEndian.PutUint16(data[0:2], 0)
	binary.BigEndian.PutUint16(data[2:4], 124) // > 123
	data[4] = 248                                // 124*2
	req := Request{
		TransactionID: 1,
		UnitID:        1,
		Function:      FcWriteMultipleRegisters,
		Data:          data,
	}
	resp := ds.HandleRequest(req)
	if !resp.IsException() {
		t.Fatal("expected exception for quantity > 123")
	}
}

func TestShortRequestData(t *testing.T) {
	ds := newTestStore()

	// Each function code should handle short data gracefully
	fcs := []FunctionCode{
		FcReadCoils, FcReadDiscreteInputs, FcReadHoldingRegisters,
		FcReadInputRegisters, FcWriteSingleCoil, FcWriteSingleRegister,
		FcWriteMultipleCoils, FcWriteMultipleRegisters, FcMaskWriteRegister,
	}
	for _, fc := range fcs {
		req := Request{
			TransactionID: 1,
			UnitID:        1,
			Function:      fc,
			Data:          []byte{0x00}, // too short for any function
		}
		resp := ds.HandleRequest(req)
		if !resp.IsException() {
			t.Errorf("FC 0x%02X: expected exception for short data", fc)
		}
	}
}
