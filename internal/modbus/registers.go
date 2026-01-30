package modbus

// Modbus register/coil data model for server emulation.
//
// Modbus data is organized into four address spaces:
//   - Coils (00001-09999): read-write single-bit, FC 1/5/15
//   - Discrete inputs (10001-19999): read-only single-bit, FC 2
//   - Input registers (30001-39999): read-only 16-bit, FC 4
//   - Holding registers (40001-49999): read-write 16-bit, FC 3/6/16/22/23

import (
	"encoding/binary"
	"fmt"
	"sync"
)

// DataStore holds the four Modbus address spaces.
type DataStore struct {
	mu              sync.RWMutex
	coils           []bool   // 0-based, size = coilCount
	discreteInputs []bool   // 0-based
	inputRegisters  []uint16 // 0-based
	holdingRegisters []uint16 // 0-based
}

// DataStoreConfig configures the sizes of the Modbus address spaces.
type DataStoreConfig struct {
	CoilCount           int // Number of coils (default 9999)
	DiscreteInputCount  int // Number of discrete inputs (default 9999)
	InputRegisterCount  int // Number of input registers (default 9999)
	HoldingRegisterCount int // Number of holding registers (default 9999)
}

// DefaultDataStoreConfig returns standard Modbus address space sizes.
func DefaultDataStoreConfig() DataStoreConfig {
	return DataStoreConfig{
		CoilCount:            9999,
		DiscreteInputCount:   9999,
		InputRegisterCount:   9999,
		HoldingRegisterCount: 9999,
	}
}

// NewDataStore creates a data store with the given configuration.
func NewDataStore(cfg DataStoreConfig) *DataStore {
	return &DataStore{
		coils:            make([]bool, cfg.CoilCount),
		discreteInputs:   make([]bool, cfg.DiscreteInputCount),
		inputRegisters:   make([]uint16, cfg.InputRegisterCount),
		holdingRegisters: make([]uint16, cfg.HoldingRegisterCount),
	}
}

// --- Public accessors (for test setup and diagnostics) ---

// SetCoil sets a single coil value (0-based address).
func (ds *DataStore) SetCoil(addr int, value bool) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if addr < 0 || addr >= len(ds.coils) {
		return fmt.Errorf("coil address %d out of range (0-%d)", addr, len(ds.coils)-1)
	}
	ds.coils[addr] = value
	return nil
}

// SetDiscreteInput sets a single discrete input value (0-based address).
func (ds *DataStore) SetDiscreteInput(addr int, value bool) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if addr < 0 || addr >= len(ds.discreteInputs) {
		return fmt.Errorf("discrete input address %d out of range (0-%d)", addr, len(ds.discreteInputs)-1)
	}
	ds.discreteInputs[addr] = value
	return nil
}

// SetInputRegister sets a single input register value (0-based address).
func (ds *DataStore) SetInputRegister(addr int, value uint16) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if addr < 0 || addr >= len(ds.inputRegisters) {
		return fmt.Errorf("input register address %d out of range (0-%d)", addr, len(ds.inputRegisters)-1)
	}
	ds.inputRegisters[addr] = value
	return nil
}

// SetHoldingRegister sets a single holding register value (0-based address).
func (ds *DataStore) SetHoldingRegister(addr int, value uint16) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if addr < 0 || addr >= len(ds.holdingRegisters) {
		return fmt.Errorf("holding register address %d out of range (0-%d)", addr, len(ds.holdingRegisters)-1)
	}
	ds.holdingRegisters[addr] = value
	return nil
}

// GetHoldingRegister reads a single holding register (0-based).
func (ds *DataStore) GetHoldingRegister(addr int) (uint16, error) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	if addr < 0 || addr >= len(ds.holdingRegisters) {
		return 0, fmt.Errorf("holding register address %d out of range", addr)
	}
	return ds.holdingRegisters[addr], nil
}

// GetCoil reads a single coil (0-based).
func (ds *DataStore) GetCoil(addr int) (bool, error) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	if addr < 0 || addr >= len(ds.coils) {
		return false, fmt.Errorf("coil address %d out of range", addr)
	}
	return ds.coils[addr], nil
}

// --- Modbus PDU handlers ---

// HandleRequest processes a Modbus PDU request and returns the response data.
// Returns the response function code and data bytes, or an exception.
func (ds *DataStore) HandleRequest(req Request) Response {
	switch req.Function {
	case FcReadCoils:
		return ds.handleReadCoils(req)
	case FcReadDiscreteInputs:
		return ds.handleReadDiscreteInputs(req)
	case FcReadHoldingRegisters:
		return ds.handleReadHoldingRegisters(req)
	case FcReadInputRegisters:
		return ds.handleReadInputRegisters(req)
	case FcWriteSingleCoil:
		return ds.handleWriteSingleCoil(req)
	case FcWriteSingleRegister:
		return ds.handleWriteSingleRegister(req)
	case FcWriteMultipleCoils:
		return ds.handleWriteMultipleCoils(req)
	case FcWriteMultipleRegisters:
		return ds.handleWriteMultipleRegisters(req)
	case FcMaskWriteRegister:
		return ds.handleMaskWriteRegister(req)
	default:
		return exceptionResponse(req, ExceptionIllegalFunction)
	}
}

// --- Read handlers ---

func (ds *DataStore) handleReadCoils(req Request) Response {
	if len(req.Data) < 4 {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}
	startAddr := binary.BigEndian.Uint16(req.Data[0:2])
	quantity := binary.BigEndian.Uint16(req.Data[2:4])
	if quantity < 1 || quantity > 2000 {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}

	ds.mu.RLock()
	defer ds.mu.RUnlock()

	end := int(startAddr) + int(quantity)
	if end > len(ds.coils) {
		return exceptionResponse(req, ExceptionIllegalDataAddress)
	}

	byteCount := (quantity + 7) / 8
	data := make([]byte, 1+byteCount)
	data[0] = byte(byteCount)
	for i := uint16(0); i < quantity; i++ {
		if ds.coils[int(startAddr)+int(i)] {
			data[1+i/8] |= 1 << (i % 8)
		}
	}
	return Response{
		TransactionID: req.TransactionID,
		UnitID:        req.UnitID,
		Function:      req.Function,
		Data:          data,
	}
}

func (ds *DataStore) handleReadDiscreteInputs(req Request) Response {
	if len(req.Data) < 4 {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}
	startAddr := binary.BigEndian.Uint16(req.Data[0:2])
	quantity := binary.BigEndian.Uint16(req.Data[2:4])
	if quantity < 1 || quantity > 2000 {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}

	ds.mu.RLock()
	defer ds.mu.RUnlock()

	end := int(startAddr) + int(quantity)
	if end > len(ds.discreteInputs) {
		return exceptionResponse(req, ExceptionIllegalDataAddress)
	}

	byteCount := (quantity + 7) / 8
	data := make([]byte, 1+byteCount)
	data[0] = byte(byteCount)
	for i := uint16(0); i < quantity; i++ {
		if ds.discreteInputs[int(startAddr)+int(i)] {
			data[1+i/8] |= 1 << (i % 8)
		}
	}
	return Response{
		TransactionID: req.TransactionID,
		UnitID:        req.UnitID,
		Function:      req.Function,
		Data:          data,
	}
}

func (ds *DataStore) handleReadHoldingRegisters(req Request) Response {
	if len(req.Data) < 4 {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}
	startAddr := binary.BigEndian.Uint16(req.Data[0:2])
	quantity := binary.BigEndian.Uint16(req.Data[2:4])
	if quantity < 1 || quantity > 125 {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}

	ds.mu.RLock()
	defer ds.mu.RUnlock()

	end := int(startAddr) + int(quantity)
	if end > len(ds.holdingRegisters) {
		return exceptionResponse(req, ExceptionIllegalDataAddress)
	}

	byteCount := quantity * 2
	data := make([]byte, 1+byteCount)
	data[0] = byte(byteCount)
	for i := uint16(0); i < quantity; i++ {
		binary.BigEndian.PutUint16(data[1+i*2:], ds.holdingRegisters[int(startAddr)+int(i)])
	}
	return Response{
		TransactionID: req.TransactionID,
		UnitID:        req.UnitID,
		Function:      req.Function,
		Data:          data,
	}
}

func (ds *DataStore) handleReadInputRegisters(req Request) Response {
	if len(req.Data) < 4 {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}
	startAddr := binary.BigEndian.Uint16(req.Data[0:2])
	quantity := binary.BigEndian.Uint16(req.Data[2:4])
	if quantity < 1 || quantity > 125 {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}

	ds.mu.RLock()
	defer ds.mu.RUnlock()

	end := int(startAddr) + int(quantity)
	if end > len(ds.inputRegisters) {
		return exceptionResponse(req, ExceptionIllegalDataAddress)
	}

	byteCount := quantity * 2
	data := make([]byte, 1+byteCount)
	data[0] = byte(byteCount)
	for i := uint16(0); i < quantity; i++ {
		binary.BigEndian.PutUint16(data[1+i*2:], ds.inputRegisters[int(startAddr)+int(i)])
	}
	return Response{
		TransactionID: req.TransactionID,
		UnitID:        req.UnitID,
		Function:      req.Function,
		Data:          data,
	}
}

// --- Write handlers ---

func (ds *DataStore) handleWriteSingleCoil(req Request) Response {
	if len(req.Data) < 4 {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}
	addr := binary.BigEndian.Uint16(req.Data[0:2])
	val := binary.BigEndian.Uint16(req.Data[2:4])
	if val != 0x0000 && val != 0xFF00 {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	if int(addr) >= len(ds.coils) {
		return exceptionResponse(req, ExceptionIllegalDataAddress)
	}
	ds.coils[addr] = (val == 0xFF00)

	// Echo request data as response
	return Response{
		TransactionID: req.TransactionID,
		UnitID:        req.UnitID,
		Function:      req.Function,
		Data:          cloneBytes(req.Data[:4]),
	}
}

func (ds *DataStore) handleWriteSingleRegister(req Request) Response {
	if len(req.Data) < 4 {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}
	addr := binary.BigEndian.Uint16(req.Data[0:2])
	val := binary.BigEndian.Uint16(req.Data[2:4])

	ds.mu.Lock()
	defer ds.mu.Unlock()

	if int(addr) >= len(ds.holdingRegisters) {
		return exceptionResponse(req, ExceptionIllegalDataAddress)
	}
	ds.holdingRegisters[addr] = val

	return Response{
		TransactionID: req.TransactionID,
		UnitID:        req.UnitID,
		Function:      req.Function,
		Data:          cloneBytes(req.Data[:4]),
	}
}

func (ds *DataStore) handleWriteMultipleCoils(req Request) Response {
	if len(req.Data) < 5 {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}
	startAddr := binary.BigEndian.Uint16(req.Data[0:2])
	quantity := binary.BigEndian.Uint16(req.Data[2:4])
	byteCount := int(req.Data[4])
	if quantity < 1 || quantity > 1968 {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}
	expectedBytes := int((quantity + 7) / 8)
	if byteCount != expectedBytes || len(req.Data) < 5+byteCount {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	end := int(startAddr) + int(quantity)
	if end > len(ds.coils) {
		return exceptionResponse(req, ExceptionIllegalDataAddress)
	}

	for i := uint16(0); i < quantity; i++ {
		byteIdx := i / 8
		bitIdx := i % 8
		ds.coils[int(startAddr)+int(i)] = (req.Data[5+byteIdx] & (1 << bitIdx)) != 0
	}

	// Response echoes start address and quantity
	respData := make([]byte, 4)
	binary.BigEndian.PutUint16(respData[0:2], startAddr)
	binary.BigEndian.PutUint16(respData[2:4], quantity)
	return Response{
		TransactionID: req.TransactionID,
		UnitID:        req.UnitID,
		Function:      req.Function,
		Data:          respData,
	}
}

func (ds *DataStore) handleWriteMultipleRegisters(req Request) Response {
	if len(req.Data) < 5 {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}
	startAddr := binary.BigEndian.Uint16(req.Data[0:2])
	quantity := binary.BigEndian.Uint16(req.Data[2:4])
	byteCount := int(req.Data[4])
	if quantity < 1 || quantity > 123 {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}
	if byteCount != int(quantity)*2 || len(req.Data) < 5+byteCount {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	end := int(startAddr) + int(quantity)
	if end > len(ds.holdingRegisters) {
		return exceptionResponse(req, ExceptionIllegalDataAddress)
	}

	for i := uint16(0); i < quantity; i++ {
		ds.holdingRegisters[int(startAddr)+int(i)] = binary.BigEndian.Uint16(req.Data[5+i*2:])
	}

	respData := make([]byte, 4)
	binary.BigEndian.PutUint16(respData[0:2], startAddr)
	binary.BigEndian.PutUint16(respData[2:4], quantity)
	return Response{
		TransactionID: req.TransactionID,
		UnitID:        req.UnitID,
		Function:      req.Function,
		Data:          respData,
	}
}

func (ds *DataStore) handleMaskWriteRegister(req Request) Response {
	if len(req.Data) < 6 {
		return exceptionResponse(req, ExceptionIllegalDataValue)
	}
	addr := binary.BigEndian.Uint16(req.Data[0:2])
	andMask := binary.BigEndian.Uint16(req.Data[2:4])
	orMask := binary.BigEndian.Uint16(req.Data[4:6])

	ds.mu.Lock()
	defer ds.mu.Unlock()

	if int(addr) >= len(ds.holdingRegisters) {
		return exceptionResponse(req, ExceptionIllegalDataAddress)
	}

	// Result = (Current AND And_Mask) OR (Or_Mask AND NOT And_Mask)
	current := ds.holdingRegisters[addr]
	ds.holdingRegisters[addr] = (current & andMask) | (orMask & ^andMask)

	return Response{
		TransactionID: req.TransactionID,
		UnitID:        req.UnitID,
		Function:      req.Function,
		Data:          cloneBytes(req.Data[:6]),
	}
}

// --- helpers ---

func exceptionResponse(req Request, exc ExceptionCode) Response {
	return Response{
		TransactionID: req.TransactionID,
		UnitID:        req.UnitID,
		Function:      req.Function | 0x80,
		Data:          []byte{byte(exc)},
	}
}
