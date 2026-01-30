package pccc

// PCCC data table definitions and in-memory data table model.
//
// Data tables represent the processor's memory layout:
//   O (Output)   - 16-bit output image
//   I (Input)    - 16-bit input image
//   S (Status)   - 16-bit processor status
//   B (Bit)      - 16-bit binary words
//   T (Timer)    - 6-byte timer structure (CTL, PRE, ACC)
//   C (Counter)  - 6-byte counter structure (CTL, PRE, ACC)
//   R (Control)  - 6-byte control structure (CTL, LEN, POS)
//   N (Integer)  - 16-bit signed integers
//   F (Float)    - 32-bit IEEE 754 floats
//   ST (String)  - 84-byte string (2-byte length + 82-byte data)
//   A (ASCII)    - 16-bit ASCII words
//   L (Long)     - 32-bit signed integers

import (
	"encoding/binary"
	"fmt"
	"math"
)

// DataTable provides in-memory storage for a single PCCC data file.
type DataTable struct {
	FileType   FileType
	FileNumber uint8
	Elements   int    // Number of elements
	Data       []byte // Raw byte storage
}

// NewDataTable creates a data table with the specified number of elements.
func NewDataTable(ft FileType, fileNum uint8, elements int) *DataTable {
	return &DataTable{
		FileType:   ft,
		FileNumber: fileNum,
		Elements:   elements,
		Data:       make([]byte, elements*ft.ByteSize()),
	}
}

// ReadBytes reads raw bytes starting from the given element/sub-element offset.
func (dt *DataTable) ReadBytes(element uint16, subElement uint8, count int) ([]byte, error) {
	offset := dt.byteOffset(element, subElement)
	if offset < 0 || offset+count > len(dt.Data) {
		return nil, fmt.Errorf("read out of range: offset %d, count %d, table size %d",
			offset, count, len(dt.Data))
	}
	result := make([]byte, count)
	copy(result, dt.Data[offset:offset+count])
	return result, nil
}

// WriteBytes writes raw bytes starting from the given element/sub-element offset.
func (dt *DataTable) WriteBytes(element uint16, subElement uint8, data []byte) error {
	offset := dt.byteOffset(element, subElement)
	if offset < 0 || offset+len(data) > len(dt.Data) {
		return fmt.Errorf("write out of range: offset %d, count %d, table size %d",
			offset, len(data), len(dt.Data))
	}
	copy(dt.Data[offset:], data)
	return nil
}

// ReadInt16 reads a 16-bit integer from the given element.
func (dt *DataTable) ReadInt16(element uint16, subElement uint8) (int16, error) {
	data, err := dt.ReadBytes(element, subElement, 2)
	if err != nil {
		return 0, err
	}
	return int16(binary.LittleEndian.Uint16(data)), nil
}

// WriteInt16 writes a 16-bit integer to the given element.
func (dt *DataTable) WriteInt16(element uint16, subElement uint8, value int16) error {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], uint16(value))
	return dt.WriteBytes(element, subElement, buf[:])
}

// ReadFloat32 reads a 32-bit float from the given element.
func (dt *DataTable) ReadFloat32(element uint16) (float32, error) {
	data, err := dt.ReadBytes(element, 0, 4)
	if err != nil {
		return 0, err
	}
	return math.Float32frombits(binary.LittleEndian.Uint32(data)), nil
}

// WriteFloat32 writes a 32-bit float to the given element.
func (dt *DataTable) WriteFloat32(element uint16, value float32) error {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], math.Float32bits(value))
	return dt.WriteBytes(element, 0, buf[:])
}

// ReadInt32 reads a 32-bit integer from the given element (Long type).
func (dt *DataTable) ReadInt32(element uint16) (int32, error) {
	data, err := dt.ReadBytes(element, 0, 4)
	if err != nil {
		return 0, err
	}
	return int32(binary.LittleEndian.Uint32(data)), nil
}

// WriteInt32 writes a 32-bit integer to the given element (Long type).
func (dt *DataTable) WriteInt32(element uint16, value int32) error {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(value))
	return dt.WriteBytes(element, 0, buf[:])
}

// byteOffset computes the byte offset for an element/sub-element.
func (dt *DataTable) byteOffset(element uint16, subElement uint8) int {
	elemSize := dt.FileType.ByteSize()
	base := int(element) * elemSize

	switch dt.FileType {
	case FileTypeTimer, FileTypeCounter, FileTypeControl:
		// 3-word structures: each sub-element is 2 bytes
		return base + int(subElement)*2
	default:
		return base
	}
}

// DataTableSet holds a collection of data tables indexed by file number.
type DataTableSet struct {
	Tables map[uint8]*DataTable
}

// NewDataTableSet creates a data table set with standard SLC-500 defaults.
func NewDataTableSet() *DataTableSet {
	return &DataTableSet{
		Tables: map[uint8]*DataTable{
			0:  NewDataTable(FileTypeOutput, 0, 32),
			1:  NewDataTable(FileTypeInput, 1, 32),
			2:  NewDataTable(FileTypeStatus, 2, 64),
			3:  NewDataTable(FileTypeBit, 3, 32),
			4:  NewDataTable(FileTypeTimer, 4, 16),
			5:  NewDataTable(FileTypeCounter, 5, 16),
			6:  NewDataTable(FileTypeControl, 6, 16),
			7:  NewDataTable(FileTypeInteger, 7, 256),
			8:  NewDataTable(FileTypeFloat, 8, 64),
			9:  NewDataTable(FileTypeString, 9, 16),
			10: NewDataTable(FileTypeASCII, 10, 32),
			11: NewDataTable(FileTypeLong, 11, 64),
		},
	}
}

// Lookup returns the data table for the given file number.
func (dts *DataTableSet) Lookup(fileNumber uint8) (*DataTable, bool) {
	dt, ok := dts.Tables[fileNumber]
	return dt, ok
}

// HandleTypedRead processes a typed read request and returns the response data.
func (dts *DataTableSet) HandleTypedRead(data []byte) ([]byte, error) {
	byteCount, addr, _, err := DecodeTypedReadData(data)
	if err != nil {
		return nil, err
	}

	dt, ok := dts.Lookup(addr.FileNumber)
	if !ok {
		return nil, fmt.Errorf("file %d not found", addr.FileNumber)
	}

	if dt.FileType != addr.FileType {
		return nil, fmt.Errorf("file type mismatch: expected %s, got %s", dt.FileType, addr.FileType)
	}

	return dt.ReadBytes(addr.Element, addr.SubElement, int(byteCount))
}

// HandleTypedWrite processes a typed write request.
func (dts *DataTableSet) HandleTypedWrite(data []byte) error {
	_, addr, writeData, err := DecodeTypedReadData(data)
	if err != nil {
		return err
	}

	dt, ok := dts.Lookup(addr.FileNumber)
	if !ok {
		return fmt.Errorf("file %d not found", addr.FileNumber)
	}

	if dt.FileType != addr.FileType {
		return fmt.Errorf("file type mismatch: expected %s, got %s", dt.FileType, addr.FileType)
	}

	return dt.WriteBytes(addr.Element, addr.SubElement, writeData)
}
