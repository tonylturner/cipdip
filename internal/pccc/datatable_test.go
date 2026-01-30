package pccc

import (
	"encoding/binary"
	"testing"
)

func TestDataTableReadWriteInt16(t *testing.T) {
	dt := NewDataTable(FileTypeInteger, 7, 256)

	// Write value
	if err := dt.WriteInt16(5, 0, 12345); err != nil {
		t.Fatalf("WriteInt16: %v", err)
	}

	// Read it back
	val, err := dt.ReadInt16(5, 0)
	if err != nil {
		t.Fatalf("ReadInt16: %v", err)
	}
	if val != 12345 {
		t.Errorf("ReadInt16: got %d, want 12345", val)
	}
}

func TestDataTableReadWriteFloat32(t *testing.T) {
	dt := NewDataTable(FileTypeFloat, 8, 64)

	if err := dt.WriteFloat32(0, 3.14); err != nil {
		t.Fatalf("WriteFloat32: %v", err)
	}

	val, err := dt.ReadFloat32(0)
	if err != nil {
		t.Fatalf("ReadFloat32: %v", err)
	}
	if val < 3.139 || val > 3.141 {
		t.Errorf("ReadFloat32: got %f, want ~3.14", val)
	}
}

func TestDataTableReadWriteInt32(t *testing.T) {
	dt := NewDataTable(FileTypeLong, 11, 64)

	if err := dt.WriteInt32(0, 1000000); err != nil {
		t.Fatalf("WriteInt32: %v", err)
	}

	val, err := dt.ReadInt32(0)
	if err != nil {
		t.Fatalf("ReadInt32: %v", err)
	}
	if val != 1000000 {
		t.Errorf("ReadInt32: got %d, want 1000000", val)
	}
}

func TestDataTableTimerSubElements(t *testing.T) {
	dt := NewDataTable(FileTypeTimer, 4, 16)

	// Timer element 0: write PRE=1000, ACC=500
	if err := dt.WriteInt16(0, uint8(SubTimerPRE), 1000); err != nil {
		t.Fatalf("WriteInt16 PRE: %v", err)
	}
	if err := dt.WriteInt16(0, uint8(SubTimerACC), 500); err != nil {
		t.Fatalf("WriteInt16 ACC: %v", err)
	}

	pre, err := dt.ReadInt16(0, uint8(SubTimerPRE))
	if err != nil {
		t.Fatalf("ReadInt16 PRE: %v", err)
	}
	if pre != 1000 {
		t.Errorf("PRE: got %d, want 1000", pre)
	}

	acc, err := dt.ReadInt16(0, uint8(SubTimerACC))
	if err != nil {
		t.Fatalf("ReadInt16 ACC: %v", err)
	}
	if acc != 500 {
		t.Errorf("ACC: got %d, want 500", acc)
	}
}

func TestDataTableOutOfRange(t *testing.T) {
	dt := NewDataTable(FileTypeInteger, 7, 10)

	// Read beyond bounds
	_, err := dt.ReadBytes(10, 0, 2)
	if err == nil {
		t.Error("expected error for out-of-range read")
	}

	// Write beyond bounds
	err = dt.WriteBytes(10, 0, []byte{0x00, 0x00})
	if err == nil {
		t.Error("expected error for out-of-range write")
	}
}

func TestDataTableSetLookup(t *testing.T) {
	dts := NewDataTableSet()

	// Standard files should exist
	for fileNum := uint8(0); fileNum <= 11; fileNum++ {
		dt, ok := dts.Lookup(fileNum)
		if !ok {
			t.Errorf("file %d not found", fileNum)
			continue
		}
		if dt.FileNumber != fileNum {
			t.Errorf("file %d: FileNumber = %d", fileNum, dt.FileNumber)
		}
	}

	// Non-existent file
	_, ok := dts.Lookup(99)
	if ok {
		t.Error("expected file 99 to not exist")
	}
}

func TestHandleTypedRead(t *testing.T) {
	dts := NewDataTableSet()

	// Pre-populate N7:5 = 42
	dt, _ := dts.Lookup(7)
	binary.LittleEndian.PutUint16(dt.Data[5*2:], 42)

	// Build typed read request data for N7:5, 2 bytes
	reqData := []byte{0x02, 0x07, 0x89, 0x05}

	result, err := dts.HandleTypedRead(reqData)
	if err != nil {
		t.Fatalf("HandleTypedRead: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("result length: got %d, want 2", len(result))
	}
	val := int16(binary.LittleEndian.Uint16(result))
	if val != 42 {
		t.Errorf("read value: got %d, want 42", val)
	}
}

func TestHandleTypedWrite(t *testing.T) {
	dts := NewDataTableSet()

	// Build typed write request data for N7:3 = 100
	// byte_count=2, file=7, type=0x89, element=3, data=0x64,0x00
	reqData := []byte{0x02, 0x07, 0x89, 0x03, 0x64, 0x00}

	err := dts.HandleTypedWrite(reqData)
	if err != nil {
		t.Fatalf("HandleTypedWrite: %v", err)
	}

	// Verify the value
	dt, _ := dts.Lookup(7)
	val := int16(binary.LittleEndian.Uint16(dt.Data[3*2:]))
	if val != 100 {
		t.Errorf("written value: got %d, want 100", val)
	}
}

func TestHandleTypedReadFileMismatch(t *testing.T) {
	dts := NewDataTableSet()

	// Try to read file 7 (integer) with float type
	reqData := []byte{0x04, 0x07, 0x8A, 0x00} // file 7, type float
	_, err := dts.HandleTypedRead(reqData)
	if err == nil {
		t.Fatal("expected error for file type mismatch")
	}
}

func TestHandleTypedReadFileNotFound(t *testing.T) {
	dts := NewDataTableSet()

	reqData := []byte{0x02, 0x63, 0x89, 0x00} // file 99
	_, err := dts.HandleTypedRead(reqData)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
