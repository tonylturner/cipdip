package codec

import (
	"encoding/binary"
	"testing"
)

func TestPutUint16(t *testing.T) {
	tests := []struct {
		name  string
		order binary.ByteOrder
		value uint16
		want  []byte
	}{
		{"little endian zero", binary.LittleEndian, 0x0000, []byte{0x00, 0x00}},
		{"little endian", binary.LittleEndian, 0x0102, []byte{0x02, 0x01}},
		{"big endian", binary.BigEndian, 0x0102, []byte{0x01, 0x02}},
		{"little endian max", binary.LittleEndian, 0xFFFF, []byte{0xFF, 0xFF}},
		{"big endian max", binary.BigEndian, 0xFFFF, []byte{0xFF, 0xFF}},
		{"CIP port 44818", binary.LittleEndian, 44818, []byte{0x12, 0xAF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, 2)
			PutUint16(tt.order, buf, tt.value)
			if buf[0] != tt.want[0] || buf[1] != tt.want[1] {
				t.Errorf("PutUint16() = %v, want %v", buf, tt.want)
			}
		})
	}
}

func TestPutUint32(t *testing.T) {
	tests := []struct {
		name  string
		order binary.ByteOrder
		value uint32
		want  []byte
	}{
		{"little endian zero", binary.LittleEndian, 0x00000000, []byte{0x00, 0x00, 0x00, 0x00}},
		{"little endian", binary.LittleEndian, 0x01020304, []byte{0x04, 0x03, 0x02, 0x01}},
		{"big endian", binary.BigEndian, 0x01020304, []byte{0x01, 0x02, 0x03, 0x04}},
		{"little endian max", binary.LittleEndian, 0xFFFFFFFF, []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{"ENIP session handle", binary.LittleEndian, 0x12345678, []byte{0x78, 0x56, 0x34, 0x12}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, 4)
			PutUint32(tt.order, buf, tt.value)
			for i := range tt.want {
				if buf[i] != tt.want[i] {
					t.Errorf("PutUint32() = %v, want %v", buf, tt.want)
					break
				}
			}
		})
	}
}

func TestPutUint64(t *testing.T) {
	tests := []struct {
		name  string
		order binary.ByteOrder
		value uint64
		want  []byte
	}{
		{"little endian zero", binary.LittleEndian, 0, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"little endian", binary.LittleEndian, 0x0102030405060708, []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}},
		{"big endian", binary.BigEndian, 0x0102030405060708, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, 8)
			PutUint64(tt.order, buf, tt.value)
			for i := range tt.want {
				if buf[i] != tt.want[i] {
					t.Errorf("PutUint64() = %v, want %v", buf, tt.want)
					break
				}
			}
		})
	}
}

func TestAppendUint16(t *testing.T) {
	tests := []struct {
		name  string
		order binary.ByteOrder
		dst   []byte
		value uint16
		want  []byte
	}{
		{"append to empty LE", binary.LittleEndian, nil, 0x0102, []byte{0x02, 0x01}},
		{"append to empty BE", binary.BigEndian, nil, 0x0102, []byte{0x01, 0x02}},
		{"append to existing", binary.LittleEndian, []byte{0xAA}, 0x0102, []byte{0xAA, 0x02, 0x01}},
		{"append multiple", binary.LittleEndian, []byte{0xAA, 0xBB}, 0xCCDD, []byte{0xAA, 0xBB, 0xDD, 0xCC}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AppendUint16(tt.order, tt.dst, tt.value)
			if len(got) != len(tt.want) {
				t.Fatalf("AppendUint16() len = %d, want %d", len(got), len(tt.want))
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("AppendUint16() = %v, want %v", got, tt.want)
					break
				}
			}
		})
	}
}

func TestAppendUint16_DoesNotMutateSrc(t *testing.T) {
	src := []byte{0x01, 0x02}
	srcCopy := make([]byte, len(src))
	copy(srcCopy, src)

	AppendUint16(binary.LittleEndian, src, 0x0304)

	for i := range src {
		if src[i] != srcCopy[i] {
			t.Errorf("AppendUint16 mutated source: %v, was %v", src, srcCopy)
			break
		}
	}
}

func TestAppendUint32(t *testing.T) {
	tests := []struct {
		name  string
		order binary.ByteOrder
		dst   []byte
		value uint32
		want  []byte
	}{
		{"append to empty LE", binary.LittleEndian, nil, 0x01020304, []byte{0x04, 0x03, 0x02, 0x01}},
		{"append to empty BE", binary.BigEndian, nil, 0x01020304, []byte{0x01, 0x02, 0x03, 0x04}},
		{"append to existing", binary.LittleEndian, []byte{0xFF}, 0xAABBCCDD, []byte{0xFF, 0xDD, 0xCC, 0xBB, 0xAA}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AppendUint32(tt.order, tt.dst, tt.value)
			if len(got) != len(tt.want) {
				t.Fatalf("AppendUint32() len = %d, want %d", len(got), len(tt.want))
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("AppendUint32() = %v, want %v", got, tt.want)
					break
				}
			}
		})
	}
}

func TestAppendUint64(t *testing.T) {
	tests := []struct {
		name  string
		order binary.ByteOrder
		dst   []byte
		value uint64
		want  []byte
	}{
		{"append to empty LE", binary.LittleEndian, nil, 0x0102030405060708, []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}},
		{"append to empty BE", binary.BigEndian, nil, 0x0102030405060708, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{"append to existing", binary.LittleEndian, []byte{0xAA}, 0x0000000000000001, []byte{0xAA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AppendUint64(tt.order, tt.dst, tt.value)
			if len(got) != len(tt.want) {
				t.Fatalf("AppendUint64() len = %d, want %d", len(got), len(tt.want))
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("AppendUint64() = %v, want %v", got, tt.want)
					break
				}
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	// Verify Put then read back gives same value
	t.Run("uint16 round trip", func(t *testing.T) {
		buf := make([]byte, 2)
		PutUint16(binary.LittleEndian, buf, 44818)
		got := binary.LittleEndian.Uint16(buf)
		if got != 44818 {
			t.Errorf("round trip = %d, want %d", got, 44818)
		}
	})

	t.Run("uint32 round trip", func(t *testing.T) {
		buf := make([]byte, 4)
		PutUint32(binary.LittleEndian, buf, 0xDEADBEEF)
		got := binary.LittleEndian.Uint32(buf)
		if got != 0xDEADBEEF {
			t.Errorf("round trip = 0x%X, want 0xDEADBEEF", got)
		}
	})

	t.Run("uint64 round trip", func(t *testing.T) {
		buf := make([]byte, 8)
		PutUint64(binary.BigEndian, buf, 0xCAFEBABEDEADBEEF)
		got := binary.BigEndian.Uint64(buf)
		if got != 0xCAFEBABEDEADBEEF {
			t.Errorf("round trip = 0x%X, want 0xCAFEBABEDEADBEEF", got)
		}
	})
}

func TestAppendChaining(t *testing.T) {
	// Verify multiple appends build correct packet structure
	buf := AppendUint16(binary.LittleEndian, nil, 0x0065) // ENIP command
	buf = AppendUint32(binary.LittleEndian, buf, 0x00000010)  // length
	buf = AppendUint32(binary.LittleEndian, buf, 0x12345678)  // session handle

	if len(buf) != 10 {
		t.Fatalf("chained append len = %d, want 10", len(buf))
	}

	// Verify each field
	cmd := binary.LittleEndian.Uint16(buf[0:2])
	if cmd != 0x0065 {
		t.Errorf("command = 0x%04X, want 0x0065", cmd)
	}
	length := binary.LittleEndian.Uint32(buf[2:6])
	if length != 0x10 {
		t.Errorf("length = 0x%08X, want 0x00000010", length)
	}
	session := binary.LittleEndian.Uint32(buf[6:10])
	if session != 0x12345678 {
		t.Errorf("session = 0x%08X, want 0x12345678", session)
	}
}
