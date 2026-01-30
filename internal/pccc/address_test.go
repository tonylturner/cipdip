package pccc

import "testing"

func TestParseAddress(t *testing.T) {
	tests := []struct {
		input      string
		fileType   FileType
		fileNum    uint8
		element    uint16
		subElem    uint8
		hasSub     bool
		bitNum     int8
		hasBit     bool
	}{
		// Integer files
		{"N7:0", FileTypeInteger, 7, 0, 0, false, -1, false},
		{"N7:100", FileTypeInteger, 7, 100, 0, false, -1, false},
		{"N10:5", FileTypeInteger, 10, 5, 0, false, -1, false},

		// Bit files
		{"B3:0", FileTypeBit, 3, 0, 0, false, -1, false},
		{"B3:1/5", FileTypeBit, 3, 1, 0, false, 5, true},
		{"B3:0/15", FileTypeBit, 3, 0, 0, false, 15, true},

		// Float files
		{"F8:0", FileTypeFloat, 8, 0, 0, false, -1, false},
		{"F8:10", FileTypeFloat, 8, 10, 0, false, -1, false},

		// String files
		{"ST9:0", FileTypeString, 9, 0, 0, false, -1, false},
		{"ST9:5", FileTypeString, 9, 5, 0, false, -1, false},

		// Timer files with sub-elements
		{"T4:0", FileTypeTimer, 4, 0, 0, false, -1, false},
		{"T4:2.ACC", FileTypeTimer, 4, 2, 2, true, -1, false},
		{"T4:2.PRE", FileTypeTimer, 4, 2, 1, true, -1, false},
		{"T4:0.CTL", FileTypeTimer, 4, 0, 0, true, -1, false},
		{"T4:0.EN", FileTypeTimer, 4, 0, 0, true, -1, false},
		{"T4:0.DN", FileTypeTimer, 4, 0, 0, true, -1, false},
		{"T4:0.TT", FileTypeTimer, 4, 0, 0, true, -1, false},

		// Counter files with sub-elements
		{"C5:0.ACC", FileTypeCounter, 5, 0, 2, true, -1, false},
		{"C5:0.PRE", FileTypeCounter, 5, 0, 1, true, -1, false},
		{"C5:0.DN", FileTypeCounter, 5, 0, 0, true, -1, false},
		{"C5:0.CU", FileTypeCounter, 5, 0, 0, true, -1, false},

		// Control files with sub-elements
		{"R6:0.LEN", FileTypeControl, 6, 0, 1, true, -1, false},
		{"R6:0.POS", FileTypeControl, 6, 0, 2, true, -1, false},
		{"R6:0.EN", FileTypeControl, 6, 0, 0, true, -1, false},

		// Output/Input/Status with default file numbers
		{"O:0", FileTypeOutput, 0, 0, 0, false, -1, false},
		{"O:0/0", FileTypeOutput, 0, 0, 0, false, 0, true},
		{"I:0", FileTypeInput, 1, 0, 0, false, -1, false},
		{"I:0/7", FileTypeInput, 1, 0, 0, false, 7, true},
		{"S:0", FileTypeStatus, 2, 0, 0, false, -1, false},

		// Output/Input with explicit file numbers
		{"O0:0", FileTypeOutput, 0, 0, 0, false, -1, false},
		{"I1:0", FileTypeInput, 1, 0, 0, false, -1, false},

		// ASCII and Long
		{"A10:0", FileTypeASCII, 10, 0, 0, false, -1, false},
		{"L11:0", FileTypeLong, 11, 0, 0, false, -1, false},

		// Numeric sub-elements
		{"T4:0.0", FileTypeTimer, 4, 0, 0, true, -1, false},
		{"T4:0.1", FileTypeTimer, 4, 0, 1, true, -1, false},
		{"T4:0.2", FileTypeTimer, 4, 0, 2, true, -1, false},

		// Case insensitive
		{"n7:0", FileTypeInteger, 7, 0, 0, false, -1, false},
		{"t4:0.acc", FileTypeTimer, 4, 0, 2, true, -1, false},
		{"st9:0", FileTypeString, 9, 0, 0, false, -1, false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			addr, err := ParseAddress(tc.input)
			if err != nil {
				t.Fatalf("ParseAddress(%q) error: %v", tc.input, err)
			}

			if addr.FileType != tc.fileType {
				t.Errorf("FileType: got %s (0x%02X), want %s (0x%02X)",
					addr.FileType, uint8(addr.FileType), tc.fileType, uint8(tc.fileType))
			}
			if addr.FileNumber != tc.fileNum {
				t.Errorf("FileNumber: got %d, want %d", addr.FileNumber, tc.fileNum)
			}
			if addr.Element != tc.element {
				t.Errorf("Element: got %d, want %d", addr.Element, tc.element)
			}
			if addr.HasSub != tc.hasSub {
				t.Errorf("HasSub: got %v, want %v", addr.HasSub, tc.hasSub)
			}
			if addr.HasSub && addr.SubElement != tc.subElem {
				t.Errorf("SubElement: got %d, want %d", addr.SubElement, tc.subElem)
			}
			if addr.HasBit != tc.hasBit {
				t.Errorf("HasBit: got %v, want %v", addr.HasBit, tc.hasBit)
			}
			if addr.HasBit && addr.BitNumber != tc.bitNum {
				t.Errorf("BitNumber: got %d, want %d", addr.BitNumber, tc.bitNum)
			}
		})
	}
}

func TestParseAddressErrors(t *testing.T) {
	badAddrs := []string{
		"",
		"X7:0",       // Unknown prefix
		"N:0",        // Missing file number
		"N7",         // Missing element
		"N7:",        // Missing element number
		"B3:0/",      // Missing bit number
		"B3:0/16",    // Bit out of range
		"N7:0.ACC",   // Integer doesn't support named sub-elements
		"T4:0.BOGUS", // Unknown timer sub-element
	}

	for _, addr := range badAddrs {
		t.Run(addr, func(t *testing.T) {
			_, err := ParseAddress(addr)
			if err == nil {
				t.Fatalf("ParseAddress(%q) expected error, got nil", addr)
			}
		})
	}
}

func TestFileTypeString(t *testing.T) {
	tests := []struct {
		ft   FileType
		want string
	}{
		{FileTypeOutput, "O"},
		{FileTypeInput, "I"},
		{FileTypeStatus, "S"},
		{FileTypeBit, "B"},
		{FileTypeTimer, "T"},
		{FileTypeCounter, "C"},
		{FileTypeControl, "R"},
		{FileTypeInteger, "N"},
		{FileTypeFloat, "F"},
		{FileTypeString, "ST"},
		{FileTypeASCII, "A"},
		{FileTypeLong, "L"},
	}

	for _, tc := range tests {
		if got := tc.ft.String(); got != tc.want {
			t.Errorf("FileType(0x%02X).String() = %q, want %q", uint8(tc.ft), got, tc.want)
		}
	}
}

func TestFileTypeByteSize(t *testing.T) {
	tests := []struct {
		ft   FileType
		want int
	}{
		{FileTypeInteger, 2},
		{FileTypeBit, 2},
		{FileTypeFloat, 4},
		{FileTypeLong, 4},
		{FileTypeTimer, 6},
		{FileTypeCounter, 6},
		{FileTypeControl, 6},
		{FileTypeString, 84},
	}

	for _, tc := range tests {
		if got := tc.ft.ByteSize(); got != tc.want {
			t.Errorf("FileType(%s).ByteSize() = %d, want %d", tc.ft, got, tc.want)
		}
	}
}

func TestDefaultFileNumber(t *testing.T) {
	tests := []struct {
		ft   FileType
		want uint8
	}{
		{FileTypeOutput, 0},
		{FileTypeInput, 1},
		{FileTypeStatus, 2},
		{FileTypeBit, 3},
		{FileTypeTimer, 4},
		{FileTypeCounter, 5},
		{FileTypeControl, 6},
		{FileTypeInteger, 7},
		{FileTypeFloat, 8},
		{FileTypeString, 9},
	}

	for _, tc := range tests {
		if got := DefaultFileNumber(tc.ft); got != tc.want {
			t.Errorf("DefaultFileNumber(%s) = %d, want %d", tc.ft, got, tc.want)
		}
	}
}
