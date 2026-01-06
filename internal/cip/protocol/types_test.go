package protocol

import "testing"

func TestCIPTypeNameAndCode(t *testing.T) {
	cases := []struct {
		code CIPDataType
		name string
	}{
		{CIPTypeBOOL, "BOOL"},
		{CIPTypeSINT, "SINT"},
		{CIPTypeINT, "INT"},
		{CIPTypeDINT, "DINT"},
		{CIPTypeLINT, "LINT"},
		{CIPTypeREAL, "REAL"},
		{CIPTypeLREAL, "LREAL"},
		{CIPTypeSTR, "STRING"},
	}
	for _, tc := range cases {
		if got := CIPTypeName(tc.code); got != tc.name {
			t.Fatalf("CIPTypeName(%v) = %s, want %s", tc.code, got, tc.name)
		}
		if got := CIPTypeCode(tc.name); got != tc.code {
			t.Fatalf("CIPTypeCode(%s) = %v, want %v", tc.name, got, tc.code)
		}
	}
	if got := CIPTypeName(0x9999); got != "UNKNOWN(0x9999)" {
		t.Fatalf("CIPTypeName(0x9999) = %s, want UNKNOWN(0x9999)", got)
	}
	if got := CIPTypeCode("UNKNOWN"); got != CIPTypeDINT {
		t.Fatalf("CIPTypeCode(UNKNOWN) = %v, want %v", got, CIPTypeDINT)
	}
}
