package cipclient

import (
	"math"
	"testing"
)

func TestCIPTypeNameAndCode(t *testing.T) {
	cases := []struct {
		name string
		code CIPDataType
	}{
		{"BOOL", CIPTypeBOOL},
		{"SINT", CIPTypeSINT},
		{"INT", CIPTypeINT},
		{"DINT", CIPTypeDINT},
		{"LINT", CIPTypeLINT},
		{"REAL", CIPTypeREAL},
		{"LREAL", CIPTypeLREAL},
		{"STRING", CIPTypeSTR},
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
		t.Fatalf("unexpected unknown name: %s", got)
	}
	if got := CIPTypeCode("UNKNOWN"); got != CIPTypeDINT {
		t.Fatalf("unexpected default type code: %v", got)
	}
}

func TestEncodeDecodeCIPValueRoundTrip(t *testing.T) {
	cases := []struct {
		dt    CIPDataType
		value any
	}{
		{CIPTypeBOOL, true},
		{CIPTypeSINT, int8(-4)},
		{CIPTypeINT, int16(-1234)},
		{CIPTypeDINT, int32(123456)},
		{CIPTypeLINT, int64(-999999)},
		{CIPTypeREAL, float32(3.14)},
		{CIPTypeLREAL, float64(-12.5)},
		{CIPTypeSTR, "cipdip"},
	}

	for _, tc := range cases {
		encoded, err := EncodeCIPValue(tc.dt, tc.value)
		if err != nil {
			t.Fatalf("EncodeCIPValue(%v) error: %v", tc.dt, err)
		}
		decoded, used, err := DecodeCIPValue(tc.dt, encoded)
		if err != nil {
			t.Fatalf("DecodeCIPValue(%v) error: %v", tc.dt, err)
		}
		if used != len(encoded) {
			t.Fatalf("DecodeCIPValue(%v) used %d bytes, want %d", tc.dt, used, len(encoded))
		}

		switch v := decoded.(type) {
		case float32:
			want := tc.value.(float32)
			if math.Abs(float64(v-want)) > 0.0001 {
				t.Fatalf("REAL mismatch: got %v want %v", v, want)
			}
		case float64:
			want := tc.value.(float64)
			if math.Abs(v-want) > 0.0000001 {
				t.Fatalf("LREAL mismatch: got %v want %v", v, want)
			}
		default:
			if decoded != tc.value {
				t.Fatalf("value mismatch for %v: got %#v want %#v", tc.dt, decoded, tc.value)
			}
		}
	}
}

func TestDecodeCIPValueErrors(t *testing.T) {
	if _, _, err := DecodeCIPValue(CIPTypeDINT, []byte{0x01, 0x02}); err == nil {
		t.Fatalf("expected DINT short read error")
	}
	if _, _, err := DecodeCIPValue(CIPTypeSTR, []byte{0x05, 0x00, 0x01}); err == nil {
		t.Fatalf("expected STRING length error")
	}
}

func TestEncodeCIPValueErrors(t *testing.T) {
	if _, err := EncodeCIPValue(CIPTypeBOOL, 123); err == nil {
		t.Fatalf("expected BOOL type error")
	}
	if _, err := EncodeCIPValue(CIPTypeINT, "bad"); err == nil {
		t.Fatalf("expected INT type error")
	}
	if _, err := EncodeCIPValue(CIPTypeSTR, 12); err == nil {
		t.Fatalf("expected STRING type error")
	}
}
