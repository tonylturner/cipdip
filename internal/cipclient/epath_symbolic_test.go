package cipclient

import "testing"

func TestSymbolicEPATHRoundTrip(t *testing.T) {
	tag := "Program.Main.Pressure"
	epath := BuildSymbolicEPATH(tag)
	if len(epath) == 0 {
		t.Fatalf("BuildSymbolicEPATH returned empty data")
	}
	decoded, err := DecodeSymbolicEPATH(epath)
	if err != nil {
		t.Fatalf("DecodeSymbolicEPATH failed: %v", err)
	}
	if decoded != tag {
		t.Fatalf("Expected tag %q, got %q", tag, decoded)
	}
}

func TestDecodeSymbolicEPATHRejectsNonSymbolic(t *testing.T) {
	_, err := DecodeSymbolicEPATH([]byte{0x20, 0x01})
	if err == nil {
		t.Fatalf("Expected error for non-symbolic EPATH")
	}
}
