package cipclient

import (
	"github.com/tturner/cipdip/internal/cip/protocol"
	"testing"
)

func TestSymbolicEPATHRoundTrip(t *testing.T) {
	tag := "Program.Main.Pressure"
	epath := protocol.BuildSymbolicEPATH(tag)
	if len(epath) == 0 {
		t.Fatalf("protocol.BuildSymbolicEPATH returned empty data")
	}
	decoded, err := protocol.DecodeSymbolicEPATH(epath)
	if err != nil {
		t.Fatalf("protocol.DecodeSymbolicEPATH failed: %v", err)
	}
	if decoded != tag {
		t.Fatalf("Expected tag %q, got %q", tag, decoded)
	}
}

func TestDecodeSymbolicEPATHRejectsNonSymbolic(t *testing.T) {
	_, err := protocol.DecodeSymbolicEPATH([]byte{0x20, 0x01})
	if err == nil {
		t.Fatalf("Expected error for non-symbolic EPATH")
	}
}
