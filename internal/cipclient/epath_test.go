package cipclient

import (
	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"testing"
)

func TestParseEPATH8BitSegments(t *testing.T) {
	data := []byte{0x20, 0x01, 0x24, 0x02, 0x30, 0x03}
	info, err := protocol.ParseEPATH(data)
	if err != nil {
		t.Fatalf("protocol.ParseEPATH failed: %v", err)
	}
	if info.Path.Class != 0x01 || info.Path.Instance != 0x02 || info.Path.Attribute != 0x03 {
		t.Fatalf("Unexpected path: class=0x%04X instance=0x%04X attr=0x%04X", info.Path.Class, info.Path.Instance, info.Path.Attribute)
	}
	if info.ClassIs16 || info.InstanceIs16 || info.AttributeIs16 {
		t.Fatalf("Unexpected 16-bit flags: class=%v instance=%v attr=%v", info.ClassIs16, info.InstanceIs16, info.AttributeIs16)
	}
}

func TestParseEPATH16BitSegments(t *testing.T) {
	data := []byte{
		0x21, 0x67, 0x00,
		0x25, 0x01, 0x00,
		0x31, 0x10, 0x00,
	}
	info, err := protocol.ParseEPATH(data)
	if err != nil {
		t.Fatalf("protocol.ParseEPATH failed: %v", err)
	}
	if info.Path.Class != 0x0067 || info.Path.Instance != 0x0001 || info.Path.Attribute != 0x0010 {
		t.Fatalf("Unexpected path: class=0x%04X instance=0x%04X attr=0x%04X", info.Path.Class, info.Path.Instance, info.Path.Attribute)
	}
	if !info.ClassIs16 || !info.InstanceIs16 || !info.AttributeIs16 {
		t.Fatalf("Expected 16-bit flags set: class=%v instance=%v attr=%v", info.ClassIs16, info.InstanceIs16, info.AttributeIs16)
	}
}

func TestParseEPATHWithPortSegment(t *testing.T) {
	data := []byte{
		0x01, 0x05,
		0x20, 0x06,
		0x24, 0x01,
	}
	info, err := protocol.ParseEPATH(data)
	if err != nil {
		t.Fatalf("protocol.ParseEPATH failed: %v", err)
	}
	if info.Path.Class != 0x06 || info.Path.Instance != 0x01 {
		t.Fatalf("Unexpected path: class=0x%04X instance=0x%04X", info.Path.Class, info.Path.Instance)
	}
}
