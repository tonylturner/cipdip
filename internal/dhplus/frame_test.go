package dhplus

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeFrame(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
	}{
		{
			name: "typed_read_request",
			frame: Frame{
				Dst:     0x05,
				Src:     0x01,
				Command: CmdTypedRead,
				Status:  0x00,
				TNS:     0x1234,
				Data:    []byte{0x02, 0x07, 0x89, 0x00},
			},
		},
		{
			name: "typed_write_request",
			frame: Frame{
				Dst:     0x03,
				Src:     0x01,
				Command: CmdTypedWrite,
				Status:  0x00,
				TNS:     0xABCD,
				Data:    []byte{0x02, 0x07, 0x89, 0x05, 0x64, 0x00},
			},
		},
		{
			name: "diagnostic_status",
			frame: Frame{
				Dst:     0x10,
				Src:     0x01,
				Command: CmdDiagnosticStatus,
				Status:  0x00,
				TNS:     0x0001,
			},
		},
		{
			name: "response_frame",
			frame: Frame{
				Dst:     0x01,
				Src:     0x05,
				Command: CmdTypedRead,
				Status:  0x00,
				TNS:     0x1234,
				Data:    []byte{0x64, 0x00},
			},
		},
		{
			name: "max_node_addresses",
			frame: Frame{
				Dst:     MaxNodeAddress,
				Src:     MaxNodeAddress - 1,
				Command: CmdUnprotectedRead,
				Status:  0x00,
				TNS:     0x0000,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := EncodeFrame(tc.frame)
			if err != nil {
				t.Fatalf("EncodeFrame: %v", err)
			}

			decoded, err := DecodeFrame(encoded)
			if err != nil {
				t.Fatalf("DecodeFrame: %v", err)
			}

			if decoded.Dst != tc.frame.Dst {
				t.Errorf("Dst: got %d, want %d", decoded.Dst, tc.frame.Dst)
			}
			if decoded.Src != tc.frame.Src {
				t.Errorf("Src: got %d, want %d", decoded.Src, tc.frame.Src)
			}
			if decoded.Command != tc.frame.Command {
				t.Errorf("Command: got 0x%02X, want 0x%02X", decoded.Command, tc.frame.Command)
			}
			if decoded.Status != tc.frame.Status {
				t.Errorf("Status: got 0x%02X, want 0x%02X", decoded.Status, tc.frame.Status)
			}
			if decoded.TNS != tc.frame.TNS {
				t.Errorf("TNS: got 0x%04X, want 0x%04X", decoded.TNS, tc.frame.TNS)
			}
			if !bytes.Equal(decoded.Data, tc.frame.Data) {
				t.Errorf("Data: got %x, want %x", decoded.Data, tc.frame.Data)
			}
		})
	}
}

func TestEncodeFrameInvalidNode(t *testing.T) {
	f := Frame{Dst: 64, Src: 0, Command: CmdTypedRead}
	if _, err := EncodeFrame(f); err == nil {
		t.Fatal("expected error for dst > 63")
	}

	f = Frame{Dst: 0, Src: 64, Command: CmdTypedRead}
	if _, err := EncodeFrame(f); err == nil {
		t.Fatal("expected error for src > 63")
	}
}

func TestDecodeFrameTooShort(t *testing.T) {
	_, err := DecodeFrame([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("expected error for short frame")
	}
}

func TestValidateFrame(t *testing.T) {
	valid := Frame{Dst: 5, Src: 1, Command: CmdTypedRead}
	if err := ValidateFrame(valid); err != nil {
		t.Errorf("ValidateFrame valid: %v", err)
	}

	invalid := Frame{Dst: 100, Src: 1}
	if err := ValidateFrame(invalid); err == nil {
		t.Error("expected error for dst > 63")
	}
}

func TestFrameHeaderSize(t *testing.T) {
	f := Frame{Dst: 1, Src: 2, Command: CmdDiagnosticStatus, TNS: 0x0001}
	encoded, err := EncodeFrame(f)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	if len(encoded) != HeaderSize {
		t.Errorf("frame without data: got %d bytes, want %d", len(encoded), HeaderSize)
	}
}

func TestCommandCodeString(t *testing.T) {
	tests := []struct {
		cmd  CommandCode
		want string
	}{
		{CmdTypedRead, "Typed_Read"},
		{CmdTypedWrite, "Typed_Write"},
		{CmdDiagnosticStatus, "Diagnostic_Status"},
		{CmdProtectedWrite, "Protected_Write"},
		{CommandCode(0xFF), "Unknown"},
	}

	for _, tc := range tests {
		if got := tc.cmd.String(); got != tc.want {
			t.Errorf("CommandCode(0x%02X).String() = %q, want %q", uint8(tc.cmd), got, tc.want)
		}
	}
}

func TestCommandCodeIsReadWrite(t *testing.T) {
	reads := []CommandCode{CmdUnprotectedRead, CmdProtectedRead, CmdTypedRead, CmdWordRangeRead, CmdDiagnosticStatus}
	for _, cmd := range reads {
		if !cmd.IsRead() {
			t.Errorf("%s should be read", cmd)
		}
	}

	writes := []CommandCode{CmdProtectedWrite, CmdUnprotectedWrite, CmdTypedWrite, CmdWordRangeWrite}
	for _, cmd := range writes {
		if !cmd.IsWrite() {
			t.Errorf("%s should be write", cmd)
		}
	}
}
