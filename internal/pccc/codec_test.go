package pccc

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeRequest(t *testing.T) {
	tests := []struct {
		name string
		req  Request
	}{
		{
			name: "extended_typed_read",
			req: Request{
				Command:  CmdExtended,
				Status:   0,
				TNS:      0x1234,
				Function: FncTypedRead,
				Data:     []byte{0x02, 0x07, 0x89, 0x00},
			},
		},
		{
			name: "extended_typed_write",
			req: Request{
				Command:  CmdExtended,
				Status:   0,
				TNS:      0xABCD,
				Function: FncTypedWrite,
				Data:     []byte{0x02, 0x07, 0x89, 0x00, 0xFF, 0x00},
			},
		},
		{
			name: "extended_echo",
			req: Request{
				Command:  CmdExtended,
				Status:   0,
				TNS:      0x0001,
				Function: FncEcho,
				Data:     []byte{0xDE, 0xAD, 0xBE, 0xEF},
			},
		},
		{
			name: "protected_read_no_fnc",
			req: Request{
				Command: CmdProtectedRead,
				Status:  0,
				TNS:     0x5678,
				Data:    []byte{0x01, 0x02},
			},
		},
		{
			name: "extended_no_data",
			req: Request{
				Command:  CmdExtended,
				Status:   0,
				TNS:      0x0010,
				Function: FncDiagnosticRead,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := EncodeRequest(tc.req)
			decoded, err := DecodeRequest(encoded)
			if err != nil {
				t.Fatalf("DecodeRequest failed: %v", err)
			}

			if decoded.Command != tc.req.Command {
				t.Errorf("Command: got 0x%02X, want 0x%02X", decoded.Command, tc.req.Command)
			}
			if decoded.Status != tc.req.Status {
				t.Errorf("Status: got 0x%02X, want 0x%02X", decoded.Status, tc.req.Status)
			}
			if decoded.TNS != tc.req.TNS {
				t.Errorf("TNS: got 0x%04X, want 0x%04X", decoded.TNS, tc.req.TNS)
			}
			if decoded.Function != tc.req.Function {
				t.Errorf("Function: got 0x%02X, want 0x%02X", decoded.Function, tc.req.Function)
			}
			if !bytes.Equal(decoded.Data, tc.req.Data) {
				t.Errorf("Data: got %x, want %x", decoded.Data, tc.req.Data)
			}
		})
	}
}

func TestEncodeDecodeResponse(t *testing.T) {
	tests := []struct {
		name string
		resp Response
	}{
		{
			name: "success_with_data",
			resp: Response{
				Command:  CmdExtended,
				Status:   0,
				TNS:      0x1234,
				Function: FncTypedRead,
				Data:     []byte{0x00, 0x64}, // N7:0 = 100
			},
		},
		{
			name: "error_response",
			resp: Response{
				Command:  CmdExtended,
				Status:   0x10, // Illegal command
				TNS:      0x1234,
				Function: FncTypedRead,
				ExtSTS:   0x01,
			},
		},
		{
			name: "simple_command_success",
			resp: Response{
				Command: CmdProtectedRead,
				Status:  0,
				TNS:     0x5678,
				Data:    []byte{0x01, 0x02, 0x03},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := EncodeResponse(tc.resp)
			decoded, err := DecodeResponse(encoded)
			if err != nil {
				t.Fatalf("DecodeResponse failed: %v", err)
			}

			if decoded.Command != tc.resp.Command {
				t.Errorf("Command: got 0x%02X, want 0x%02X", decoded.Command, tc.resp.Command)
			}
			if decoded.Status != tc.resp.Status {
				t.Errorf("Status: got 0x%02X, want 0x%02X", decoded.Status, tc.resp.Status)
			}
			if decoded.TNS != tc.resp.TNS {
				t.Errorf("TNS: got 0x%04X, want 0x%04X", decoded.TNS, tc.resp.TNS)
			}
			if decoded.Function != tc.resp.Function {
				t.Errorf("Function: got 0x%02X, want 0x%02X", decoded.Function, tc.resp.Function)
			}
			if tc.resp.Status != 0 && decoded.ExtSTS != tc.resp.ExtSTS {
				t.Errorf("ExtSTS: got 0x%02X, want 0x%02X", decoded.ExtSTS, tc.resp.ExtSTS)
			}
			if !bytes.Equal(decoded.Data, tc.resp.Data) {
				t.Errorf("Data: got %x, want %x", decoded.Data, tc.resp.Data)
			}
		})
	}
}

func TestDecodeRequestTooShort(t *testing.T) {
	_, err := DecodeRequest([]byte{0x0F, 0x00, 0x01})
	if err == nil {
		t.Fatal("expected error for short request")
	}
}

func TestDecodeResponseTooShort(t *testing.T) {
	_, err := DecodeResponse([]byte{0x0F})
	if err == nil {
		t.Fatal("expected error for short response")
	}
}

func TestDecodeExtendedMissingFnc(t *testing.T) {
	_, err := DecodeRequest([]byte{0x0F, 0x00, 0x01, 0x00})
	if err == nil {
		t.Fatal("expected error for extended command without function code")
	}
}

func TestTypedReadRequest(t *testing.T) {
	addr, err := ParseAddress("N7:0")
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}

	req := TypedReadRequest(0x0001, addr, 2)

	if req.Command != CmdExtended {
		t.Errorf("Command: got 0x%02X, want 0x%02X", req.Command, CmdExtended)
	}
	if req.Function != FncTypedRead {
		t.Errorf("Function: got 0x%02X, want 0x%02X", req.Function, FncTypedRead)
	}

	// Data: byte_count=2, file=7, type=0x89(N), element=0
	expected := []byte{0x02, 0x07, 0x89, 0x00}
	if !bytes.Equal(req.Data, expected) {
		t.Errorf("Data: got %x, want %x", req.Data, expected)
	}
}

func TestTypedWriteRequest(t *testing.T) {
	addr, err := ParseAddress("N7:5")
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}

	writeData := []byte{0x64, 0x00} // int16 = 100
	req := TypedWriteRequest(0x0002, addr, writeData)

	if req.Command != CmdExtended {
		t.Errorf("Command: got 0x%02X, want 0x%02X", req.Command, CmdExtended)
	}
	if req.Function != FncTypedWrite {
		t.Errorf("Function: got 0x%02X, want 0x%02X", req.Function, FncTypedWrite)
	}

	// Data: byte_count=2, file=7, type=0x89(N), element=5, then write data
	expected := []byte{0x02, 0x07, 0x89, 0x05, 0x64, 0x00}
	if !bytes.Equal(req.Data, expected) {
		t.Errorf("Data: got %x, want %x", req.Data, expected)
	}
}

func TestTypedReadRequestWithSubElement(t *testing.T) {
	addr, err := ParseAddress("T4:2.ACC")
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}

	req := TypedReadRequest(0x0003, addr, 2)

	// Data: byte_count=2, file=4, type=0x86(T), element=2, sub=2(ACC)
	expected := []byte{0x02, 0x04, 0x86, 0x02, 0x02}
	if !bytes.Equal(req.Data, expected) {
		t.Errorf("Data: got %x, want %x", req.Data, expected)
	}
}

func TestEchoRequest(t *testing.T) {
	payload := []byte{0xDE, 0xAD}
	req := EchoRequest(0x0100, payload)

	if req.Command != CmdExtended {
		t.Errorf("Command: got 0x%02X, want 0x%02X", req.Command, CmdExtended)
	}
	if req.Function != FncEcho {
		t.Errorf("Function: got 0x%02X, want 0x%02X", req.Function, FncEcho)
	}
	if !bytes.Equal(req.Data, payload) {
		t.Errorf("Data: got %x, want %x", req.Data, payload)
	}
}

func TestIsPCCCPayload(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "valid_extended_typed_read",
			data: []byte{0x0F, 0x00, 0x01, 0x00, 0x68, 0x02, 0x07, 0x89, 0x00},
			want: true,
		},
		{
			name: "valid_protected_read",
			data: []byte{0x05, 0x00, 0x01, 0x00},
			want: true,
		},
		{
			name: "too_short",
			data: []byte{0x0F, 0x00},
			want: false,
		},
		{
			name: "unknown_command",
			data: []byte{0xFF, 0x00, 0x01, 0x00},
			want: false,
		},
		{
			name: "bad_status",
			data: []byte{0x0F, 0x80, 0x01, 0x00, 0x68},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsPCCCPayload(tc.data); got != tc.want {
				t.Errorf("IsPCCCPayload(%x) = %v, want %v", tc.data, got, tc.want)
			}
		})
	}
}

func TestDecodeTypedReadData(t *testing.T) {
	// Typed read for N7:0, 2 bytes
	data := []byte{0x02, 0x07, 0x89, 0x00}
	byteCount, addr, remaining, err := DecodeTypedReadData(data)
	if err != nil {
		t.Fatalf("DecodeTypedReadData: %v", err)
	}
	if byteCount != 2 {
		t.Errorf("byteCount: got %d, want 2", byteCount)
	}
	if addr.FileNumber != 7 {
		t.Errorf("FileNumber: got %d, want 7", addr.FileNumber)
	}
	if addr.FileType != FileTypeInteger {
		t.Errorf("FileType: got 0x%02X, want 0x%02X", addr.FileType, FileTypeInteger)
	}
	if addr.Element != 0 {
		t.Errorf("Element: got %d, want 0", addr.Element)
	}
	if len(remaining) != 0 {
		t.Errorf("remaining: got %x, want empty", remaining)
	}
}

func TestDecodeTypedReadDataTooShort(t *testing.T) {
	_, _, _, err := DecodeTypedReadData([]byte{0x02, 0x07})
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestFunctionCodeString(t *testing.T) {
	tests := []struct {
		fnc  FunctionCode
		want string
	}{
		{FncTypedRead, "Typed_Read"},
		{FncTypedWrite, "Typed_Write"},
		{FncEcho, "Echo"},
		{FunctionCode(0xFF), "Unknown"},
	}

	for _, tc := range tests {
		if got := tc.fnc.String(); got != tc.want {
			t.Errorf("FunctionCode(0x%02X).String() = %q, want %q", uint8(tc.fnc), got, tc.want)
		}
	}
}

func TestFunctionCodeIsReadWrite(t *testing.T) {
	if !FncTypedRead.IsRead() {
		t.Error("FncTypedRead should be read")
	}
	if FncTypedRead.IsWrite() {
		t.Error("FncTypedRead should not be write")
	}
	if !FncTypedWrite.IsWrite() {
		t.Error("FncTypedWrite should be write")
	}
	if FncTypedWrite.IsRead() {
		t.Error("FncTypedWrite should not be read")
	}
}

func TestCommandString(t *testing.T) {
	if got := CmdExtended.String(); got != "Extended" {
		t.Errorf("CmdExtended.String() = %q, want %q", got, "Extended")
	}
	if got := CmdProtectedRead.String(); got != "Protected_Read" {
		t.Errorf("CmdProtectedRead.String() = %q, want %q", got, "Protected_Read")
	}
}
