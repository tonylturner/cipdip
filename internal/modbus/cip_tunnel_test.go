package modbus

import (
	"strings"
	"testing"
)

func TestCIPTunnelRequestRoundTrip(t *testing.T) {
	req := Request{
		UnitID:   0x01,
		Function: FcReadHoldingRegisters,
		Data:     ReadHoldingRegistersRequest(0x0000, 10),
	}
	payload := EncodeCIPTunnelRequest(req)

	decoded, err := DecodeCIPTunnelRequest(payload, req.UnitID)
	if err != nil {
		t.Fatalf("DecodeCIPTunnelRequest: %v", err)
	}
	if decoded.Function != req.Function {
		t.Errorf("Function = 0x%02X, want 0x%02X", decoded.Function, req.Function)
	}
	if decoded.UnitID != req.UnitID {
		t.Errorf("UnitID = %d, want %d", decoded.UnitID, req.UnitID)
	}
	if len(decoded.Data) != len(req.Data) {
		t.Fatalf("Data len = %d, want %d", len(decoded.Data), len(req.Data))
	}
}

func TestCIPTunnelResponseRoundTrip(t *testing.T) {
	resp := Response{
		UnitID:   0x01,
		Function: FcReadHoldingRegisters,
		Data:     []byte{0x04, 0x00, 0x0A, 0x00, 0x14},
	}
	payload := EncodeCIPTunnelResponse(resp)

	decoded, err := DecodeCIPTunnelResponse(payload, resp.UnitID)
	if err != nil {
		t.Fatalf("DecodeCIPTunnelResponse: %v", err)
	}
	if decoded.Function != resp.Function {
		t.Errorf("Function = 0x%02X, want 0x%02X", decoded.Function, resp.Function)
	}
}

func TestCIPTunnelDecodeEmpty(t *testing.T) {
	_, err := DecodeCIPTunnelRequest(nil, 1)
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
	_, err = DecodeCIPTunnelResponse(nil, 1)
	if err == nil {
		t.Fatal("expected error for empty response payload")
	}
}

func TestIsCIPModbusPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    bool
	}{
		{"ReadCoils", []byte{byte(FcReadCoils), 0x00, 0x00, 0x00, 0x0A}, true},
		{"WriteMultiple", []byte{byte(FcWriteMultipleRegisters), 0x00, 0x01}, true},
		{"Exception", []byte{byte(FcReadCoils) | 0x80, 0x01}, true},
		{"UnknownFC", []byte{0x50, 0x00}, false},
		{"Empty", nil, false},
		{"DiagFC", []byte{byte(FcDiagnostics), 0x00, 0x00}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsCIPModbusPayload(tt.payload)
			if got != tt.want {
				t.Errorf("IsCIPModbusPayload = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDescribeCIPModbus(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		contains string
	}{
		{
			"ReadHolding",
			[]byte{byte(FcReadHoldingRegisters), 0x00, 0x00, 0x00, 0x0A},
			"Read_Holding_Registers",
		},
		{
			"Exception",
			[]byte{byte(FcReadCoils) | 0x80, byte(ExceptionIllegalFunction)},
			"Illegal_Function",
		},
		{
			"Empty",
			nil,
			"empty",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DescribeCIPModbus(tt.payload)
			if !strings.Contains(got, tt.contains) {
				t.Errorf("DescribeCIPModbus = %q, want containing %q", got, tt.contains)
			}
		})
	}
}

func TestCIPModbusClass(t *testing.T) {
	if CIPModbusClass != 0x44 {
		t.Errorf("CIPModbusClass = 0x%04X, want 0x0044", CIPModbusClass)
	}
}
