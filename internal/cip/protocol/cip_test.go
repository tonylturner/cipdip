package protocol

import (
	"encoding/binary"
	"testing"
)

func TestEncodeEPATH_8Bit(t *testing.T) {
	path := CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x01}
	epath := EncodeEPATH(path)

	// 8-bit: class(0x20, 0x01) + instance(0x24, 0x01) + attribute(0x30, 0x01)
	if len(epath) != 6 {
		t.Fatalf("EncodeEPATH len = %d, want 6", len(epath))
	}
	if epath[0] != 0x20 || epath[1] != 0x01 {
		t.Errorf("class segment = [%02X %02X], want [20 01]", epath[0], epath[1])
	}
	if epath[2] != 0x24 || epath[3] != 0x01 {
		t.Errorf("instance segment = [%02X %02X], want [24 01]", epath[2], epath[3])
	}
	if epath[4] != 0x30 || epath[5] != 0x01 {
		t.Errorf("attribute segment = [%02X %02X], want [30 01]", epath[4], epath[5])
	}
}

func TestEncodeEPATH_16Bit(t *testing.T) {
	path := CIPPath{Class: 0x0100, Instance: 0x0200, Attribute: 0x0300}
	epath := EncodeEPATH(path)

	// 16-bit: class(0x21, lo, hi) + instance(0x25, lo, hi) + attribute(0x31, lo, hi)
	if len(epath) != 9 {
		t.Fatalf("EncodeEPATH len = %d, want 9", len(epath))
	}
	if epath[0] != 0x21 {
		t.Errorf("class segment type = 0x%02X, want 0x21", epath[0])
	}
	classVal := binary.LittleEndian.Uint16(epath[1:3])
	if classVal != 0x0100 {
		t.Errorf("class = 0x%04X, want 0x0100", classVal)
	}
	if epath[3] != 0x25 {
		t.Errorf("instance segment type = 0x%02X, want 0x25", epath[3])
	}
	if epath[6] != 0x31 {
		t.Errorf("attribute segment type = 0x%02X, want 0x31", epath[6])
	}
}

func TestEncodeEPATH_Mixed(t *testing.T) {
	// 8-bit class, 16-bit instance, 8-bit attribute
	path := CIPPath{Class: 0x04, Instance: 0x0100, Attribute: 0x03}
	epath := EncodeEPATH(path)

	if epath[0] != 0x20 {
		t.Errorf("class should be 8-bit (0x20), got 0x%02X", epath[0])
	}
	if epath[2] != 0x25 {
		t.Errorf("instance should be 16-bit (0x25), got 0x%02X", epath[2])
	}
}

func TestDecodeEPATH_8Bit(t *testing.T) {
	// class=0x01, instance=0x01, attribute=0x03
	data := []byte{0x20, 0x01, 0x24, 0x01, 0x30, 0x03}
	path, err := DecodeEPATH(data)
	if err != nil {
		t.Fatalf("DecodeEPATH: %v", err)
	}
	if path.Class != 0x01 || path.Instance != 0x01 || path.Attribute != 0x03 {
		t.Errorf("path = {%d, %d, %d}, want {1, 1, 3}", path.Class, path.Instance, path.Attribute)
	}
}

func TestDecodeEPATH_16BitClass(t *testing.T) {
	data := []byte{0x21, 0x00, 0x01, 0x24, 0x01}
	info, err := ParseEPATH(data)
	if err != nil {
		t.Fatalf("ParseEPATH: %v", err)
	}
	if info.Path.Class != 0x0100 {
		t.Errorf("class = 0x%04X, want 0x0100", info.Path.Class)
	}
	if !info.ClassIs16 {
		t.Error("ClassIs16 should be true")
	}
}

func TestDecodeEPATH_Errors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"incomplete class", []byte{0x20}},
		{"incomplete 16-bit class", []byte{0x21, 0x00}},
		{"incomplete instance", []byte{0x20, 0x01, 0x24}},
		{"incomplete 16-bit instance", []byte{0x20, 0x01, 0x25, 0x00}},
		{"incomplete attribute", []byte{0x20, 0x01, 0x24, 0x01, 0x30}},
		{"incomplete 16-bit attribute", []byte{0x20, 0x01, 0x24, 0x01, 0x31, 0x00}},
		{"invalid segment", []byte{0x20, 0x01, 0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeEPATH(tt.data)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestDecodeEPATH_SkipsPadding(t *testing.T) {
	// Leading zero byte (padding) should be skipped
	data := []byte{0x00, 0x20, 0x01, 0x24, 0x01, 0x30, 0x03}
	path, err := DecodeEPATH(data)
	if err != nil {
		t.Fatalf("DecodeEPATH: %v", err)
	}
	if path.Class != 0x01 {
		t.Errorf("class = 0x%04X, want 0x01", path.Class)
	}
}

func TestEncodeDecodeEPATH_RoundTrip(t *testing.T) {
	original := CIPPath{Class: 0x04, Instance: 0x65, Attribute: 0x03}
	encoded := EncodeEPATH(original)
	decoded, err := DecodeEPATH(encoded)
	if err != nil {
		t.Fatalf("round trip error: %v", err)
	}
	if decoded.Class != original.Class || decoded.Instance != original.Instance || decoded.Attribute != original.Attribute {
		t.Errorf("round trip mismatch: got {%d, %d, %d}, want {%d, %d, %d}",
			decoded.Class, decoded.Instance, decoded.Attribute,
			original.Class, original.Instance, original.Attribute)
	}
}

func TestEncodeCIPRequest(t *testing.T) {
	SetOptions(Options{
		ByteOrder:       binary.LittleEndian,
		IncludePathSize: true,
	})
	defer SetOptions(Options{
		ByteOrder:           binary.LittleEndian,
		IncludePathSize:     true,
		IncludeRespReserved: true,
	})

	req := CIPRequest{
		Service: 0x0E,
		Path:    CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x01},
	}

	data, err := EncodeCIPRequest(req)
	if err != nil {
		t.Fatalf("EncodeCIPRequest: %v", err)
	}

	if data[0] != 0x0E {
		t.Errorf("service = 0x%02X, want 0x0E", data[0])
	}

	// Path size should be 3 words (6 bytes)
	if data[1] != 3 {
		t.Errorf("path size = %d words, want 3", data[1])
	}
}

func TestEncodeCIPRequest_WithPayload(t *testing.T) {
	SetOptions(Options{
		ByteOrder:       binary.LittleEndian,
		IncludePathSize: true,
	})
	defer SetOptions(Options{
		ByteOrder:           binary.LittleEndian,
		IncludePathSize:     true,
		IncludeRespReserved: true,
	})

	req := CIPRequest{
		Service: 0x10,
		Path:    CIPPath{Class: 0x04, Instance: 0x64, Attribute: 0x03},
		Payload: []byte{0x01, 0x00},
	}

	data, err := EncodeCIPRequest(req)
	if err != nil {
		t.Fatalf("EncodeCIPRequest: %v", err)
	}

	// Last 2 bytes should be payload
	if data[len(data)-2] != 0x01 || data[len(data)-1] != 0x00 {
		t.Errorf("payload = [%02X %02X], want [01 00]", data[len(data)-2], data[len(data)-1])
	}
}

func TestEncodeCIPRequest_RawPath(t *testing.T) {
	SetOptions(Options{
		ByteOrder:       binary.LittleEndian,
		IncludePathSize: true,
	})
	defer SetOptions(Options{
		ByteOrder:           binary.LittleEndian,
		IncludePathSize:     true,
		IncludeRespReserved: true,
	})

	rawPath := []byte{0x20, 0x01, 0x24, 0x01}
	req := CIPRequest{
		Service: 0x0E,
		RawPath: rawPath,
	}

	data, err := EncodeCIPRequest(req)
	if err != nil {
		t.Fatalf("EncodeCIPRequest: %v", err)
	}

	// Path size = 2 words
	if data[1] != 2 {
		t.Errorf("path size = %d, want 2", data[1])
	}
}

func TestDecodeCIPRequest(t *testing.T) {
	SetOptions(Options{
		ByteOrder:       binary.LittleEndian,
		IncludePathSize: true,
	})
	defer SetOptions(Options{
		ByteOrder:           binary.LittleEndian,
		IncludePathSize:     true,
		IncludeRespReserved: true,
	})

	// Service 0x0E, path size 3 words, class 0x01, instance 0x01, attribute 0x01
	data := []byte{0x0E, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x01}
	req, err := DecodeCIPRequest(data)
	if err != nil {
		t.Fatalf("DecodeCIPRequest: %v", err)
	}

	if req.Service != 0x0E {
		t.Errorf("service = 0x%02X, want 0x0E", req.Service)
	}
	if req.Path.Class != 0x01 || req.Path.Instance != 0x01 || req.Path.Attribute != 0x01 {
		t.Errorf("path = {%d, %d, %d}, want {1, 1, 1}", req.Path.Class, req.Path.Instance, req.Path.Attribute)
	}
}

func TestDecodeCIPRequest_Errors(t *testing.T) {
	SetOptions(Options{
		ByteOrder:       binary.LittleEndian,
		IncludePathSize: true,
	})
	defer SetOptions(Options{
		ByteOrder:           binary.LittleEndian,
		IncludePathSize:     true,
		IncludeRespReserved: true,
	})

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"missing path size", []byte{0x0E}},
		{"incomplete path", []byte{0x0E, 0x03, 0x20, 0x01}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeCIPRequest(tt.data)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestEncodeCIPResponse(t *testing.T) {
	SetOptions(Options{
		ByteOrder:           binary.LittleEndian,
		IncludePathSize:     true,
		IncludeRespReserved: true,
	})

	resp := CIPResponse{
		Service: 0x8E,
		Status:  0x00,
		Payload: []byte{0x42, 0x00},
	}

	data, err := EncodeCIPResponse(resp)
	if err != nil {
		t.Fatalf("EncodeCIPResponse: %v", err)
	}

	if data[0] != 0x8E {
		t.Errorf("service = 0x%02X, want 0x8E", data[0])
	}
	if data[1] != 0x00 { // reserved
		t.Errorf("reserved = 0x%02X, want 0x00", data[1])
	}
	if data[2] != 0x00 { // status
		t.Errorf("status = 0x%02X, want 0x00", data[2])
	}
	if data[3] != 0x00 { // ext status size
		t.Errorf("ext status size = 0x%02X, want 0x00", data[3])
	}
	// Payload
	if data[4] != 0x42 || data[5] != 0x00 {
		t.Errorf("payload = [%02X %02X], want [42 00]", data[4], data[5])
	}
}

func TestEncodeCIPResponse_WithExtStatus(t *testing.T) {
	SetOptions(Options{
		ByteOrder:           binary.LittleEndian,
		IncludePathSize:     true,
		IncludeRespReserved: true,
	})

	resp := CIPResponse{
		Service:   0x8E,
		Status:    0x08,
		ExtStatus: []byte{0x01, 0x00},
	}

	data, err := EncodeCIPResponse(resp)
	if err != nil {
		t.Fatalf("EncodeCIPResponse: %v", err)
	}

	if data[2] != 0x08 {
		t.Errorf("status = 0x%02X, want 0x08", data[2])
	}
	if data[3] != 0x01 { // ext status size in words
		t.Errorf("ext status size = %d, want 1", data[3])
	}
}

func TestDecodeCIPResponse(t *testing.T) {
	SetOptions(Options{
		ByteOrder:           binary.LittleEndian,
		IncludePathSize:     true,
		IncludeRespReserved: true,
	})

	// Response: service=0x8E, reserved=0x00, status=0x00, ext_size=0x00, payload=0x42,0x00
	data := []byte{0x8E, 0x00, 0x00, 0x00, 0x42, 0x00}
	path := CIPPath{Class: 0x01, Instance: 0x01}

	resp, err := DecodeCIPResponse(data, path)
	if err != nil {
		t.Fatalf("DecodeCIPResponse: %v", err)
	}

	if resp.Service != 0x8E {
		t.Errorf("service = 0x%02X, want 0x8E", resp.Service)
	}
	if resp.Status != 0x00 {
		t.Errorf("status = 0x%02X, want 0x00", resp.Status)
	}
	if len(resp.Payload) != 2 || resp.Payload[0] != 0x42 {
		t.Errorf("payload = %v, want [42 00]", resp.Payload)
	}
}

func TestDecodeCIPResponse_Error(t *testing.T) {
	SetOptions(Options{
		ByteOrder:           binary.LittleEndian,
		IncludePathSize:     true,
		IncludeRespReserved: true,
	})

	// Response with error status=0x08 and extended status
	data := []byte{0x8E, 0x00, 0x08, 0x01, 0x01, 0x00}
	path := CIPPath{}

	resp, err := DecodeCIPResponse(data, path)
	if err != nil {
		t.Fatalf("DecodeCIPResponse: %v", err)
	}

	if resp.Status != 0x08 {
		t.Errorf("status = 0x%02X, want 0x08", resp.Status)
	}
	if len(resp.ExtStatus) != 2 {
		t.Errorf("ext status len = %d, want 2", len(resp.ExtStatus))
	}
}

func TestDecodeCIPResponse_TooShort(t *testing.T) {
	SetOptions(Options{
		ByteOrder:           binary.LittleEndian,
		IncludePathSize:     true,
		IncludeRespReserved: true,
	})

	_, err := DecodeCIPResponse([]byte{0x8E, 0x00}, CIPPath{})
	if err == nil {
		t.Error("expected error for too-short response")
	}
}

func TestLooksLikeEPATH(t *testing.T) {
	tests := []struct {
		data []byte
		want bool
	}{
		{[]byte{0x20, 0x01}, true},
		{[]byte{0x21, 0x00, 0x01}, true},
		{[]byte{0x24, 0x01}, true},
		{[]byte{0x30, 0x01}, true},
		{[]byte{0x00, 0x20}, true},
		{[]byte{0xFF, 0x01}, false},
		{[]byte{0x0E}, false},
		{nil, false},
	}

	for _, tt := range tests {
		got := LooksLikeEPATH(tt.data)
		if got != tt.want {
			t.Errorf("LooksLikeEPATH(%v) = %v, want %v", tt.data, got, tt.want)
		}
	}
}

func TestParseUnconnectedSendRequestPayload(t *testing.T) {
	// Build a minimal unconnected send payload:
	// timeout_ticks(1) + timeout_value(1) + msg_size(2) + msg_bytes + route_words(1) + reserved(1) + route
	embeddedMsg := []byte{0x0E, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x01}
	route := []byte{0x01, 0x00} // port 1, link 0

	payload := make([]byte, 0)
	payload = append(payload, 0x0A)                                  // timeout ticks
	payload = append(payload, 0x06)                                  // timeout value
	payload = append(payload, byte(len(embeddedMsg)), 0x00)          // msg size LE
	payload = append(payload, embeddedMsg...)                         // embedded message
	payload = append(payload, byte(len(route)/2))                    // route words
	payload = append(payload, 0x00)                                  // reserved
	payload = append(payload, route...)                               // route path

	msg, routePath, ok := ParseUnconnectedSendRequestPayload(payload)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(msg) != len(embeddedMsg) {
		t.Errorf("msg len = %d, want %d", len(msg), len(embeddedMsg))
	}
	if len(routePath) != len(route) {
		t.Errorf("route len = %d, want %d", len(routePath), len(route))
	}
}

func TestParseUnconnectedSendRequestPayload_TooShort(t *testing.T) {
	_, _, ok := ParseUnconnectedSendRequestPayload([]byte{0x01, 0x02})
	if ok {
		t.Error("expected ok=false for short payload")
	}
}

func TestParseUnconnectedSendResponsePayload(t *testing.T) {
	// msg_size(2) + embedded response
	embeddedResp := []byte{0x8E, 0x00, 0x00, 0x00, 0x42}
	payload := make([]byte, 0)
	payload = append(payload, byte(len(embeddedResp)), 0x00)
	payload = append(payload, embeddedResp...)

	msg, ok := ParseUnconnectedSendResponsePayload(payload)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(msg) != len(embeddedResp) {
		t.Errorf("msg len = %d, want %d", len(msg), len(embeddedResp))
	}
}

func TestParseUnconnectedSendResponsePayload_TooShort(t *testing.T) {
	_, ok := ParseUnconnectedSendResponsePayload([]byte{0x01})
	if ok {
		t.Error("expected ok=false for short payload")
	}
}

func TestOptions_SetAndGet(t *testing.T) {
	original := CurrentOptions()
	defer SetOptions(original)

	SetOptions(Options{
		ByteOrder:           binary.BigEndian,
		IncludePathSize:     false,
		IncludeRespReserved: false,
	})

	opts := CurrentOptions()
	if opts.ByteOrder != binary.BigEndian {
		t.Error("ByteOrder should be BigEndian")
	}
	if opts.IncludePathSize {
		t.Error("IncludePathSize should be false")
	}
	if opts.IncludeRespReserved {
		t.Error("IncludeRespReserved should be false")
	}
}

func TestOptions_NilByteOrder(t *testing.T) {
	original := CurrentOptions()
	defer SetOptions(original)

	SetOptions(Options{ByteOrder: nil})
	opts := CurrentOptions()
	if opts.ByteOrder != binary.LittleEndian {
		t.Error("nil ByteOrder should default to LittleEndian")
	}
}

func TestParseCIPMessage_Request(t *testing.T) {
	// Service 0x0E, path_size=3, class=0x01, instance=0x01, attribute=0x01
	data := []byte{0x0E, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x01}
	info, err := ParseCIPMessage(data)
	if err != nil {
		t.Fatalf("ParseCIPMessage: %v", err)
	}
	if info.IsResponse {
		t.Error("should not be a response")
	}
	if info.Service != 0x0E {
		t.Errorf("service = 0x%02X, want 0x0E", info.Service)
	}
	if info.BaseService != 0x0E {
		t.Errorf("base service = 0x%02X, want 0x0E", info.BaseService)
	}
}

func TestParseCIPMessage_Response(t *testing.T) {
	// Response: service=0x8E, reserved=0x00, status=0x00, ext_size=0x00, payload=0x42
	data := []byte{0x8E, 0x00, 0x00, 0x00, 0x42}
	info, err := ParseCIPMessage(data)
	if err != nil {
		t.Fatalf("ParseCIPMessage: %v", err)
	}
	if !info.IsResponse {
		t.Error("should be a response")
	}
	if info.BaseService != 0x0E {
		t.Errorf("base service = 0x%02X, want 0x0E", info.BaseService)
	}
	if info.GeneralStatus == nil || *info.GeneralStatus != 0x00 {
		t.Error("general status should be 0x00")
	}
}

func TestParseCIPMessage_Empty(t *testing.T) {
	_, err := ParseCIPMessage(nil)
	if err == nil {
		t.Error("expected error for nil data")
	}
}
