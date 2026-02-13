package fixtures

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
)

func TestBuildPacketExpectation_Request(t *testing.T) {
	reqSpec := ValidationRequestSpec{
		Name:         "test_request",
		ServiceShape: ServiceShapeRead,
		Outcome:      "valid",
		TrafficMode:  "client_only",
	}

	expect := buildPacketExpectation(reqSpec, "request")

	if expect.ID != "test_request/request" {
		t.Errorf("ID = %q, want %q", expect.ID, "test_request/request")
	}
	if expect.Direction != "request" {
		t.Errorf("Direction = %q, want %q", expect.Direction, "request")
	}
	if expect.Outcome != "valid" {
		t.Errorf("Outcome = %q, want %q", expect.Outcome, "valid")
	}
	if expect.PacketType != "explicit_request" {
		t.Errorf("PacketType = %q, want %q", expect.PacketType, "explicit_request")
	}
	if expect.ServiceShape != ServiceShapeRead {
		t.Errorf("ServiceShape = %q, want %q", expect.ServiceShape, ServiceShapeRead)
	}
	if !expect.ExpectENIP || !expect.ExpectCPF || !expect.ExpectCIP {
		t.Error("should expect ENIP, CPF, and CIP layers")
	}
	if !expect.ExpectCIPPath {
		t.Error("request without ExpectSymbol should expect CIP path")
	}
}

func TestBuildPacketExpectation_Response(t *testing.T) {
	reqSpec := ValidationRequestSpec{
		Name:            "test_response",
		ServiceShape:    ServiceShapeWrite,
		Outcome:         "valid",
		ResponseOutcome: "invalid",
	}

	expect := buildPacketExpectation(reqSpec, "response")

	if expect.ID != "test_response/response" {
		t.Errorf("ID = %q, want %q", expect.ID, "test_response/response")
	}
	if expect.Direction != "response" {
		t.Errorf("Direction = %q, want %q", expect.Direction, "response")
	}
	if expect.Outcome != "invalid" {
		t.Errorf("Outcome = %q, want %q (ResponseOutcome should override)", expect.Outcome, "invalid")
	}
	if expect.PacketType != "explicit_response" {
		t.Errorf("PacketType = %q, want %q", expect.PacketType, "explicit_response")
	}
	if !expect.ExpectStatus {
		t.Error("response should expect status")
	}
	if expect.ExpectCIPPath {
		t.Error("response should not expect CIP path")
	}
}

func TestBuildPacketExpectation_Defaults(t *testing.T) {
	reqSpec := ValidationRequestSpec{
		Name: "test_defaults",
	}

	expect := buildPacketExpectation(reqSpec, "request")

	if expect.Outcome != "valid" {
		t.Errorf("empty Outcome should default to %q, got %q", "valid", expect.Outcome)
	}
	if expect.TrafficMode != "client_only" {
		t.Errorf("empty TrafficMode should default to %q, got %q", "client_only", expect.TrafficMode)
	}
}

func TestBuildPacketExpectation_ResponseFallsBackToOutcome(t *testing.T) {
	reqSpec := ValidationRequestSpec{
		Name:    "test_fallback",
		Outcome: "invalid",
	}

	expect := buildPacketExpectation(reqSpec, "response")
	if expect.Outcome != "invalid" {
		t.Errorf("response with empty ResponseOutcome should use Outcome, got %q", expect.Outcome)
	}
}

func TestBuildPacketExpectation_SymbolPath(t *testing.T) {
	reqSpec := ValidationRequestSpec{
		Name:         "symbol_test",
		ExpectSymbol: true,
	}

	expect := buildPacketExpectation(reqSpec, "request")
	if !expect.ExpectSymbol {
		t.Error("should expect symbol")
	}
	if expect.ExpectCIPPath {
		t.Error("symbol request should not expect CIP path")
	}
}

func TestResponseServiceCode(t *testing.T) {
	tests := []struct {
		input protocol.CIPServiceCode
		want  protocol.CIPServiceCode
	}{
		{0x0E, 0x8E},
		{0x10, 0x90},
		{0x01, 0x81},
	}

	for _, tt := range tests {
		got := responseServiceCode(tt.input)
		if got != tt.want {
			t.Errorf("responseServiceCode(0x%02X) = 0x%02X, want 0x%02X", tt.input, got, tt.want)
		}
	}
}

func TestDefaultResponsePayload(t *testing.T) {
	tests := []struct {
		shape string
		want  int // expected length, -1 for nil
	}{
		{ServiceShapeRead, 2},
		{ServiceShapeRockwellTag, 2},
		{ServiceShapeRockwellTagFrag, 2},
		{ServiceShapeTemplate, 4},
		{ServiceShapeFileObject, 1},
		{ServiceShapeModbus, 1},
		{ServiceShapePCCC, 1},
		{ServiceShapePayload, 1},
		{ServiceShapeSafetyReset, 1},
		{ServiceShapeNone, -1},
		{ServiceShapeWrite, -1},
		{"unknown", -1},
	}

	for _, tt := range tests {
		t.Run(tt.shape, func(t *testing.T) {
			got := defaultResponsePayload(tt.shape)
			if tt.want == -1 {
				if got != nil {
					t.Errorf("defaultResponsePayload(%q) should be nil, got %v", tt.shape, got)
				}
			} else {
				if len(got) != tt.want {
					t.Errorf("defaultResponsePayload(%q) len = %d, want %d", tt.shape, len(got), tt.want)
				}
			}
		})
	}
}

func TestBuildResponseForRequest(t *testing.T) {
	t.Run("get attribute single", func(t *testing.T) {
		req := protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeSingle,
			Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x01},
		}
		reqSpec := ValidationRequestSpec{ServiceShape: ServiceShapeRead}
		resp, err := buildResponseForRequest(req, reqSpec)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Service != responseServiceCode(spec.CIPServiceGetAttributeSingle) {
			t.Errorf("response service = 0x%02X, want 0x%02X", resp.Service, responseServiceCode(spec.CIPServiceGetAttributeSingle))
		}
		if resp.Status != 0x00 {
			t.Errorf("status = 0x%02X, want 0x00", resp.Status)
		}
		if len(resp.Payload) == 0 {
			t.Error("read response should have payload")
		}
	})

	t.Run("forward open", func(t *testing.T) {
		req := protocol.CIPRequest{
			Service: spec.CIPServiceForwardOpen,
			Path:    protocol.CIPPath{Class: spec.CIPClassConnectionManager, Instance: 0x01},
		}
		reqSpec := ValidationRequestSpec{ServiceShape: ServiceShapeForwardOpen}
		resp, err := buildResponseForRequest(req, reqSpec)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.Payload) != 17 {
			t.Errorf("forward open response payload len = %d, want 17", len(resp.Payload))
		}
	})

	t.Run("write shape", func(t *testing.T) {
		req := protocol.CIPRequest{
			Service: spec.CIPServiceSetAttributeSingle,
			Path:    protocol.CIPPath{Class: 0x04, Instance: 0x64, Attribute: 0x03},
			Payload: []byte{0x01, 0x00},
		}
		reqSpec := ValidationRequestSpec{ServiceShape: ServiceShapeWrite}
		resp, err := buildResponseForRequest(req, reqSpec)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Payload != nil {
			t.Error("write response should have nil payload")
		}
	})

	t.Run("payload shape", func(t *testing.T) {
		req := protocol.CIPRequest{
			Service: spec.CIPServiceStart,
			Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
		}
		reqSpec := ValidationRequestSpec{ServiceShape: ServiceShapePayload}
		resp, err := buildResponseForRequest(req, reqSpec)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.Payload) != 1 {
			t.Errorf("payload shape response should have 1-byte payload, got %d", len(resp.Payload))
		}
	})
}

func TestDefaultValidationPCAPSpecs(t *testing.T) {
	specs, err := DefaultValidationPCAPSpecs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(specs) == 0 {
		t.Fatal("should return at least one spec")
	}

	expectedNames := map[string]bool{
		"common_services":       false,
		"core":                  false,
		"rockwell":              false,
		"file_modbus":           false,
		"safety_energy_motion":  false,
	}

	for _, s := range specs {
		if _, ok := expectedNames[s.Name]; ok {
			expectedNames[s.Name] = true
		}
		if len(s.Requests) == 0 {
			t.Errorf("spec %q has no requests", s.Name)
		}
	}

	for name, found := range expectedNames {
		if !found {
			t.Errorf("expected spec %q not found", name)
		}
	}
}

func TestBuildValidationPackets(t *testing.T) {
	// Use a simple spec with a basic get_attribute_single
	spec := ValidationPCAPSpec{
		Name: "test",
		Requests: []ValidationRequestSpec{
			{
				Name: "get_attr_single",
				Req: protocol.CIPRequest{
					Service: 0x0E, // GetAttributeSingle
					Path: protocol.CIPPath{
						Class:     0x01,
						Instance:  0x01,
						Attribute: 0x01,
					},
				},
				ServiceShape:    ServiceShapeNone,
				IncludeResponse: true,
			},
		},
	}

	packets, err := BuildValidationPackets(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have 2 packets: request + response
	if len(packets) != 2 {
		t.Fatalf("expected 2 packets (request+response), got %d", len(packets))
	}

	if packets[0].Expect.Direction != "request" {
		t.Errorf("first packet direction = %q, want %q", packets[0].Expect.Direction, "request")
	}
	if packets[1].Expect.Direction != "response" {
		t.Errorf("second packet direction = %q, want %q", packets[1].Expect.Direction, "response")
	}

	// Each packet should have non-empty data (ENIP-wrapped)
	for i, pkt := range packets {
		if len(pkt.Data) == 0 {
			t.Errorf("packet %d has empty data", i)
		}
	}
}

func TestBuildValidationPackets_NoResponse(t *testing.T) {
	spec := ValidationPCAPSpec{
		Name: "test_no_response",
		Requests: []ValidationRequestSpec{
			{
				Name: "get_attr_single",
				Req: protocol.CIPRequest{
					Service: 0x0E,
					Path: protocol.CIPPath{
						Class:     0x01,
						Instance:  0x01,
						Attribute: 0x01,
					},
				},
				ServiceShape:    ServiceShapeNone,
				IncludeResponse: false,
			},
		},
	}

	packets, err := BuildValidationPackets(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packets) != 1 {
		t.Fatalf("expected 1 packet (request only), got %d", len(packets))
	}
}

func TestBuildValidationENIPPackets(t *testing.T) {
	spec := ValidationPCAPSpec{
		Name: "test_enip",
		Requests: []ValidationRequestSpec{
			{
				Name: "get_attr",
				Req: protocol.CIPRequest{
					Service: 0x0E,
					Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x01},
				},
				ServiceShape:    ServiceShapeNone,
				IncludeResponse: false,
			},
		},
	}

	rawPackets, err := BuildValidationENIPPackets(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rawPackets) != 1 {
		t.Fatalf("expected 1 raw packet, got %d", len(rawPackets))
	}
	if len(rawPackets[0]) == 0 {
		t.Error("raw packet should not be empty")
	}
}

func TestWriteENIPPCAP(t *testing.T) {
	spec := ValidationPCAPSpec{
		Name: "test_pcap_write",
		Requests: []ValidationRequestSpec{
			{
				Name: "get_attr",
				Req: protocol.CIPRequest{
					Service: 0x0E,
					Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x01},
				},
				ServiceShape:    ServiceShapeNone,
				IncludeResponse: true,
			},
		},
	}

	packets, err := BuildValidationPackets(spec)
	if err != nil {
		t.Fatalf("build packets: %v", err)
	}

	path := filepath.Join(t.TempDir(), "test.pcap")
	if err := WriteENIPPCAP(path, packets); err != nil {
		t.Fatalf("WriteENIPPCAP: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat pcap: %v", err)
	}
	if info.Size() == 0 {
		t.Error("pcap file should not be empty")
	}
}

func TestGenerateValidationPCAPs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pcaps")

	paths, err := GenerateValidationPCAPs(dir)
	if err != nil {
		t.Fatalf("GenerateValidationPCAPs: %v", err)
	}

	if len(paths) == 0 {
		t.Fatal("should generate at least one pcap")
	}

	for _, p := range paths {
		if !strings.HasSuffix(p, ".pcap") {
			t.Errorf("path %q should end with .pcap", p)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("stat %q: %v", p, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%q should not be empty", p)
		}

		// Check validation manifest was written alongside
		manifestPath := strings.TrimSuffix(p, ".pcap") + ".validation.json"
		if _, err := os.Stat(manifestPath); err != nil {
			t.Errorf("validation manifest should exist at %q: %v", manifestPath, err)
		}
	}
}
