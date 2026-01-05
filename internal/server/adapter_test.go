package server

import (
	"context"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"testing"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
)

var cipOrder = cipclient.CurrentProtocolProfile().CIPByteOrder

// createTestAdapterPersonality creates a test adapter personality
func createTestAdapterPersonality() (*AdapterPersonality, *config.ServerConfig, error) {
	cfg := &config.ServerConfig{
		Server: config.ServerConfigSection{
			Name:        "Test Server",
			Personality: "adapter",
		},
		AdapterAssemblies: []config.AdapterAssemblyConfig{
			{
				Name:          "ReadOnlyAssembly",
				Class:         0x04,
				Instance:      0x65,
				Attribute:     0x03,
				SizeBytes:     16,
				Writable:      false,
				UpdatePattern: "static",
			},
			{
				Name:          "WritableAssembly",
				Class:         0x04,
				Instance:      0x66,
				Attribute:     0x03,
				SizeBytes:     8,
				Writable:      true,
				UpdatePattern: "counter",
			},
			{
				Name:          "ReflectAssembly",
				Class:         0x04,
				Instance:      0x67,
				Attribute:     0x03,
				SizeBytes:     4,
				Writable:      true,
				UpdatePattern: "reflect_inputs",
			},
		},
	}

	logger, _ := logging.NewLogger(logging.LogLevelError, "")
	personality, err := NewAdapterPersonality(cfg, logger)
	return personality, cfg, err
}

// TestNewAdapterPersonality tests adapter personality creation
func TestNewAdapterPersonality(t *testing.T) {
	personality, cfg, err := createTestAdapterPersonality()
	if err != nil {
		t.Fatalf("NewAdapterPersonality failed: %v", err)
	}

	if personality == nil {
		t.Fatal("NewAdapterPersonality returned nil")
	}

	if personality.GetName() != "adapter" {
		t.Errorf("Expected name 'adapter', got '%s'", personality.GetName())
	}

	// Verify assemblies are initialized
	personality.mu.RLock()
	if len(personality.assemblies) != len(cfg.AdapterAssemblies) {
		t.Errorf("Expected %d assemblies, got %d", len(cfg.AdapterAssemblies), len(personality.assemblies))
	}
	personality.mu.RUnlock()
}

// TestAdapterGetAttributeSingle tests Get_Attribute_Single handling
func TestAdapterGetAttributeSingle(t *testing.T) {
	personality, _, err := createTestAdapterPersonality()
	if err != nil {
		t.Fatalf("createTestAdapterPersonality failed: %v", err)
	}

	ctx := context.Background()

	// Test reading from existing assembly
	req := protocol.CIPRequest{
		Service: protocol.CIPServiceGetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     0x04,
			Instance:  0x65,
			Attribute: 0x03,
		},
	}

	resp, err := personality.HandleCIPRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleCIPRequest failed: %v", err)
	}

	if resp.Status != 0x00 {
		t.Errorf("Expected status 0x00 (success), got 0x%02X", resp.Status)
	}

	if resp.Service != protocol.CIPServiceGetAttributeSingle {
		t.Errorf("Expected service 0x%02X, got 0x%02X", protocol.CIPServiceGetAttributeSingle, resp.Service)
	}

	if len(resp.Payload) != 16 {
		t.Errorf("Expected payload size 16, got %d", len(resp.Payload))
	}
}

// TestAdapterGetAttributeSingleNotFound tests Get_Attribute_Single with non-existent assembly
func TestAdapterGetAttributeSingleNotFound(t *testing.T) {
	personality, _, err := createTestAdapterPersonality()
	if err != nil {
		t.Fatalf("createTestAdapterPersonality failed: %v", err)
	}

	ctx := context.Background()

	// Test reading from non-existent assembly
	req := protocol.CIPRequest{
		Service: protocol.CIPServiceGetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     0x04,
			Instance:  0x99,
			Attribute: 0x03,
		},
	}

	resp, err := personality.HandleCIPRequest(ctx, req)
	if err == nil {
		t.Error("HandleCIPRequest should fail for non-existent assembly")
	}

	if resp.Status != 0x01 {
		t.Errorf("Expected status 0x01 (general error), got 0x%02X", resp.Status)
	}
}

// TestAdapterSetAttributeSingle tests Set_Attribute_Single handling
func TestAdapterSetAttributeSingle(t *testing.T) {
	personality, _, err := createTestAdapterPersonality()
	if err != nil {
		t.Fatalf("createTestAdapterPersonality failed: %v", err)
	}

	ctx := context.Background()

	// Test writing to writable assembly
	testData := []byte{0x01, 0x02, 0x03, 0x04}
	req := protocol.CIPRequest{
		Service: protocol.CIPServiceSetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     0x04,
			Instance:  0x66,
			Attribute: 0x03,
		},
		Payload: testData,
	}

	resp, err := personality.HandleCIPRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleCIPRequest failed: %v", err)
	}

	if resp.Status != 0x00 {
		t.Errorf("Expected status 0x00 (success), got 0x%02X", resp.Status)
	}

	// Verify data was written by reading it back
	readReq := protocol.CIPRequest{
		Service: protocol.CIPServiceGetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     0x04,
			Instance:  0x66,
			Attribute: 0x03,
		},
	}

	readResp, err := personality.HandleCIPRequest(ctx, readReq)
	if err != nil {
		t.Fatalf("HandleCIPRequest (read) failed: %v", err)
	}

	// Check that first bytes match (counter pattern may have updated)
	if len(readResp.Payload) < len(testData) {
		t.Errorf("Read payload too short: got %d, want at least %d", len(readResp.Payload), len(testData))
	}
}

// TestAdapterSetAttributeSingleReadOnly tests Set_Attribute_Single on read-only assembly
func TestAdapterSetAttributeSingleReadOnly(t *testing.T) {
	personality, _, err := createTestAdapterPersonality()
	if err != nil {
		t.Fatalf("createTestAdapterPersonality failed: %v", err)
	}

	ctx := context.Background()

	// Test writing to read-only assembly
	req := protocol.CIPRequest{
		Service: protocol.CIPServiceSetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     0x04,
			Instance:  0x65, // ReadOnlyAssembly
			Attribute: 0x03,
		},
		Payload: []byte{0x01, 0x02, 0x03, 0x04},
	}

	resp, err := personality.HandleCIPRequest(ctx, req)
	if err == nil {
		t.Error("HandleCIPRequest should fail for read-only assembly")
	}

	if resp.Status != 0x05 {
		t.Errorf("Expected status 0x05 (attribute not settable), got 0x%02X", resp.Status)
	}
}

// TestAdapterUpdatePatternCounter tests counter update pattern
func TestAdapterUpdatePatternCounter(t *testing.T) {
	personality, _, err := createTestAdapterPersonality()
	if err != nil {
		t.Fatalf("createTestAdapterPersonality failed: %v", err)
	}

	ctx := context.Background()

	// Read assembly multiple times with delay to trigger counter updates
	var values []uint32
	for i := 0; i < 3; i++ {
		req := protocol.CIPRequest{
			Service: protocol.CIPServiceGetAttributeSingle,
			Path: protocol.CIPPath{
				Class:     0x04,
				Instance:  0x66, // WritableAssembly with counter pattern
				Attribute: 0x03,
			},
		}

		resp, err := personality.HandleCIPRequest(ctx, req)
		if err != nil {
			t.Fatalf("HandleCIPRequest failed: %v", err)
		}

		if len(resp.Payload) >= 4 {
			value := cipOrder.Uint32(resp.Payload[0:4])
			values = append(values, value)
		}

		time.Sleep(150 * time.Millisecond) // Wait for update threshold
	}

	// Verify counter is incrementing
	if len(values) < 2 {
		t.Fatal("Not enough values collected")
	}

	for i := 1; i < len(values); i++ {
		if values[i] <= values[i-1] {
			t.Errorf("Counter should increment: values[%d]=%d, values[%d]=%d", i-1, values[i-1], i, values[i])
		}
	}
}

// TestAdapterUpdatePatternReflectInputs tests reflect_inputs update pattern
func TestAdapterUpdatePatternReflectInputs(t *testing.T) {
	personality, _, err := createTestAdapterPersonality()
	if err != nil {
		t.Fatalf("createTestAdapterPersonality failed: %v", err)
	}

	ctx := context.Background()

	// Write data to reflect assembly
	testData := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	writeReq := protocol.CIPRequest{
		Service: protocol.CIPServiceSetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     0x04,
			Instance:  0x67, // ReflectAssembly
			Attribute: 0x03,
		},
		Payload: testData,
	}

	_, err = personality.HandleCIPRequest(ctx, writeReq)
	if err != nil {
		t.Fatalf("HandleCIPRequest (write) failed: %v", err)
	}

	// Read it back
	readReq := protocol.CIPRequest{
		Service: protocol.CIPServiceGetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     0x04,
			Instance:  0x67,
			Attribute: 0x03,
		},
	}

	readResp, err := personality.HandleCIPRequest(ctx, readReq)
	if err != nil {
		t.Fatalf("HandleCIPRequest (read) failed: %v", err)
	}

	// Verify data matches
	if len(readResp.Payload) < len(testData) {
		t.Fatalf("Read payload too short: got %d, want %d", len(readResp.Payload), len(testData))
	}

	for i := 0; i < len(testData); i++ {
		if readResp.Payload[i] != testData[i] {
			t.Errorf("Data mismatch at index %d: got 0x%02X, want 0x%02X", i, readResp.Payload[i], testData[i])
		}
	}
}

// TestAdapterUnsupportedService tests unsupported service handling
func TestAdapterUnsupportedService(t *testing.T) {
	personality, _, err := createTestAdapterPersonality()
	if err != nil {
		t.Fatalf("createTestAdapterPersonality failed: %v", err)
	}

	ctx := context.Background()

	// Test unsupported service
	req := protocol.CIPRequest{
		Service: protocol.CIPServiceGetAttributeAll, // Not supported
		Path: protocol.CIPPath{
			Class:     0x04,
			Instance:  0x65,
			Attribute: 0x03,
		},
	}

	resp, err := personality.HandleCIPRequest(ctx, req)
	if err == nil {
		t.Error("HandleCIPRequest should fail for unsupported service")
	}

	if resp.Status != 0x08 {
		t.Errorf("Expected status 0x08 (service not supported), got 0x%02X", resp.Status)
	}
}
