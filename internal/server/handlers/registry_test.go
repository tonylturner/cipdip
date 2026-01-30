package handlers

import (
	"context"
	"errors"
	"testing"

	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if r.exact == nil {
		t.Error("exact map should be initialized")
	}
	if r.classAny == nil {
		t.Error("classAny map should be initialized")
	}
	if r.serviceAny == nil {
		t.Error("serviceAny map should be initialized")
	}
}

func TestRegistryExactMatch(t *testing.T) {
	r := NewRegistry()

	called := false
	handler := func(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error) {
		called = true
		return protocol.CIPResponse{Status: 0x00}, true, nil
	}

	r.Register(0x01, uint8(spec.CIPServiceGetAttributeSingle), handler)

	req := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
	}

	resp, handled, err := r.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if !handled {
		t.Error("Expected request to be handled")
	}
	if !called {
		t.Error("Handler was not called")
	}
	if resp.Status != 0x00 {
		t.Errorf("Expected status 0x00, got 0x%02X", resp.Status)
	}
}

func TestRegistryClassWildcard(t *testing.T) {
	r := NewRegistry()

	called := false
	handler := func(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error) {
		called = true
		return protocol.CIPResponse{Status: 0x00}, true, nil
	}

	// Register with ClassAny - matches any class with specific service
	r.Register(ClassAny, uint8(spec.CIPServiceGetAttributeSingle), handler)

	req := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0x99, Instance: 0x01}, // Any class
	}

	resp, handled, err := r.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if !handled {
		t.Error("Expected request to be handled by class wildcard")
	}
	if !called {
		t.Error("Handler was not called")
	}
	if resp.Status != 0x00 {
		t.Errorf("Expected status 0x00, got 0x%02X", resp.Status)
	}
}

func TestRegistryServiceWildcard(t *testing.T) {
	r := NewRegistry()

	called := false
	handler := func(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error) {
		called = true
		return protocol.CIPResponse{Status: 0x00}, true, nil
	}

	// Register with ServiceAny - matches specific class with any service
	r.Register(0x01, ServiceAny, handler)

	req := protocol.CIPRequest{
		Service: 0x99, // Any service
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
	}

	resp, handled, err := r.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if !handled {
		t.Error("Expected request to be handled by service wildcard")
	}
	if !called {
		t.Error("Handler was not called")
	}
	if resp.Status != 0x00 {
		t.Errorf("Expected status 0x00, got 0x%02X", resp.Status)
	}
}

func TestRegistryFullWildcard(t *testing.T) {
	r := NewRegistry()

	called := false
	handler := func(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error) {
		called = true
		return protocol.CIPResponse{Status: 0x00}, true, nil
	}

	// Register with both wildcards - matches anything
	r.Register(ClassAny, ServiceAny, handler)

	req := protocol.CIPRequest{
		Service: 0x99,
		Path:    protocol.CIPPath{Class: 0x99, Instance: 0x01},
	}

	resp, handled, err := r.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if !handled {
		t.Error("Expected request to be handled by full wildcard")
	}
	if !called {
		t.Error("Handler was not called")
	}
	if resp.Status != 0x00 {
		t.Errorf("Expected status 0x00, got 0x%02X", resp.Status)
	}
}

func TestRegistryPriority(t *testing.T) {
	r := NewRegistry()

	exactCalled := false
	classWildcardCalled := false
	serviceWildcardCalled := false
	fullWildcardCalled := false

	// Register in reverse priority order
	r.Register(ClassAny, ServiceAny, func(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error) {
		fullWildcardCalled = true
		return protocol.CIPResponse{}, true, nil
	})
	r.Register(0x01, ServiceAny, func(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error) {
		serviceWildcardCalled = true
		return protocol.CIPResponse{}, true, nil
	})
	r.Register(ClassAny, uint8(spec.CIPServiceGetAttributeSingle), func(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error) {
		classWildcardCalled = true
		return protocol.CIPResponse{}, true, nil
	})
	r.Register(0x01, uint8(spec.CIPServiceGetAttributeSingle), func(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error) {
		exactCalled = true
		return protocol.CIPResponse{}, true, nil
	})

	req := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
	}

	_, _, _ = r.Handle(context.Background(), req)

	// Exact match should have highest priority
	if !exactCalled {
		t.Error("Expected exact match handler to be called")
	}
	if classWildcardCalled || serviceWildcardCalled || fullWildcardCalled {
		t.Error("Lower priority handlers should not be called when exact match exists")
	}
}

func TestRegistryNoHandler(t *testing.T) {
	r := NewRegistry()

	req := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
	}

	_, handled, err := r.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle returned unexpected error: %v", err)
	}
	if handled {
		t.Error("Expected request to not be handled when no handlers registered")
	}
}

func TestRegistryNilRegistry(t *testing.T) {
	var r *Registry

	req := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
	}

	_, handled, err := r.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle on nil registry returned error: %v", err)
	}
	if handled {
		t.Error("Expected nil registry to not handle any requests")
	}
}

func TestRegistryHandlerReturnsError(t *testing.T) {
	r := NewRegistry()

	expectedErr := errors.New("handler error")
	handler := func(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error) {
		return protocol.CIPResponse{}, false, expectedErr
	}

	r.Register(0x01, uint8(spec.CIPServiceGetAttributeSingle), handler)

	req := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
	}

	_, _, err := r.Handle(context.Background(), req)
	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
}

func TestRegistryHandlerNotHandled(t *testing.T) {
	r := NewRegistry()

	firstCalled := false
	secondCalled := false

	// First handler doesn't handle
	r.Register(0x01, uint8(spec.CIPServiceGetAttributeSingle), func(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error) {
		firstCalled = true
		return protocol.CIPResponse{}, false, nil // Not handled
	})

	// Second handler does handle
	r.Register(0x01, uint8(spec.CIPServiceGetAttributeSingle), func(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error) {
		secondCalled = true
		return protocol.CIPResponse{Status: 0x00}, true, nil
	})

	req := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
	}

	resp, handled, err := r.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if !handled {
		t.Error("Expected request to be handled")
	}
	if !firstCalled {
		t.Error("First handler should have been called")
	}
	if !secondCalled {
		t.Error("Second handler should have been called after first didn't handle")
	}
	if resp.Status != 0x00 {
		t.Errorf("Expected status 0x00, got 0x%02X", resp.Status)
	}
}

func TestWrapHandler(t *testing.T) {
	var calledReq protocol.CIPRequest
	mockHandler := &mockHandler{
		response: protocol.CIPResponse{Status: 0x00},
		onCall: func(req protocol.CIPRequest) {
			calledReq = req
		},
	}

	wrapped := WrapHandler(mockHandler)

	req := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01, Attribute: 0x01},
	}

	resp, handled, err := wrapped(context.Background(), req)
	if err != nil {
		t.Fatalf("Wrapped handler returned error: %v", err)
	}
	if !handled {
		t.Error("Wrapped handler should always return handled=true")
	}
	if resp.Status != 0x00 {
		t.Errorf("Expected status 0x00, got 0x%02X", resp.Status)
	}
	if calledReq.Path.Class != req.Path.Class {
		t.Error("Original request was not passed to handler")
	}
}

func TestRegisterHandler(t *testing.T) {
	r := NewRegistry()

	mockHandler := &mockHandler{
		response: protocol.CIPResponse{Status: 0x00},
	}

	r.RegisterHandler(0x01, uint8(spec.CIPServiceGetAttributeSingle), mockHandler)

	req := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
	}

	resp, handled, err := r.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if !handled {
		t.Error("Expected request to be handled")
	}
	if resp.Status != 0x00 {
		t.Errorf("Expected status 0x00, got 0x%02X", resp.Status)
	}
}

func TestRegistryMultipleHandlersSameKey(t *testing.T) {
	r := NewRegistry()

	callOrder := []int{}

	r.Register(0x01, uint8(spec.CIPServiceGetAttributeSingle), func(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error) {
		callOrder = append(callOrder, 1)
		return protocol.CIPResponse{}, false, nil // Not handled
	})
	r.Register(0x01, uint8(spec.CIPServiceGetAttributeSingle), func(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error) {
		callOrder = append(callOrder, 2)
		return protocol.CIPResponse{}, false, nil // Not handled
	})
	r.Register(0x01, uint8(spec.CIPServiceGetAttributeSingle), func(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error) {
		callOrder = append(callOrder, 3)
		return protocol.CIPResponse{Status: 0x00}, true, nil // Handled
	})

	req := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{Class: 0x01, Instance: 0x01},
	}

	_, _, _ = r.Handle(context.Background(), req)

	if len(callOrder) != 3 {
		t.Errorf("Expected 3 handlers to be called, got %d", len(callOrder))
	}
	for i, v := range callOrder {
		if v != i+1 {
			t.Errorf("Handlers called out of order: got %v", callOrder)
			break
		}
	}
}

// mockHandler implements the Handler interface for testing
type mockHandler struct {
	response protocol.CIPResponse
	err      error
	onCall   func(req protocol.CIPRequest)
}

func (m *mockHandler) HandleCIPRequest(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, error) {
	if m.onCall != nil {
		m.onCall(req)
	}
	return m.response, m.err
}
