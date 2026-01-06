package core

import (
	"github.com/tturner/cipdip/internal/cip/spec"
	"testing"

	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/config"
)

func TestCIPPolicyDenyOverride(t *testing.T) {
	cfg := createTestServerConfig()
	cfg.CIP.Deny = []config.ServerCIPRule{
		{Service: 0x0E, Class: 0x0004},
	}
	cfg.CIP.DenyStatusOverrides = []config.ServerCIPStatusOverride{
		{Service: 0x0E, Class: 0x0004, Status: 0x0F},
	}

	srv, err := NewServer(cfg, createTestLogger())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	req := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     0x0004,
			Instance:  0x0001,
			Attribute: 0x0001,
		},
	}

	resp, ok := srv.applyCIPPolicy(req)
	if !ok {
		t.Fatalf("expected policy reject")
	}
	if resp.Status != 0x0F {
		t.Fatalf("unexpected status: 0x%02X", resp.Status)
	}
}

func TestCIPPolicyAllowList(t *testing.T) {
	cfg := createTestServerConfig()
	cfg.CIP.Allow = []config.ServerCIPRule{
		{Service: 0x0E, Class: 0x0004},
	}

	srv, err := NewServer(cfg, createTestLogger())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	allowReq := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     0x0004,
			Instance:  0x0001,
			Attribute: 0x0001,
		},
	}
	if _, ok := srv.applyCIPPolicy(allowReq); ok {
		t.Fatalf("expected allow without policy rejection")
	}

	blockReq := protocol.CIPRequest{
		Service: spec.CIPServiceSetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     0x0004,
			Instance:  0x0001,
			Attribute: 0x0001,
		},
	}
	resp, ok := srv.applyCIPPolicy(blockReq)
	if !ok {
		t.Fatalf("expected policy reject for non-allowlisted service")
	}
	if resp.Status != 0x08 {
		t.Fatalf("unexpected status: 0x%02X", resp.Status)
	}
}

func TestCIPPolicyStrictPaths(t *testing.T) {
	cfg := createTestServerConfig()
	cfg.CIP.StrictPaths = boolPtr(true)

	srv, err := NewServer(cfg, createTestLogger())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	req := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    protocol.CIPPath{},
	}
	if _, ok := srv.applyCIPPolicy(req); !ok {
		t.Fatalf("expected policy reject for missing path")
	}
}
