package server

import (
	"testing"

	"github.com/tturner/cipdip/internal/config"
)

func TestApplyServerTarget(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerConfigSection{
			Personality: "adapter",
		},
	}

	if err := ApplyServerTarget(cfg, "rockwell_v32"); err != nil {
		t.Fatalf("ApplyServerTarget failed: %v", err)
	}
	if cfg.Server.Personality != "logix_like" {
		t.Fatalf("expected logix_like personality, got %q", cfg.Server.Personality)
	}
	if cfg.Server.IdentityProductName == "" {
		t.Fatalf("expected product name to be set")
	}
	if len(cfg.LogixTags) == 0 {
		t.Fatalf("expected logix tags to be set")
	}
}

func TestApplyServerTargetUnknown(t *testing.T) {
	cfg := &config.ServerConfig{}
	if err := ApplyServerTarget(cfg, "unknown_target"); err == nil {
		t.Fatalf("expected error for unknown target")
	}
}
