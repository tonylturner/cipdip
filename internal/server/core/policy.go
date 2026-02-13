package core

import (
	"time"

	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/config"
)

func resolveENIPSupport(cfg *config.ServerConfig) enipSupportConfig {
	return enipSupportConfig{
		listIdentity:    boolValue(cfg.ENIP.Support.ListIdentity, true),
		listServices:    boolValue(cfg.ENIP.Support.ListServices, true),
		listInterfaces:  boolValue(cfg.ENIP.Support.ListInterfaces, true),
		registerSession: boolValue(cfg.ENIP.Support.RegisterSession, true),
		sendRRData:      boolValue(cfg.ENIP.Support.SendRRData, true),
		sendUnitData:    boolValue(cfg.ENIP.Support.SendUnitData, true),
	}
}

func resolveSessionPolicy(cfg *config.ServerConfig) enipSessionPolicy {
	idleMs := cfg.ENIP.Session.IdleTimeoutMs
	maxSessions := cfg.ENIP.Session.MaxSessions
	maxSessionsPerIP := cfg.ENIP.Session.MaxSessionsPerIP
	if maxSessions == 0 {
		maxSessions = 256
	}
	if maxSessionsPerIP == 0 {
		maxSessionsPerIP = 64
	}
	if idleMs == 0 {
		idleMs = 60000
	}
	return enipSessionPolicy{
		requireRegister:  boolValue(cfg.ENIP.Session.RequireRegisterSession, true),
		maxSessions:      maxSessions,
		maxSessionsPerIP: maxSessionsPerIP,
		idleTimeout:      time.Duration(idleMs) * time.Millisecond,
	}
}

func resolveCIPPolicy(cfg *config.ServerConfig) cipPolicyConfig {
	defaultStatus := cfg.CIP.DefaultUnsupportedStatus
	if defaultStatus == 0 {
		defaultStatus = 0x08
	}
	return cipPolicyConfig{
		strictPaths:        boolValue(cfg.CIP.StrictPaths, true),
		defaultStatus:      defaultStatus,
		defaultExtStatus:   cfg.CIP.DefaultErrorExtStatus,
		allowRules:         cfg.CIP.Allow,
		denyRules:          cfg.CIP.Deny,
		denyStatusOverride: cfg.CIP.DenyStatusOverrides,
	}
}

func (s *Server) applyCIPPolicy(req protocol.CIPRequest) (protocol.CIPResponse, bool) {
	if s.cipPolicy.strictPaths && req.Path.Class == 0 && req.Path.Name == "" {
		return s.policyReject(req), true
	}

	for _, rule := range s.cipPolicy.denyRules {
		if ruleMatches(rule, req) {
			return s.policyReject(req), true
		}
	}

	if len(s.cipPolicy.allowRules) > 0 {
		for _, rule := range s.cipPolicy.allowRules {
			if ruleMatches(rule, req) {
				return protocol.CIPResponse{}, false
			}
		}
		return s.policyReject(req), true
	}

	return protocol.CIPResponse{}, false
}

func (s *Server) policyReject(req protocol.CIPRequest) protocol.CIPResponse {
	status := s.cipPolicy.defaultStatus
	for _, override := range s.cipPolicy.denyStatusOverride {
		if overrideMatches(override, req) {
			status = override.Status
			break
		}
	}
	resp := protocol.CIPResponse{
		Service: req.Service,
		Status:  status,
		Path:    req.Path,
	}
	if s.cipPolicy.defaultExtStatus != 0 {
		resp.ExtStatus = []byte{
			byte(s.cipPolicy.defaultExtStatus & 0xFF),
			byte(s.cipPolicy.defaultExtStatus >> 8),
		}
	}
	return resp
}

func ruleMatches(rule config.ServerCIPRule, req protocol.CIPRequest) bool {
	if rule.Service != 0 && rule.Service != uint8(req.Service) {
		return false
	}
	if rule.Class != 0 && rule.Class != req.Path.Class {
		return false
	}
	if rule.Instance != 0 && rule.Instance != req.Path.Instance {
		return false
	}
	if rule.Attribute != 0 && rule.Attribute != req.Path.Attribute {
		return false
	}
	return true
}

func overrideMatches(rule config.ServerCIPStatusOverride, req protocol.CIPRequest) bool {
	if rule.Service != 0 && rule.Service != uint8(req.Service) {
		return false
	}
	if rule.Class != 0 && rule.Class != req.Path.Class {
		return false
	}
	if rule.Instance != 0 && rule.Instance != req.Path.Instance {
		return false
	}
	if rule.Attribute != 0 && rule.Attribute != req.Path.Attribute {
		return false
	}
	return true
}

func boolValue(value *bool, def bool) bool {
	if value == nil {
		return def
	}
	return *value
}
