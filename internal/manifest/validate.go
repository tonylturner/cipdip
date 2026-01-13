package manifest

import (
	"fmt"
	"net"
	"strings"
)

// ValidationError represents a manifest validation error.
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationErrors is a collection of validation errors.
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "no validation errors"
	}
	var msgs []string
	for _, err := range e {
		msgs = append(msgs, err.Error())
	}
	return fmt.Sprintf("manifest validation failed:\n  - %s", strings.Join(msgs, "\n  - "))
}

// Validate checks the manifest for correctness.
func (m *Manifest) Validate() error {
	var errs ValidationErrors

	// API version
	if m.APIVersion == "" {
		errs = append(errs, ValidationError{"api_version", "required"})
	} else if m.APIVersion != APIVersion {
		errs = append(errs, ValidationError{"api_version", fmt.Sprintf("must be '%s', got '%s'", APIVersion, m.APIVersion)})
	}

	// Profile
	if m.Profile.Path == "" {
		errs = append(errs, ValidationError{"profile.path", "required"})
	}
	if err := validateDistribution(m.Profile.Distribution); err != nil {
		errs = append(errs, ValidationError{"profile.distribution", err.Error()})
	}

	// Network
	if m.Network.DataPlane.TargetIP == "" {
		errs = append(errs, ValidationError{"network.data_plane.target_ip", "required"})
	} else if !isValidIP(m.Network.DataPlane.TargetIP) {
		errs = append(errs, ValidationError{"network.data_plane.target_ip", "must be a valid IP address"})
	}

	// Roles - at least one must be defined
	if m.Roles.Server == nil && m.Roles.Client == nil {
		errs = append(errs, ValidationError{"roles", "at least one of server or client must be defined"})
	}

	// Server role validation
	if m.Roles.Server != nil {
		if m.Roles.Server.Agent == "" {
			errs = append(errs, ValidationError{"roles.server.agent", "required"})
		}
		if m.Network.DataPlane.ServerListenIP == "" {
			errs = append(errs, ValidationError{"network.data_plane.server_listen_ip", "required when server role is defined"})
		} else if !isValidIP(m.Network.DataPlane.ServerListenIP) {
			errs = append(errs, ValidationError{"network.data_plane.server_listen_ip", "must be a valid IP address"})
		}
		if err := validatePersonality(m.Roles.Server.Personality); err != nil {
			errs = append(errs, ValidationError{"roles.server.personality", err.Error()})
		}
	}

	// Client role validation
	if m.Roles.Client != nil {
		if m.Roles.Client.Agent == "" {
			errs = append(errs, ValidationError{"roles.client.agent", "required"})
		}
		if m.Roles.Client.Scenario == "" {
			errs = append(errs, ValidationError{"roles.client.scenario", "required"})
		}
		if m.Roles.Client.DurationSeconds <= 0 {
			errs = append(errs, ValidationError{"roles.client.duration_seconds", "must be > 0"})
		}
		if m.Roles.Client.Scenario == "profile" && m.Roles.Client.ProfileRole == "" {
			errs = append(errs, ValidationError{"roles.client.profile_role", "required when scenario is 'profile'"})
		}
	}

	// Readiness
	if err := validateReadinessMethod(m.Readiness.Method); err != nil {
		errs = append(errs, ValidationError{"readiness.method", err.Error()})
	}

	// Artifacts
	if err := validateBundleFormat(m.Artifacts.BundleFormat); err != nil {
		errs = append(errs, ValidationError{"artifacts.bundle_format", err.Error()})
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ValidateAgents checks that all agent references in the manifest have mappings.
func (m *Manifest) ValidateAgents(agentMap map[string]string) error {
	var errs ValidationErrors

	if m.Roles.Server != nil && m.Roles.Server.Agent != "local" {
		if _, ok := agentMap[m.Roles.Server.Agent]; !ok {
			errs = append(errs, ValidationError{
				"roles.server.agent",
				fmt.Sprintf("agent '%s' not found in agent mappings", m.Roles.Server.Agent),
			})
		}
	}

	if m.Roles.Client != nil && m.Roles.Client.Agent != "local" {
		if _, ok := agentMap[m.Roles.Client.Agent]; !ok {
			errs = append(errs, ValidationError{
				"roles.client.agent",
				fmt.Sprintf("agent '%s' not found in agent mappings", m.Roles.Client.Agent),
			})
		}
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateDistribution(dist string) error {
	switch dist {
	case "", "inline", "push", "preinstalled":
		return nil
	default:
		return fmt.Errorf("must be one of: inline, push, preinstalled")
	}
}

func validatePersonality(p string) error {
	if p == "" {
		return nil // optional, defaults handled elsewhere
	}
	switch p {
	case "adapter", "logix_like":
		return nil
	default:
		return fmt.Errorf("must be one of: adapter, logix_like")
	}
}

func validateReadinessMethod(method string) error {
	switch method {
	case "", "structured_stdout", "tcp_connect":
		return nil
	default:
		return fmt.Errorf("must be one of: structured_stdout, tcp_connect")
	}
}

func validateBundleFormat(format string) error {
	switch format {
	case "", "dir", "zip":
		return nil
	default:
		return fmt.Errorf("must be one of: dir, zip")
	}
}

func isValidIP(s string) bool {
	// Allow "0.0.0.0" for server listen
	if s == "0.0.0.0" {
		return true
	}
	return net.ParseIP(s) != nil
}
