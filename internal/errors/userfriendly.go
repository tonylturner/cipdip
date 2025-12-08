package errors

import (
	"fmt"
	"strings"
)

// UserFriendlyError provides user-friendly error messages with context and hints
type UserFriendlyError struct {
	Message string
	Reason  string
	Hint    string
	Try     string
	Err     error
}

func (e UserFriendlyError) Error() string {
	var buf strings.Builder
	buf.WriteString(e.Message)
	if e.Reason != "" {
		buf.WriteString("\n  Reason: " + e.Reason)
	}
	if e.Hint != "" {
		buf.WriteString("\n  Hint: " + e.Hint)
	}
	if e.Try != "" {
		buf.WriteString("\n  Try: " + e.Try)
	}
	if e.Err != nil {
		buf.WriteString("\n  Details: " + e.Err.Error())
	}
	return buf.String()
}

func (e UserFriendlyError) Unwrap() error {
	return e.Err
}

// WrapNetworkError wraps network errors with user-friendly context
func WrapNetworkError(err error, ip string, port int) error {
	if err == nil {
		return nil
	}
	
	return UserFriendlyError{
		Message: fmt.Sprintf("Failed to communicate with device at %s:%d", ip, port),
		Reason:  extractNetworkReason(err),
		Hint:    "Device may not be a CIP/EtherNet-IP device, or there may be a network connectivity issue",
		Try:     fmt.Sprintf("cipdip test --ip %s --port %d", ip, port),
		Err:     err,
	}
}

// WrapCIPError wraps CIP protocol errors with user-friendly context
func WrapCIPError(err error, operation string) error {
	if err == nil {
		return nil
	}
	
	return UserFriendlyError{
		Message: fmt.Sprintf("CIP operation failed: %s", operation),
		Reason:  extractCIPReason(err),
		Hint:    "The device may not support this operation, or the CIP path may be incorrect",
		Try:     "Check your configuration file for correct class/instance/attribute values",
		Err:     err,
	}
}

// WrapConfigError wraps configuration errors with user-friendly context
func WrapConfigError(err error, configPath string) error {
	if err == nil {
		return nil
	}
	
	return UserFriendlyError{
		Message: fmt.Sprintf("Configuration error in %s", configPath),
		Reason:  err.Error(),
		Hint:    "See docs/CONFIGURATION.md for configuration examples",
		Try:     fmt.Sprintf("Validate your config: cipdip validate-config --config %s", configPath),
		Err:     err,
	}
}

func extractNetworkReason(err error) string {
	errStr := err.Error()
	
	// Common network error patterns
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") {
		return "Connection timeout - device may be offline or unreachable"
	}
	if strings.Contains(errStr, "connection refused") {
		return "Connection refused - device may not be listening on this port"
	}
	if strings.Contains(errStr, "no route to host") {
		return "No route to host - network routing issue or device unreachable"
	}
	if strings.Contains(errStr, "connection reset") {
		return "Connection reset - device closed the connection unexpectedly"
	}
	
	return "Network communication failed"
}

func extractCIPReason(err error) string {
	errStr := err.Error()
	
	// Common CIP error patterns
	if strings.Contains(errStr, "status 0x") {
		return "Device returned a CIP error status code"
	}
	if strings.Contains(errStr, "invalid packet") || strings.Contains(errStr, "decode") {
		return "Received invalid or malformed response from device"
	}
	if strings.Contains(errStr, "timeout") {
		return "Device did not respond within timeout period"
	}
	
	return "CIP protocol error occurred"
}

