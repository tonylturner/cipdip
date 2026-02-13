package errors

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestUserFriendlyError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      UserFriendlyError
		contains []string
	}{
		{
			name:     "message only",
			err:      UserFriendlyError{Message: "something broke"},
			contains: []string{"something broke"},
		},
		{
			name: "all fields",
			err: UserFriendlyError{
				Message: "connection failed",
				Reason:  "timeout",
				Hint:    "check network",
				Try:     "ping host",
				Err:     fmt.Errorf("dial tcp: timeout"),
			},
			contains: []string{"connection failed", "Reason: timeout", "Hint: check network", "Try: ping host", "Details: dial tcp: timeout"},
		},
		{
			name: "no reason",
			err: UserFriendlyError{
				Message: "failed",
				Hint:    "hint here",
			},
			contains: []string{"failed", "Hint: hint here"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, s := range tt.contains {
				if !strings.Contains(msg, s) {
					t.Errorf("Error() = %q, want to contain %q", msg, s)
				}
			}
		})
	}
}

func TestUserFriendlyError_ErrorOmitsEmptyFields(t *testing.T) {
	err := UserFriendlyError{Message: "msg"}
	msg := err.Error()
	if strings.Contains(msg, "Reason:") || strings.Contains(msg, "Hint:") || strings.Contains(msg, "Try:") || strings.Contains(msg, "Details:") {
		t.Errorf("Error() = %q, should not contain empty fields", msg)
	}
}

func TestUserFriendlyError_Unwrap(t *testing.T) {
	inner := fmt.Errorf("root cause")
	err := UserFriendlyError{Message: "wrapper", Err: inner}

	if !errors.Is(err, inner) {
		t.Error("Unwrap should return the inner error")
	}

	var nilErr UserFriendlyError
	if nilErr.Unwrap() != nil {
		t.Error("Unwrap on nil Err should return nil")
	}
}

func TestWrapNetworkError(t *testing.T) {
	t.Run("nil error returns nil", func(t *testing.T) {
		if WrapNetworkError(nil, "10.0.0.1", 44818) != nil {
			t.Error("expected nil")
		}
	})

	t.Run("timeout error", func(t *testing.T) {
		err := WrapNetworkError(fmt.Errorf("dial tcp: i/o timeout"), "10.0.0.1", 44818)
		ufe := err.(UserFriendlyError)
		if !strings.Contains(ufe.Message, "10.0.0.1:44818") {
			t.Errorf("message should contain address, got %q", ufe.Message)
		}
		if !strings.Contains(ufe.Reason, "timeout") {
			t.Errorf("reason should mention timeout, got %q", ufe.Reason)
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		err := WrapNetworkError(fmt.Errorf("connection refused"), "10.0.0.1", 44818)
		ufe := err.(UserFriendlyError)
		if !strings.Contains(ufe.Reason, "refused") {
			t.Errorf("reason should mention refused, got %q", ufe.Reason)
		}
	})

	t.Run("no route to host", func(t *testing.T) {
		err := WrapNetworkError(fmt.Errorf("no route to host"), "10.0.0.1", 44818)
		ufe := err.(UserFriendlyError)
		if !strings.Contains(ufe.Reason, "route") {
			t.Errorf("reason should mention route, got %q", ufe.Reason)
		}
	})

	t.Run("connection reset", func(t *testing.T) {
		err := WrapNetworkError(fmt.Errorf("connection reset by peer"), "10.0.0.1", 44818)
		ufe := err.(UserFriendlyError)
		if !strings.Contains(ufe.Reason, "reset") {
			t.Errorf("reason should mention reset, got %q", ufe.Reason)
		}
	})

	t.Run("generic network error", func(t *testing.T) {
		err := WrapNetworkError(fmt.Errorf("something else"), "10.0.0.1", 44818)
		ufe := err.(UserFriendlyError)
		if ufe.Reason != "Network communication failed" {
			t.Errorf("unexpected reason: %q", ufe.Reason)
		}
	})
}

func TestWrapCIPError(t *testing.T) {
	t.Run("nil error returns nil", func(t *testing.T) {
		if WrapCIPError(nil, "read") != nil {
			t.Error("expected nil")
		}
	})

	t.Run("status code error", func(t *testing.T) {
		err := WrapCIPError(fmt.Errorf("CIP status 0x08"), "GetAttributeSingle")
		ufe := err.(UserFriendlyError)
		if !strings.Contains(ufe.Message, "GetAttributeSingle") {
			t.Errorf("message should contain operation, got %q", ufe.Message)
		}
		if !strings.Contains(ufe.Reason, "status code") {
			t.Errorf("reason should mention status code, got %q", ufe.Reason)
		}
	})

	t.Run("invalid packet error", func(t *testing.T) {
		err := WrapCIPError(fmt.Errorf("invalid packet data"), "read")
		ufe := err.(UserFriendlyError)
		if !strings.Contains(ufe.Reason, "malformed") {
			t.Errorf("reason should mention malformed, got %q", ufe.Reason)
		}
	})

	t.Run("decode error", func(t *testing.T) {
		err := WrapCIPError(fmt.Errorf("failed to decode response"), "read")
		ufe := err.(UserFriendlyError)
		if !strings.Contains(ufe.Reason, "malformed") {
			t.Errorf("reason should mention malformed, got %q", ufe.Reason)
		}
	})

	t.Run("timeout error", func(t *testing.T) {
		err := WrapCIPError(fmt.Errorf("timeout waiting for response"), "read")
		ufe := err.(UserFriendlyError)
		if !strings.Contains(ufe.Reason, "timeout") {
			t.Errorf("reason should mention timeout, got %q", ufe.Reason)
		}
	})

	t.Run("generic CIP error", func(t *testing.T) {
		err := WrapCIPError(fmt.Errorf("something"), "read")
		ufe := err.(UserFriendlyError)
		if ufe.Reason != "CIP protocol error occurred" {
			t.Errorf("unexpected reason: %q", ufe.Reason)
		}
	})
}

func TestWrapConfigError(t *testing.T) {
	t.Run("nil error returns nil", func(t *testing.T) {
		if WrapConfigError(nil, "config.yaml") != nil {
			t.Error("expected nil")
		}
	})

	t.Run("wraps config error", func(t *testing.T) {
		err := WrapConfigError(fmt.Errorf("invalid yaml"), "cipdip_client.yaml")
		ufe := err.(UserFriendlyError)
		if !strings.Contains(ufe.Message, "cipdip_client.yaml") {
			t.Errorf("message should contain config path, got %q", ufe.Message)
		}
		if ufe.Reason != "invalid yaml" {
			t.Errorf("reason should be inner error message, got %q", ufe.Reason)
		}
		if !strings.Contains(ufe.Hint, "CONFIGURATION.md") {
			t.Errorf("hint should reference docs, got %q", ufe.Hint)
		}
	})
}
