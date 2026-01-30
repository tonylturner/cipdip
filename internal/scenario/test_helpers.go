package scenario

import "errors"

// Test helpers and common errors for scenario tests

// errConnectionRefused is used by tests to simulate connection failures
var errConnectionRefused = errors.New("connection refused")
