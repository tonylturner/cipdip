package controller

import (
	"context"
	"fmt"
	"net"
	"time"
)

// WaitForTCPReady polls TCP connect until the server is ready.
func WaitForTCPReady(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}

	return fmt.Errorf("server not ready at %s after %v", addr, timeout)
}

// WaitForTCPReadyWithRetry polls TCP connect with configurable retry parameters.
func WaitForTCPReadyWithRetry(ctx context.Context, addr string, timeout, dialTimeout, retryInterval time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn, err := net.DialTimeout("tcp", addr, dialTimeout)
		if err == nil {
			conn.Close()
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retryInterval):
		}
	}

	return fmt.Errorf("server not ready at %s after %v", addr, timeout)
}
