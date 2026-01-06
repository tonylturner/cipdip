package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func resolveReportPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	if filepath.Dir(path) != "." {
		return path, nil
	}
	reportsDir := "reports"
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		return "", fmt.Errorf("create reports dir: %w", err)
	}
	return filepath.Join(reportsDir, path), nil
}
