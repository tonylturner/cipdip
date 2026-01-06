package app

import (
	"fmt"
	"os"
	"path/filepath"
)

func ResolveCatalogRoot(root string) (string, error) {
	if root != "" {
		return root, nil
	}
	if _, err := os.Stat(filepath.Join("workspaces", "workspace", "catalogs")); err == nil {
		return filepath.Join("workspaces", "workspace"), nil
	}
	if _, err := os.Stat(filepath.Join("workspace", "catalogs")); err == nil {
		return "workspace", nil
	}
	if _, err := os.Stat("catalogs"); err == nil {
		return ".", nil
	}
	return "", fmt.Errorf("catalog root not found (use --catalog-root)")
}
