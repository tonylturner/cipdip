package app

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func ResolveExternalPath(explicit, envKey, name string) (string, error) {
	if explicit == "" {
		explicit = os.Getenv(envKey)
	}
	if explicit != "" {
		if filepath.Base(explicit) == explicit {
			path, err := exec.LookPath(explicit)
			if err != nil {
				return "", fmt.Errorf("%s not found in PATH", name)
			}
			return path, nil
		}
		return explicit, nil
	}

	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not found in PATH; set %s or --%s", name, envKey, name)
	}
	return path, nil
}

func runExternal(path string, args []string) error {
	cmd := exec.Command(path, args...)
	var stderr bytes.Buffer
	cmd.Stdout = os.Stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %s", filepath.Base(path), strings.TrimSpace(stderr.String()))
	}
	return nil
}
