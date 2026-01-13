package bundle

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// VerifyResult contains the results of bundle verification.
type VerifyResult struct {
	Valid           bool
	Errors          []string
	Warnings        []string
	FilesChecked    int
	HashesVerified  int
	HashMismatches  []string
	MissingFiles    []string
	ExtraFiles      []string
}

// VerifyOptions configures bundle verification.
type VerifyOptions struct {
	CheckHashes      bool // Verify file hashes
	CheckPcaps       bool // Verify PCAP files exist and are non-empty
	StrictSchema     bool // Require all expected files
	AllowExtraFiles  bool // Don't warn about extra files
}

// DefaultVerifyOptions returns the default verification options.
func DefaultVerifyOptions() VerifyOptions {
	return VerifyOptions{
		CheckHashes:     true,
		CheckPcaps:      true,
		StrictSchema:    true,
		AllowExtraFiles: true,
	}
}

// Verify checks the bundle for correctness.
func (b *Bundle) Verify(opts VerifyOptions) (*VerifyResult, error) {
	result := &VerifyResult{
		Valid: true,
	}

	// Check required files exist
	requiredFiles := []string{
		ManifestFile,
		RunMetaFile,
		VersionsFile,
	}

	if opts.StrictSchema {
		requiredFiles = append(requiredFiles, ResolvedManifestFile)
	}

	for _, f := range requiredFiles {
		path := filepath.Join(b.Path, f)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			result.MissingFiles = append(result.MissingFiles, f)
			result.Errors = append(result.Errors, fmt.Sprintf("missing required file: %s", f))
			result.Valid = false
		}
	}

	// Check hashes file exists and verify
	if opts.CheckHashes {
		hashesPath := filepath.Join(b.Path, HashesFile)
		if _, err := os.Stat(hashesPath); os.IsNotExist(err) {
			result.Errors = append(result.Errors, "missing hashes.txt file")
			result.Valid = false
		} else {
			if err := b.verifyHashes(result); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("hash verification failed: %v", err))
				result.Valid = false
			}
		}
	}

	// Check run_meta.json is valid JSON
	if meta, err := b.ReadRunMeta(); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("invalid run_meta.json: %v", err))
		result.Valid = false
	} else {
		// Validate run_meta fields
		if meta.RunID == "" {
			result.Warnings = append(result.Warnings, "run_meta.json: run_id is empty")
		}
		if meta.Status == "" {
			result.Warnings = append(result.Warnings, "run_meta.json: status is empty")
		}
	}

	// Check versions.json is valid JSON
	if versions, err := b.ReadVersions(); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("invalid versions.json: %v", err))
		result.Valid = false
	} else {
		if versions.CipdipVersion == "" {
			result.Warnings = append(result.Warnings, "versions.json: cipdip_version is empty")
		}
	}

	// Check PCAP files
	if opts.CheckPcaps {
		if err := b.verifyPcaps(result); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("PCAP verification failed: %v", err))
			result.Valid = false
		}
	}

	// Count files checked
	_ = filepath.Walk(b.Path, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			result.FilesChecked++
		}
		return nil
	})

	return result, nil
}

// verifyHashes checks that all file hashes match.
func (b *Bundle) verifyHashes(result *VerifyResult) error {
	storedHashes, err := b.ReadHashes()
	if err != nil {
		return err
	}

	currentHashes, err := b.ComputeHashes()
	if err != nil {
		return err
	}

	// Check each stored hash
	for file, storedHash := range storedHashes {
		result.HashesVerified++
		currentHash, exists := currentHashes[file]
		if !exists {
			result.MissingFiles = append(result.MissingFiles, file)
			result.Errors = append(result.Errors, fmt.Sprintf("file in hashes.txt not found: %s", file))
			result.Valid = false
			continue
		}
		if currentHash != storedHash {
			result.HashMismatches = append(result.HashMismatches, file)
			result.Errors = append(result.Errors, fmt.Sprintf("hash mismatch for %s: expected %s, got %s", file, storedHash, currentHash))
			result.Valid = false
		}
	}

	// Check for extra files not in hashes
	for file := range currentHashes {
		if _, exists := storedHashes[file]; !exists {
			result.ExtraFiles = append(result.ExtraFiles, file)
			result.Warnings = append(result.Warnings, fmt.Sprintf("file not in hashes.txt: %s", file))
		}
	}

	return nil
}

// verifyPcaps checks that PCAP files exist and are non-empty.
func (b *Bundle) verifyPcaps(result *VerifyResult) error {
	roles := []string{ServerRole, ClientRole}

	for _, role := range roles {
		roleDir := b.RoleDir(role)
		if _, err := os.Stat(roleDir); os.IsNotExist(err) {
			continue // Role directory doesn't exist, which may be fine
		}

		// Check for role_meta.json to see if this role was used
		metaPath := filepath.Join(roleDir, RoleMetaFile)
		if _, err := os.Stat(metaPath); os.IsNotExist(err) {
			continue // No role meta, role wasn't used
		}

		// Read role meta to get expected PCAP files
		meta, err := b.ReadRoleMeta(role)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("could not read %s role_meta.json: %v", role, err))
			continue
		}

		// Check each expected PCAP file
		for _, pcapFile := range meta.PcapFiles {
			pcapPath := filepath.Join(roleDir, pcapFile)
			info, err := os.Stat(pcapPath)
			if os.IsNotExist(err) {
				result.Errors = append(result.Errors, fmt.Sprintf("%s role: missing PCAP file %s", role, pcapFile))
				result.Valid = false
				continue
			}
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s role: error checking PCAP %s: %v", role, pcapFile, err))
				result.Valid = false
				continue
			}
			if info.Size() == 0 {
				result.Warnings = append(result.Warnings, fmt.Sprintf("%s role: PCAP file %s is empty", role, pcapFile))
			}
		}
	}

	return nil
}

// FormatResult returns a human-readable summary of verification results.
func (r *VerifyResult) FormatResult() string {
	var sb strings.Builder

	if r.Valid {
		sb.WriteString("Bundle verification: PASSED\n")
	} else {
		sb.WriteString("Bundle verification: FAILED\n")
	}

	sb.WriteString(fmt.Sprintf("Files checked: %d\n", r.FilesChecked))
	sb.WriteString(fmt.Sprintf("Hashes verified: %d\n", r.HashesVerified))

	if len(r.Errors) > 0 {
		sb.WriteString("\nErrors:\n")
		for _, err := range r.Errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", err))
		}
	}

	if len(r.Warnings) > 0 {
		sb.WriteString("\nWarnings:\n")
		for _, warn := range r.Warnings {
			sb.WriteString(fmt.Sprintf("  - %s\n", warn))
		}
	}

	if len(r.HashMismatches) > 0 {
		sb.WriteString("\nHash mismatches:\n")
		for _, f := range r.HashMismatches {
			sb.WriteString(fmt.Sprintf("  - %s\n", f))
		}
	}

	if len(r.MissingFiles) > 0 {
		sb.WriteString("\nMissing files:\n")
		for _, f := range r.MissingFiles {
			sb.WriteString(fmt.Sprintf("  - %s\n", f))
		}
	}

	return sb.String()
}
