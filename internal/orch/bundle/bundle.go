// Package bundle provides Run Bundle creation, management, and verification
// for distributed orchestration runs.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Standard bundle directory and file names.
const (
	ManifestFile         = "manifest.yaml"
	ResolvedManifestFile = "manifest_resolved.yaml"
	ProfileFile          = "profile.yaml"
	RunMetaFile          = "run_meta.json"
	VersionsFile         = "versions.json"
	HashesFile           = "hashes.txt"
	RolesDir             = "roles"
	AnalysisDir          = "analysis"
	ServerRole           = "server"
	ClientRole           = "client"
	StdoutLog            = "stdout.log"
	StderrLog            = "stderr.log"
	RoleMetaFile         = "role_meta.json"
)

// Bundle represents a Run Bundle directory.
type Bundle struct {
	Path  string
	RunID string
}

// RunMeta contains aggregated run metadata.
type RunMeta struct {
	RunID           string    `json:"run_id"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
	DurationSeconds float64   `json:"duration_seconds"`
	Status          string    `json:"status"` // success, failed, timeout
	ControllerHost  string    `json:"controller_host"`
	PhasesCompleted []string  `json:"phases_completed"`
	Error           string    `json:"error,omitempty"`
}

// Versions contains tool and environment version information.
type Versions struct {
	CipdipVersion  string                 `json:"cipdip_version"`
	GitCommit      string                 `json:"git_commit,omitempty"`
	BuildTimestamp string                 `json:"build_timestamp,omitempty"`
	GoVersion      string                 `json:"go_version,omitempty"`
	ControllerOS   string                 `json:"controller_os"`
	ControllerArch string                 `json:"controller_arch"`
	Roles          map[string]RoleVersion `json:"roles,omitempty"`
}

// RoleVersion contains version info for a specific role host.
type RoleVersion struct {
	Host      string `json:"host"`
	OS        string `json:"os,omitempty"`
	Arch      string `json:"arch,omitempty"`
	Transport string `json:"transport"` // local, ssh
}

// RoleMeta contains metadata for a single role execution.
type RoleMeta struct {
	Role        string    `json:"role"`
	AgentID     string    `json:"agent_id"`
	Argv        []string  `json:"argv"`
	BindIP      string    `json:"bind_ip,omitempty"`
	TargetIP    string    `json:"target_ip,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	ExitCode    int       `json:"exit_code"`
	PcapFiles   []string  `json:"pcap_files,omitempty"`
	MetricsFile string    `json:"metrics_file,omitempty"`
}

// Create creates a new bundle directory structure.
func Create(baseDir, runID string) (*Bundle, error) {
	bundlePath := filepath.Join(baseDir, runID)

	// Create main directory
	if err := os.MkdirAll(bundlePath, 0755); err != nil {
		return nil, fmt.Errorf("create bundle directory: %w", err)
	}

	// Create roles subdirectories
	for _, role := range []string{ServerRole, ClientRole} {
		roleDir := filepath.Join(bundlePath, RolesDir, role)
		if err := os.MkdirAll(roleDir, 0755); err != nil {
			return nil, fmt.Errorf("create role directory %s: %w", role, err)
		}
	}

	// Create analysis directory
	analysisDir := filepath.Join(bundlePath, AnalysisDir)
	if err := os.MkdirAll(analysisDir, 0755); err != nil {
		return nil, fmt.Errorf("create analysis directory: %w", err)
	}

	return &Bundle{
		Path:  bundlePath,
		RunID: runID,
	}, nil
}

// Open opens an existing bundle directory.
func Open(bundlePath string) (*Bundle, error) {
	info, err := os.Stat(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("open bundle: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("bundle path is not a directory: %s", bundlePath)
	}

	return &Bundle{
		Path:  bundlePath,
		RunID: filepath.Base(bundlePath),
	}, nil
}

// RoleDir returns the path to a role's directory.
func (b *Bundle) RoleDir(role string) string {
	return filepath.Join(b.Path, RolesDir, role)
}

// WriteManifest writes the original manifest to the bundle.
func (b *Bundle) WriteManifest(data []byte) error {
	return b.writeFile(ManifestFile, data)
}

// WriteResolvedManifest writes the resolved manifest to the bundle.
func (b *Bundle) WriteResolvedManifest(data []byte) error {
	return b.writeFile(ResolvedManifestFile, data)
}

// WriteProfile writes the profile content to the bundle.
func (b *Bundle) WriteProfile(data []byte) error {
	return b.writeFile(ProfileFile, data)
}

// WriteRunMeta writes the run metadata to the bundle.
func (b *Bundle) WriteRunMeta(meta *RunMeta) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal run meta: %w", err)
	}
	return b.writeFile(RunMetaFile, data)
}

// WriteVersions writes the versions info to the bundle.
func (b *Bundle) WriteVersions(versions *Versions) error {
	data, err := json.MarshalIndent(versions, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal versions: %w", err)
	}
	return b.writeFile(VersionsFile, data)
}

// WriteRoleMeta writes role metadata to the role directory.
func (b *Bundle) WriteRoleMeta(role string, meta *RoleMeta) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal role meta: %w", err)
	}
	path := filepath.Join(RolesDir, role, RoleMetaFile)
	return b.writeFile(path, data)
}

// WriteRoleLog writes a log file to the role directory.
func (b *Bundle) WriteRoleLog(role, filename string, data []byte) error {
	path := filepath.Join(RolesDir, role, filename)
	return b.writeFile(path, data)
}

// CopyFileToRole copies a file into the role directory.
func (b *Bundle) CopyFileToRole(role, srcPath, destFilename string) error {
	destPath := filepath.Join(b.Path, RolesDir, role, destFilename)
	return copyFile(srcPath, destPath)
}

// WriteAnalysis writes a file to the analysis directory.
func (b *Bundle) WriteAnalysis(filename string, data []byte) error {
	path := filepath.Join(AnalysisDir, filename)
	return b.writeFile(path, data)
}

// ComputeHashes calculates SHA256 hashes for all files in the bundle.
func (b *Bundle) ComputeHashes() (map[string]string, error) {
	hashes := make(map[string]string)

	err := filepath.Walk(b.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		// Skip the hashes file itself
		if filepath.Base(path) == HashesFile {
			return nil
		}

		relPath, err := filepath.Rel(b.Path, path)
		if err != nil {
			return err
		}

		hash, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("hash %s: %w", relPath, err)
		}

		hashes[relPath] = hash
		return nil
	})

	if err != nil {
		return nil, err
	}

	return hashes, nil
}

// WriteHashes writes the hashes file to the bundle.
func (b *Bundle) WriteHashes(hashes map[string]string) error {
	// Sort keys for deterministic output
	keys := make([]string, 0, len(hashes))
	for k := range hashes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var lines []string
	for _, k := range keys {
		lines = append(lines, fmt.Sprintf("%s  %s", hashes[k], k))
	}

	data := []byte(strings.Join(lines, "\n") + "\n")
	return b.writeFile(HashesFile, data)
}

// Finalize computes hashes and writes the hashes file.
func (b *Bundle) Finalize() error {
	hashes, err := b.ComputeHashes()
	if err != nil {
		return fmt.Errorf("compute hashes: %w", err)
	}
	return b.WriteHashes(hashes)
}

// writeFile writes data to a file within the bundle.
func (b *Bundle) writeFile(relPath string, data []byte) error {
	fullPath := filepath.Join(b.Path, relPath)

	// Ensure parent directory exists
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	if err := os.WriteFile(fullPath, data, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

// hashFile computes the SHA256 hash of a file.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	return dstFile.Sync()
}

// ReadRunMeta reads the run metadata from the bundle.
func (b *Bundle) ReadRunMeta() (*RunMeta, error) {
	data, err := os.ReadFile(filepath.Join(b.Path, RunMetaFile))
	if err != nil {
		return nil, err
	}
	var meta RunMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// ReadVersions reads the versions info from the bundle.
func (b *Bundle) ReadVersions() (*Versions, error) {
	data, err := os.ReadFile(filepath.Join(b.Path, VersionsFile))
	if err != nil {
		return nil, err
	}
	var versions Versions
	if err := json.Unmarshal(data, &versions); err != nil {
		return nil, err
	}
	return &versions, nil
}

// ReadRoleMeta reads role metadata from the bundle.
func (b *Bundle) ReadRoleMeta(role string) (*RoleMeta, error) {
	data, err := os.ReadFile(filepath.Join(b.Path, RolesDir, role, RoleMetaFile))
	if err != nil {
		return nil, err
	}
	var meta RoleMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// ReadHashes reads the hashes file from the bundle.
func (b *Bundle) ReadHashes() (map[string]string, error) {
	data, err := os.ReadFile(filepath.Join(b.Path, HashesFile))
	if err != nil {
		return nil, err
	}

	hashes := make(map[string]string)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			continue
		}
		hashes[parts[1]] = parts[0]
	}

	return hashes, nil
}

// ListRolePcaps returns the PCAP files in a role directory.
func (b *Bundle) ListRolePcaps(role string) ([]string, error) {
	roleDir := b.RoleDir(role)
	entries, err := os.ReadDir(roleDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var pcaps []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".pcap") || strings.HasSuffix(name, ".pcapng") {
			pcaps = append(pcaps, name)
		}
	}

	return pcaps, nil
}

// Unused but required by yaml import
var _ = yaml.Marshal
