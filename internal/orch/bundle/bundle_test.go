package bundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreate(t *testing.T) {
	tmpDir := t.TempDir()

	b, err := Create(tmpDir, "test-run-001")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Check bundle path
	expectedPath := filepath.Join(tmpDir, "test-run-001")
	if b.Path != expectedPath {
		t.Errorf("Bundle.Path = %v, want %v", b.Path, expectedPath)
	}

	// Check directories exist
	dirs := []string{
		b.Path,
		filepath.Join(b.Path, RolesDir, ServerRole),
		filepath.Join(b.Path, RolesDir, ClientRole),
		filepath.Join(b.Path, AnalysisDir),
	}

	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("Directory not created: %s", dir)
		}
	}
}

func TestOpen(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a bundle first
	_, err := Create(tmpDir, "test-run")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Open it
	b, err := Open(filepath.Join(tmpDir, "test-run"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	if b.RunID != "test-run" {
		t.Errorf("Bundle.RunID = %v, want test-run", b.RunID)
	}

	// Try to open non-existent
	_, err = Open(filepath.Join(tmpDir, "nonexistent"))
	if err == nil {
		t.Error("Open() should fail for non-existent bundle")
	}
}

func TestWriteAndReadRunMeta(t *testing.T) {
	tmpDir := t.TempDir()
	b, _ := Create(tmpDir, "test-run")

	meta := &RunMeta{
		RunID:           "test-run",
		StartedAt:       time.Now().Add(-time.Minute),
		FinishedAt:      time.Now(),
		DurationSeconds: 60,
		Status:          "success",
		ControllerHost:  "localhost",
		PhasesCompleted: []string{"init", "stage", "done"},
	}

	if err := b.WriteRunMeta(meta); err != nil {
		t.Fatalf("WriteRunMeta() error = %v", err)
	}

	// Read it back
	readMeta, err := b.ReadRunMeta()
	if err != nil {
		t.Fatalf("ReadRunMeta() error = %v", err)
	}

	if readMeta.RunID != meta.RunID {
		t.Errorf("RunID = %v, want %v", readMeta.RunID, meta.RunID)
	}
	if readMeta.Status != meta.Status {
		t.Errorf("Status = %v, want %v", readMeta.Status, meta.Status)
	}
	if len(readMeta.PhasesCompleted) != len(meta.PhasesCompleted) {
		t.Errorf("PhasesCompleted length = %v, want %v", len(readMeta.PhasesCompleted), len(meta.PhasesCompleted))
	}
}

func TestWriteAndReadVersions(t *testing.T) {
	tmpDir := t.TempDir()
	b, _ := Create(tmpDir, "test-run")

	versions := &Versions{
		CipdipVersion:  "0.2.1",
		GitCommit:      "abc123",
		ControllerOS:   "darwin",
		ControllerArch: "arm64",
		Roles: map[string]RoleVersion{
			"server": {Host: "server.local", Transport: "ssh"},
			"client": {Host: "localhost", Transport: "local"},
		},
	}

	if err := b.WriteVersions(versions); err != nil {
		t.Fatalf("WriteVersions() error = %v", err)
	}

	readVersions, err := b.ReadVersions()
	if err != nil {
		t.Fatalf("ReadVersions() error = %v", err)
	}

	if readVersions.CipdipVersion != versions.CipdipVersion {
		t.Errorf("CipdipVersion = %v, want %v", readVersions.CipdipVersion, versions.CipdipVersion)
	}
	if len(readVersions.Roles) != 2 {
		t.Errorf("Roles count = %v, want 2", len(readVersions.Roles))
	}
}

func TestWriteAndReadRoleMeta(t *testing.T) {
	tmpDir := t.TempDir()
	b, _ := Create(tmpDir, "test-run")

	meta := &RoleMeta{
		Role:       "client",
		AgentID:    "local",
		Argv:       []string{"cipdip", "client", "--ip", "10.0.0.1"},
		TargetIP:   "10.0.0.1",
		StartedAt:  time.Now().Add(-time.Minute),
		FinishedAt: time.Now(),
		ExitCode:   0,
		PcapFiles:  []string{"client.pcap"},
	}

	if err := b.WriteRoleMeta("client", meta); err != nil {
		t.Fatalf("WriteRoleMeta() error = %v", err)
	}

	readMeta, err := b.ReadRoleMeta("client")
	if err != nil {
		t.Fatalf("ReadRoleMeta() error = %v", err)
	}

	if readMeta.Role != meta.Role {
		t.Errorf("Role = %v, want %v", readMeta.Role, meta.Role)
	}
	if readMeta.ExitCode != meta.ExitCode {
		t.Errorf("ExitCode = %v, want %v", readMeta.ExitCode, meta.ExitCode)
	}
}

func TestComputeAndWriteHashes(t *testing.T) {
	tmpDir := t.TempDir()
	b, _ := Create(tmpDir, "test-run")

	// Write some files
	if err := b.WriteManifest([]byte("manifest content")); err != nil {
		t.Fatalf("WriteManifest() error = %v", err)
	}
	if err := b.WriteProfile([]byte("profile content")); err != nil {
		t.Fatalf("WriteProfile() error = %v", err)
	}

	// Compute hashes
	hashes, err := b.ComputeHashes()
	if err != nil {
		t.Fatalf("ComputeHashes() error = %v", err)
	}

	if len(hashes) != 2 {
		t.Errorf("Expected 2 hashes, got %d", len(hashes))
	}

	// Check hash format
	for file, hash := range hashes {
		if !strings.HasPrefix(hash, "sha256:") {
			t.Errorf("Hash for %s doesn't start with sha256: %s", file, hash)
		}
	}

	// Write and read back
	if err := b.WriteHashes(hashes); err != nil {
		t.Fatalf("WriteHashes() error = %v", err)
	}

	readHashes, err := b.ReadHashes()
	if err != nil {
		t.Fatalf("ReadHashes() error = %v", err)
	}

	if len(readHashes) != len(hashes) {
		t.Errorf("Read %d hashes, want %d", len(readHashes), len(hashes))
	}

	for file, hash := range hashes {
		if readHashes[file] != hash {
			t.Errorf("Hash mismatch for %s: got %s, want %s", file, readHashes[file], hash)
		}
	}
}

func TestFinalize(t *testing.T) {
	tmpDir := t.TempDir()
	b, _ := Create(tmpDir, "test-run")

	// Write required files
	b.WriteManifest([]byte("manifest"))
	b.WriteRunMeta(&RunMeta{RunID: "test-run", Status: "success"})
	b.WriteVersions(&Versions{CipdipVersion: "0.2.1"})

	// Finalize
	if err := b.Finalize(); err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}

	// Check hashes file exists
	hashesPath := filepath.Join(b.Path, HashesFile)
	if _, err := os.Stat(hashesPath); os.IsNotExist(err) {
		t.Error("hashes.txt not created")
	}
}

func TestVerify(t *testing.T) {
	tmpDir := t.TempDir()
	b, _ := Create(tmpDir, "test-run")

	// Create a complete bundle
	b.WriteManifest([]byte("api_version: v1"))
	b.WriteResolvedManifest([]byte("resolved manifest"))
	b.WriteProfile([]byte("profile"))
	b.WriteRunMeta(&RunMeta{
		RunID:  "test-run",
		Status: "success",
	})
	b.WriteVersions(&Versions{
		CipdipVersion:  "0.2.1",
		ControllerOS:   "darwin",
		ControllerArch: "arm64",
	})
	b.Finalize()

	// Verify
	result, err := b.Verify(DefaultVerifyOptions())
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !result.Valid {
		t.Errorf("Bundle should be valid. Errors: %v", result.Errors)
	}
}

func TestVerify_MissingFiles(t *testing.T) {
	tmpDir := t.TempDir()
	b, _ := Create(tmpDir, "test-run")

	// Create incomplete bundle (missing manifest)
	b.WriteRunMeta(&RunMeta{RunID: "test-run", Status: "success"})
	b.WriteVersions(&Versions{CipdipVersion: "0.2.1"})

	result, _ := b.Verify(DefaultVerifyOptions())

	if result.Valid {
		t.Error("Bundle should be invalid due to missing manifest")
	}
	if len(result.MissingFiles) == 0 {
		t.Error("Should report missing files")
	}
}

func TestVerify_HashMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	b, _ := Create(tmpDir, "test-run")

	// Create complete bundle
	b.WriteManifest([]byte("original content"))
	b.WriteResolvedManifest([]byte("resolved"))
	b.WriteRunMeta(&RunMeta{RunID: "test-run", Status: "success"})
	b.WriteVersions(&Versions{CipdipVersion: "0.2.1"})
	b.Finalize()

	// Modify a file after finalization
	manifestPath := filepath.Join(b.Path, ManifestFile)
	os.WriteFile(manifestPath, []byte("modified content"), 0644)

	result, _ := b.Verify(DefaultVerifyOptions())

	if result.Valid {
		t.Error("Bundle should be invalid due to hash mismatch")
	}
	if len(result.HashMismatches) == 0 {
		t.Error("Should report hash mismatch")
	}
}

func TestCopyFileToRole(t *testing.T) {
	tmpDir := t.TempDir()
	b, _ := Create(tmpDir, "test-run")

	// Create a source file
	srcPath := filepath.Join(tmpDir, "source.pcap")
	if err := os.WriteFile(srcPath, []byte("pcap data"), 0644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	// Copy to role
	if err := b.CopyFileToRole("client", srcPath, "client.pcap"); err != nil {
		t.Fatalf("CopyFileToRole() error = %v", err)
	}

	// Verify copy exists
	destPath := filepath.Join(b.RoleDir("client"), "client.pcap")
	if _, err := os.Stat(destPath); os.IsNotExist(err) {
		t.Error("Copied file not found")
	}

	// Verify content
	data, _ := os.ReadFile(destPath)
	if string(data) != "pcap data" {
		t.Errorf("Content mismatch: got %s", string(data))
	}
}

func TestListRolePcaps(t *testing.T) {
	tmpDir := t.TempDir()
	b, _ := Create(tmpDir, "test-run")

	// Create some PCAP files
	roleDir := b.RoleDir("client")
	os.WriteFile(filepath.Join(roleDir, "client.pcap"), []byte("pcap1"), 0644)
	os.WriteFile(filepath.Join(roleDir, "other.pcapng"), []byte("pcap2"), 0644)
	os.WriteFile(filepath.Join(roleDir, "not_pcap.txt"), []byte("text"), 0644)

	pcaps, err := b.ListRolePcaps("client")
	if err != nil {
		t.Fatalf("ListRolePcaps() error = %v", err)
	}

	if len(pcaps) != 2 {
		t.Errorf("Expected 2 PCAP files, got %d", len(pcaps))
	}
}

func TestVerifyResult_FormatResult(t *testing.T) {
	result := &VerifyResult{
		Valid:          false,
		FilesChecked:   10,
		HashesVerified: 8,
		Errors:         []string{"error1", "error2"},
		Warnings:       []string{"warning1"},
		HashMismatches: []string{"file1.txt"},
		MissingFiles:   []string{"missing.txt"},
	}

	output := result.FormatResult()

	if !strings.Contains(output, "FAILED") {
		t.Error("Output should contain FAILED")
	}
	if !strings.Contains(output, "Files checked: 10") {
		t.Error("Output should contain files checked count")
	}
	if !strings.Contains(output, "error1") {
		t.Error("Output should contain errors")
	}
	if !strings.Contains(output, "warning1") {
		t.Error("Output should contain warnings")
	}
}
