package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/transport"
)

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Agent management and status",
		Long: `Commands for managing and querying agent capabilities.

The agent command provides tools for checking local and remote agent
readiness for orchestrated runs. Agents are SSH-based - no daemon is
required. Simply ensure cipdip is installed on the remote host.

Use 'agent status' to check local capabilities.
Use 'agent check' to validate remote agent connectivity.`,
	}

	cmd.AddCommand(newAgentStatusCmd())
	cmd.AddCommand(newAgentCheckCmd())

	return cmd
}

func newAgentStatusCmd() *cobra.Command {
	var flags struct {
		json    bool
		workdir string
	}

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show local agent status and capabilities",
		Long: `Display the local system's capabilities for acting as a cipdip agent.

This includes:
- cipdip version and build information
- Operating system and architecture
- Available network interfaces
- Working directory status
- Packet capture capability

Examples:
  cipdip agent status
  cipdip agent status --json
  cipdip agent status --workdir /tmp/cipdip`,
		RunE: func(cmd *cobra.Command, args []string) error {
			status := getAgentStatus(flags.workdir)

			if flags.json {
				data, err := json.MarshalIndent(status, "", "  ")
				if err != nil {
					return fmt.Errorf("marshal status: %w", err)
				}
				fmt.Println(string(data))
				return nil
			}

			printAgentStatus(status)
			return nil
		},
	}

	cmd.Flags().BoolVar(&flags.json, "json", false, "Output in JSON format")
	cmd.Flags().StringVar(&flags.workdir, "workdir", "/tmp/cipdip", "Working directory to check")

	return cmd
}

func newAgentCheckCmd() *cobra.Command {
	var flags struct {
		timeout time.Duration
		json    bool
	}

	cmd := &cobra.Command{
		Use:   "check <transport-spec>",
		Short: "Check remote agent connectivity and capabilities",
		Long: `Validate that a remote host is reachable and capable of acting as an agent.

The transport spec can be:
- ssh://user@host:port - SSH URL format
- user@host:port - Shorthand SSH format
- user@host - SSH with default port
- host - SSH with current user and default port

Examples:
  cipdip agent check ssh://root@192.168.1.10
  cipdip agent check user@server.local
  cipdip agent check server.local --timeout 30s`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := args[0]

			// Parse transport
			t, err := transport.Parse(spec)
			if err != nil {
				return fmt.Errorf("invalid transport spec: %w", err)
			}
			defer t.Close()

			ctx, cancel := context.WithTimeout(context.Background(), flags.timeout)
			defer cancel()

			result := checkRemoteAgent(ctx, t, spec)

			if flags.json {
				data, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return fmt.Errorf("marshal result: %w", err)
				}
				fmt.Println(string(data))
				if !result.OK {
					os.Exit(1)
				}
				return nil
			}

			printCheckResult(result)
			if !result.OK {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().DurationVar(&flags.timeout, "timeout", 30*time.Second, "Connection timeout")
	cmd.Flags().BoolVar(&flags.json, "json", false, "Output in JSON format")

	return cmd
}

// AgentStatus represents local agent capabilities.
type AgentStatus struct {
	Version      string           `json:"version"`
	GitCommit    string           `json:"git_commit"`
	OS           string           `json:"os"`
	Arch         string           `json:"arch"`
	Hostname     string           `json:"hostname"`
	Workdir      WorkdirStatus    `json:"workdir"`
	Interfaces   []InterfaceInfo  `json:"interfaces"`
	PcapCapable  bool             `json:"pcap_capable"`
	PcapMethod   string           `json:"pcap_method,omitempty"`
	SupportedRoles []string       `json:"supported_roles"`
}

// WorkdirStatus represents working directory status.
type WorkdirStatus struct {
	Path     string `json:"path"`
	Exists   bool   `json:"exists"`
	Writable bool   `json:"writable"`
	Error    string `json:"error,omitempty"`
}

// InterfaceInfo represents a network interface.
type InterfaceInfo struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	CanBind   bool     `json:"can_bind"`
}

// CheckResult represents the result of checking a remote agent.
type CheckResult struct {
	OK           bool          `json:"ok"`
	Transport    string        `json:"transport"`
	Connected    bool          `json:"connected"`
	ConnectError string        `json:"connect_error,omitempty"`
	CipdipFound  bool          `json:"cipdip_found"`
	Version      string        `json:"version,omitempty"`
	RemoteOS     string        `json:"remote_os,omitempty"`
	RemoteArch   string        `json:"remote_arch,omitempty"`
	Latency      time.Duration `json:"latency_ms"`
	Checks       []CheckItem   `json:"checks"`
}

// CheckItem represents a single check result.
type CheckItem struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "pass", "fail", "skip"
	Detail string `json:"detail,omitempty"`
}

func getAgentStatus(workdir string) *AgentStatus {
	hostname, _ := os.Hostname()

	status := &AgentStatus{
		Version:        version,
		GitCommit:      commit,
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		Hostname:       hostname,
		SupportedRoles: []string{"server", "client"},
	}

	// Check workdir
	status.Workdir = checkWorkdir(workdir)

	// Get network interfaces
	status.Interfaces = getInterfaces()

	// Check pcap capability
	status.PcapCapable, status.PcapMethod = checkPcapCapability()

	return status
}

func checkWorkdir(path string) WorkdirStatus {
	ws := WorkdirStatus{Path: path}

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Try to create it
			if err := os.MkdirAll(path, 0755); err != nil {
				ws.Error = fmt.Sprintf("cannot create: %v", err)
				return ws
			}
			ws.Exists = true
			ws.Writable = true
			// Clean up
			os.Remove(path)
			return ws
		}
		ws.Error = err.Error()
		return ws
	}

	ws.Exists = true
	if !info.IsDir() {
		ws.Error = "path exists but is not a directory"
		return ws
	}

	// Test writability
	testFile := filepath.Join(path, ".cipdip-test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		ws.Error = fmt.Sprintf("not writable: %v", err)
		return ws
	}
	os.Remove(testFile)
	ws.Writable = true

	return ws
}

func getInterfaces() []InterfaceInfo {
	var result []InterfaceInfo

	ifaces, err := net.Interfaces()
	if err != nil {
		return result
	}

	for _, iface := range ifaces {
		// Skip loopback and down interfaces for primary listing
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		info := InterfaceInfo{
			Name: iface.Name,
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				// Skip IPv6 link-local
				if ipnet.IP.IsLinkLocalUnicast() {
					continue
				}
				info.Addresses = append(info.Addresses, ipnet.IP.String())
			}
		}

		if len(info.Addresses) > 0 {
			// Test if we can bind to the first address
			info.CanBind = canBindAddress(info.Addresses[0])
			result = append(result, info)
		}
	}

	return result
}

func canBindAddress(ip string) bool {
	// Try to bind a listener briefly
	addr := net.JoinHostPort(ip, "0")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

func checkPcapCapability() (bool, string) {
	// Check for tcpdump (most portable)
	if _, err := exec.LookPath("tcpdump"); err == nil {
		return true, "tcpdump"
	}

	// Check for tshark in PATH
	if _, err := exec.LookPath("tshark"); err == nil {
		return true, "tshark"
	}

	// On Windows, check standard installation locations
	if runtime.GOOS == "windows" {
		// Check for tshark in standard Wireshark install location
		programFiles := os.Getenv("ProgramFiles")
		if programFiles == "" {
			programFiles = `C:\Program Files`
		}
		tsharkPath := filepath.Join(programFiles, "Wireshark", "tshark.exe")
		if _, err := os.Stat(tsharkPath); err == nil {
			return true, "tshark"
		}

		// Check for npcap DLL in System32\Npcap (standard install)
		systemRoot := os.Getenv("SystemRoot")
		if systemRoot == "" {
			systemRoot = `C:\Windows`
		}
		npcapPath := filepath.Join(systemRoot, "System32", "Npcap", "wpcap.dll")
		if _, err := os.Stat(npcapPath); err == nil {
			return true, "npcap"
		}
		// Check for WinPcap compatibility mode (wpcap.dll in System32)
		wpcapPath := filepath.Join(systemRoot, "System32", "wpcap.dll")
		if _, err := os.Stat(wpcapPath); err == nil {
			return true, "npcap"
		}
	}

	// On Linux, check for raw socket capability
	if runtime.GOOS == "linux" {
		// Check if we can read /proc/net/dev (basic check)
		if _, err := os.ReadFile("/proc/net/dev"); err == nil {
			return true, "raw_socket"
		}
	}

	// On macOS, BPF is typically available
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat("/dev/bpf0"); err == nil {
			return true, "bpf"
		}
	}

	return false, ""
}

func checkRemoteAgent(ctx context.Context, t transport.Transport, spec string) *CheckResult {
	result := &CheckResult{
		Transport: spec,
		Checks:    []CheckItem{},
	}

	start := time.Now()

	// Check 1: Basic connectivity
	exitCode, _, _, err := t.Exec(ctx, []string{"true"}, nil, "")
	result.Latency = time.Since(start)

	if err != nil {
		result.ConnectError = err.Error()
		result.Checks = append(result.Checks, CheckItem{
			Name:   "connectivity",
			Status: "fail",
			Detail: err.Error(),
		})
		return result
	}
	if exitCode != 0 {
		result.ConnectError = fmt.Sprintf("exit code %d", exitCode)
		result.Checks = append(result.Checks, CheckItem{
			Name:   "connectivity",
			Status: "fail",
			Detail: fmt.Sprintf("exit code %d", exitCode),
		})
		return result
	}

	result.Connected = true
	result.Checks = append(result.Checks, CheckItem{
		Name:   "connectivity",
		Status: "pass",
		Detail: fmt.Sprintf("latency %dms", result.Latency.Milliseconds()),
	})

	// Check 2: cipdip installed - try PATH first, then common locations
	cipdipPaths := []string{
		"cipdip",
		"/usr/local/bin/cipdip",
		"/opt/homebrew/bin/cipdip",
		"/usr/bin/cipdip",
		"$HOME/go/bin/cipdip",
	}
	var cipdipFound bool
	var cipdipVersion string
	for _, cipdipPath := range cipdipPaths {
		exitCode, stdout, _, err := t.Exec(ctx, []string{"sh", "-c", cipdipPath + " version"}, nil, "")
		if err == nil && exitCode == 0 {
			cipdipFound = true
			cipdipVersion = parseVersionOutput(stdout)
			break
		}
	}
	if !cipdipFound {
		result.Checks = append(result.Checks, CheckItem{
			Name:   "cipdip_installed",
			Status: "fail",
			Detail: "cipdip not found in PATH or common locations",
		})
	} else {
		result.CipdipFound = true
		result.Version = cipdipVersion
		result.Checks = append(result.Checks, CheckItem{
			Name:   "cipdip_installed",
			Status: "pass",
			Detail: result.Version,
		})
	}

	// Check 3: Get OS/Arch
	var stdout string
	exitCode, stdout, _, _ = t.Exec(ctx, []string{"uname", "-s"}, nil, "")
	if exitCode == 0 {
		result.RemoteOS = trimOutput(stdout)
	}
	exitCode, stdout, _, _ = t.Exec(ctx, []string{"uname", "-m"}, nil, "")
	if exitCode == 0 {
		result.RemoteArch = trimOutput(stdout)
	}

	if result.RemoteOS != "" {
		result.Checks = append(result.Checks, CheckItem{
			Name:   "system_info",
			Status: "pass",
			Detail: fmt.Sprintf("%s/%s", result.RemoteOS, result.RemoteArch),
		})
	}

	// Check 4: Workdir writable
	exitCode, _, _, _ = t.Exec(ctx, []string{"sh", "-c", "mkdir -p /tmp/cipdip-test && rm -rf /tmp/cipdip-test"}, nil, "")
	if exitCode == 0 {
		result.Checks = append(result.Checks, CheckItem{
			Name:   "workdir_writable",
			Status: "pass",
			Detail: "/tmp writable",
		})
	} else {
		result.Checks = append(result.Checks, CheckItem{
			Name:   "workdir_writable",
			Status: "fail",
			Detail: "cannot write to /tmp",
		})
	}

	// Check 5: tcpdump available
	exitCode, _, _, _ = t.Exec(ctx, []string{"which", "tcpdump"}, nil, "")
	if exitCode == 0 {
		result.Checks = append(result.Checks, CheckItem{
			Name:   "pcap_capable",
			Status: "pass",
			Detail: "tcpdump available",
		})
	} else {
		// Try tshark
		exitCode, _, _, _ = t.Exec(ctx, []string{"which", "tshark"}, nil, "")
		if exitCode == 0 {
			result.Checks = append(result.Checks, CheckItem{
				Name:   "pcap_capable",
				Status: "pass",
				Detail: "tshark available",
			})
		} else {
			result.Checks = append(result.Checks, CheckItem{
				Name:   "pcap_capable",
				Status: "fail",
				Detail: "no packet capture tool found",
			})
		}
	}

	// Determine overall status
	result.OK = result.Connected && result.CipdipFound
	for _, check := range result.Checks {
		if check.Status == "fail" && check.Name != "pcap_capable" {
			// pcap is optional for some roles
			if check.Name == "cipdip_installed" || check.Name == "connectivity" {
				result.OK = false
			}
		}
	}

	return result
}

func parseVersionOutput(output string) string {
	// Parse "cipdip version X.Y.Z" or just return trimmed output
	output = trimOutput(output)
	if len(output) > 50 {
		return output[:50] + "..."
	}
	return output
}

func trimOutput(s string) string {
	// Remove trailing newlines and whitespace
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}

func printAgentStatus(status *AgentStatus) {
	fmt.Println("Agent Status")
	fmt.Println("============")
	fmt.Println()

	fmt.Printf("Version:    %s\n", status.Version)
	fmt.Printf("Git Commit: %s\n", status.GitCommit)
	fmt.Printf("OS/Arch:    %s/%s\n", status.OS, status.Arch)
	fmt.Printf("Hostname:   %s\n", status.Hostname)
	fmt.Println()

	fmt.Println("Working Directory:")
	fmt.Printf("  Path:     %s\n", status.Workdir.Path)
	if status.Workdir.Error != "" {
		fmt.Printf("  Status:   FAIL (%s)\n", status.Workdir.Error)
	} else if status.Workdir.Writable {
		fmt.Printf("  Status:   OK (writable)\n")
	} else {
		fmt.Printf("  Status:   EXISTS (not writable)\n")
	}
	fmt.Println()

	fmt.Println("Network Interfaces:")
	if len(status.Interfaces) == 0 {
		fmt.Println("  (none found)")
	} else {
		for _, iface := range status.Interfaces {
			bindStatus := "can bind"
			if !iface.CanBind {
				bindStatus = "cannot bind"
			}
			for _, addr := range iface.Addresses {
				fmt.Printf("  %s: %s [%s]\n", iface.Name, addr, bindStatus)
			}
		}
	}
	fmt.Println()

	fmt.Println("Packet Capture:")
	if status.PcapCapable {
		fmt.Printf("  Status:   OK (%s)\n", status.PcapMethod)
	} else {
		fmt.Printf("  Status:   NOT AVAILABLE\n")
	}
	fmt.Println()

	fmt.Printf("Supported Roles: %v\n", status.SupportedRoles)
}

func printCheckResult(result *CheckResult) {
	fmt.Printf("Agent Check: %s\n", result.Transport)
	fmt.Println("==================")
	fmt.Println()

	for _, check := range result.Checks {
		status := "PASS"
		if check.Status == "fail" {
			status = "FAIL"
		} else if check.Status == "skip" {
			status = "SKIP"
		}
		fmt.Printf("  [%s] %s", status, check.Name)
		if check.Detail != "" {
			fmt.Printf(": %s", check.Detail)
		}
		fmt.Println()
	}

	fmt.Println()
	if result.OK {
		fmt.Println("Result: READY")
	} else {
		fmt.Println("Result: NOT READY")
	}
}
