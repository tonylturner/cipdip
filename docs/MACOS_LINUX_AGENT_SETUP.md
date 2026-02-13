# macOS/Linux Remote Agent Setup

This guide explains how to set up a macOS or Linux machine as a remote agent for cipdip orchestration.

## Prerequisites

- macOS 10.15+ or Linux (Ubuntu 20.04+, RHEL 8+, etc.)
- SSH server enabled
- Network connectivity to the controller machine

## Step 1: Enable SSH Server

### macOS

1. Open **System Preferences** → **Sharing** (or **System Settings** → **General** → **Sharing** on macOS 13+)
2. Enable **Remote Login**
3. Select which users can access (All users or specific users)

### Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh
```

### Linux (RHEL/CentOS/Fedora)

```bash
sudo dnf install openssh-server
sudo systemctl enable sshd
sudo systemctl start sshd
```

## Step 2: Configure SSH Key Authentication

On the **controller** machine, copy your public key to the agent:

```bash
# If you don't have an SSH key, generate one
ssh-keygen -t ed25519 -C "cipdip@$(hostname)"

# Copy to the remote agent
ssh-copy-id user@agent-ip
```

Test the connection:

```bash
ssh user@agent-ip "echo OK"
```

## Step 3: Configure Passwordless Sudo

PCAP capture and some operations require elevated privileges. Configure passwordless sudo for your user.

### Option A: Full sudo access (less secure)

```bash
sudo visudo
```

Add at the end of the file:

```
username ALL=(ALL) NOPASSWD: ALL
```

Replace `username` with your actual username.

### Option B: Create a sudoers drop-in file (recommended)

```bash
sudo visudo -f /etc/sudoers.d/cipdip
```

Add:

```
username ALL=(ALL) NOPASSWD: ALL
```

### Option C: Restrict to cipdip only (most secure)

```bash
sudo visudo -f /etc/sudoers.d/cipdip
```

Add (adjust path as needed):

```
username ALL=(ALL) NOPASSWD: /usr/local/bin/cipdip, /home/username/go/bin/cipdip
```

### Verify sudo works without password

```bash
sudo -n true && echo "Passwordless sudo OK" || echo "Sudo requires password"
```

## Step 4: Install PCAP Dependencies

### macOS

Install Wireshark (includes tshark and provides BPF access):

```bash
brew install --cask wireshark
```

Or just install tcpdump permissions:

```bash
# Check BPF device permissions
ls -la /dev/bpf*

# If needed, add user to access_bpf group (created by Wireshark installer)
sudo dseditgroup -o edit -a $(whoami) -t user access_bpf
```

### Linux

```bash
# Ubuntu/Debian
sudo apt install tcpdump tshark

# RHEL/CentOS/Fedora
sudo dnf install tcpdump wireshark-cli

# Grant capture capability to tcpdump (alternative to running as root)
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)
```

## Step 5: Build and Install cipdip

```bash
# Navigate to cipdip source directory
cd /path/to/cipdip

# Build
go build ./cmd/cipdip

# Install (copies to PATH and sets up completion)
./cipdip install

# Or install to Go bin
go install ./cmd/cipdip

# Verify
cipdip --version
cipdip agent status
```

Ensure cipdip is in your PATH. Common locations:
- `/usr/local/bin/cipdip`
- `~/go/bin/cipdip`
- `~/.local/bin/cipdip`

## Step 6: Verify Agent Capabilities

Run locally on the agent machine:

```bash
cipdip agent status
```

Expected output:

```
Agent Status
============

Version:    0.2.2
OS/Arch:    darwin/arm64
Hostname:   macbook

Working Directory:
  Path:     /tmp/cipdip
  Status:   OK (writable)

Network Interfaces:
  en0: 192.168.1.100 [can bind]
  lo0: 127.0.0.1 [can bind]

Packet Capture:
  Status:   OK (tcpdump)

Supported Roles: [server client]
```

## Step 7: Add Agent in cipdip

### Option A: Using the TUI

1. Run `cipdip` to open the TUI
2. Go to **Orchestration** panel
3. Press **Tab** to switch to **Agents** view
4. Press **a** to add new agent
5. Enter name, user, host, and port
6. Set **OS** to `linux` or `darwin` using ←/→ arrows
7. Set **Elevate** to `Yes` (for PCAP capture with sudo)
8. Press **Enter** to save
9. Press **c** to check connectivity

The agent status should show:
- `darwin/arm64` or `linux/amd64` - OS detected
- `PCAP: Yes` - Packet capture available
- `Elevate: Yes (sudo)` - Passwordless sudo confirmed

### Option B: Using SSH Setup Wizard

1. Press **s** for SSH Setup wizard
2. Follow the guided steps to configure SSH key authentication
3. Set **OS** appropriately and **Elevate** to `Yes`

### Option C: Manual Transport URL

```
ssh://user@host?os=darwin&elevate=true&key=~/.ssh/id_ed25519
```

Parameters:
- `os=linux` or `os=darwin` - Remote OS (default: linux)
- `elevate=true` - Enable sudo for elevated commands
- `key=/path/to/key` - SSH private key path (optional)

## Step 8: Test from Controller

```bash
# Test SSH connectivity
ssh user@agent-ip "whoami"

# Test cipdip
ssh user@agent-ip "cipdip agent status"

# Test sudo (should work without password prompt)
ssh user@agent-ip "sudo whoami"
```

## Troubleshooting

### "cipdip: command not found" via SSH

SSH sessions may not load your full shell profile. Ensure cipdip is in a standard PATH location:

```bash
# Option 1: Install to /usr/local/bin
sudo cp cipdip /usr/local/bin/

# Option 2: Add to PATH in ~/.bashrc or ~/.zshrc
export PATH="$HOME/go/bin:$PATH"
```

### "sudo: a password is required"

Passwordless sudo is not configured correctly. Verify:

```bash
# Check sudoers syntax
sudo visudo -c

# Test locally
sudo -n true
```

### PCAP shows "NOT AVAILABLE"

Check that tcpdump or tshark is installed and accessible:

```bash
which tcpdump
which tshark
```

On macOS, you may need BPF device access:

```bash
# Check BPF permissions
ls -la /dev/bpf0

# If Wireshark is installed, add to access_bpf group
sudo dseditgroup -o edit -a $(whoami) -t user access_bpf
# Then log out and back in
```

### Elevate shows "No"

The elevation check runs `sudo -n true` remotely. If it fails:

1. Verify passwordless sudo works locally on the agent
2. Check that the SSH user has sudoers access
3. Ensure `/etc/sudoers.d/` files have correct permissions (0440)

```bash
# Fix sudoers file permissions
sudo chmod 0440 /etc/sudoers.d/cipdip
```

## Security Considerations

- **Passwordless sudo** grants significant privileges. Consider restricting to specific commands if possible.
- **SSH keys** should be protected with appropriate file permissions (0600 for private keys).
- **Firewall rules** may be needed to allow SSH (port 22) between controller and agents.
- **Network segmentation** is recommended for production environments.
