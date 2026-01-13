# Windows Remote Agent Setup

This guide explains how to set up a Windows machine as a remote agent for cipdip orchestration.

## Prerequisites

- Windows 10/11 or Windows Server 2019+
- Administrator access
- Network connectivity to the controller machine

## Step 1: Install OpenSSH Server

Open PowerShell **as Administrator**:

```powershell
# Install OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start the service
Start-Service sshd

# Set to auto-start on boot
Set-Service -Name sshd -StartupType Automatic

# Verify it's running
Get-Service sshd
```

## Step 2: Configure SSH Key Authentication for Admin Users

For PCAP capture, you must run as an administrator. Admin users require a different authorized_keys location.

```powershell
# Create the authorized_keys file for administrators
New-Item -Path "C:\ProgramData\ssh\administrators_authorized_keys" -ItemType File -Force

# Add your public key (copy from controller's ~/.ssh/id_ed25519.pub or ~/.ssh/id_rsa.pub)
Add-Content -Path "C:\ProgramData\ssh\administrators_authorized_keys" -Value "ssh-ed25519 AAAA... your-public-key-here"

# Fix permissions (CRITICAL - SSH ignores the file without correct permissions)
icacls "C:\ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "SYSTEM:F" /grant "Administrators:F"

# Restart SSH service
Restart-Service sshd
```

### Finding Your Public Key

On your controller machine (Linux/macOS), view your public key:

```bash
cat ~/.ssh/id_ed25519.pub
# or
cat ~/.ssh/id_rsa.pub
```

Copy the entire output line (starts with `ssh-ed25519` or `ssh-rsa`) to use in the `Add-Content` command above.

## Step 3: Configure Windows Firewall

If SSH connections are blocked, add a firewall rule:

```powershell
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

## Step 4: Install npcap for PCAP Capture

1. Download npcap from https://npcap.com/
2. Run the installer with these options:
   - ✅ Install Npcap in WinPcap API-compatible Mode
   - ✅ Support raw 802.11 traffic (optional)

## Step 5: Build and Install cipdip

Run PowerShell **as Administrator**:

```powershell
# Navigate to cipdip source directory
cd C:\path\to\cipdip

# Build the binary
go build ./cmd/cipdip

# Install to system PATH (requires Administrator)
.\cipdip install --force
```

The `cipdip install` command will:
1. Copy the binary to `C:\Windows\System32` (always in system PATH)
2. Set up shell completion

This ensures cipdip is available in SSH sessions, which use the system PATH rather than user PATH.

**Alternative: Manual Go install** (not recommended for remote agents):
```powershell
go install ./cmd/cipdip
```
Note: `go install` puts the binary in `%USERPROFILE%\go\bin`, which is NOT in the system PATH and won't work for SSH sessions.

## Step 6: Test the Setup

From your controller machine:

```bash
# Test SSH connectivity
ssh user@windows-ip "whoami"

# Verify admin privileges
ssh user@windows-ip "whoami /groups | findstr Administrators"

# Test cipdip and PCAP capability
ssh user@windows-ip "cipdip agent status"
```

The `cipdip agent status` output should show:
```
PCAP Capable: true
```

## Step 7: Add Agent in cipdip

### Option A: Using the TUI

1. Run `cipdip` to open the TUI
2. Go to **Orchestration** panel
3. Press **Tab** to switch to **Agents** view
4. Press **a** to add new agent
5. Enter name, user, host, and port
6. Set **OS** to `windows` using ←/→ arrows
7. Set **Elevate** to `Yes` (for PCAP capture)
8. Press **Enter** to save
9. Press **c** to check connectivity

The agent status should show:
- `windows/amd64` - Confirms Windows detected
- `PCAP: Yes` - npcap is available
- `Elevate: Yes (admin)` - Administrator privileges confirmed

### Option B: Using SSH Setup Wizard

1. Press **s** for SSH Setup wizard
2. Follow the guided steps to configure SSH key authentication
3. Set **OS** to `windows` and **Elevate** to `Yes`

### Option C: Manual Transport URL

The transport URL format for Windows:

```
ssh://user@windows-ip?os=windows&elevate=true&key=/path/to/key&agent=false
```

Parameters:
- `os=windows` - Required for Windows path handling
- `elevate=true` - Enables admin privilege checks
- `key=/path/to/key` - SSH private key path
- `agent=false` - Disable SSH agent (recommended for Windows)

## Troubleshooting

### Permission Denied

Ensure your public key is in the correct file:
- **Admin users**: `C:\ProgramData\ssh\administrators_authorized_keys`
- **Regular users**: `C:\Users\<username>\.ssh\authorized_keys`

Verify permissions:
```powershell
icacls "C:\ProgramData\ssh\administrators_authorized_keys"
```

### cipdip Not Found

Add Go bin to PATH:
```powershell
$env:PATH += ";$env:USERPROFILE\go\bin"
```

### PCAP Not Working

- Verify npcap is installed: Check "Apps & features" for "Npcap"
- Run `cipdip agent status` locally on Windows to check PCAP capability
- Ensure you're connecting as an administrator

### SSH Agent Not Working

Windows OpenSSH uses named pipes for the SSH agent, which isn't fully supported. Use explicit key file authentication instead:

```
ssh://user@host?key=C:/Users/name/.ssh/id_ed25519&agent=false
```

### Elevate Shows "No"

The elevation check runs `net session` remotely. If it shows "No":

1. Ensure you're logged in as an Administrator user
2. Verify your user is in the Administrators group:
   ```powershell
   whoami /groups | findstr Administrators
   ```
3. Check that the SSH session has admin privileges:
   ```bash
   ssh user@windows-ip "whoami /groups | findstr Administrators"
   ```

If the user isn't an administrator, add them:
```powershell
# Run as Administrator
Add-LocalGroupMember -Group "Administrators" -Member "username"
```

## Architecture Notes

When using Windows as a remote agent:

- **Work directory**: `C:\Windows\Temp\cipdip-{role}`
- **PCAP files**: Written to work directory, then transferred via SFTP
- **Path handling**: SFTP uses forward slashes regardless of OS

The `?os=windows` parameter tells the orchestrator to:
1. Use Windows-compatible paths for the work directory
2. Handle any OS-specific command differences
