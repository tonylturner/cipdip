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

```powershell
# Navigate to cipdip source directory
cd C:\path\to\cipdip

# Build and install to Go bin directory
go install ./cmd/cipdip

# Verify installation
cipdip --version
```

Ensure the Go bin directory is in your PATH. Default location is `%USERPROFILE%\go\bin`.

To add permanently:
1. Open System Properties → Advanced → Environment Variables
2. Edit `Path` under User variables
3. Add `%USERPROFILE%\go\bin`

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
5. Enter name, user, and host
6. Press **Enter** to save
7. Press **c** to check connectivity

The agent should show `windows/amd64` after checking, confirming Windows was detected.

### Option B: Manual Manifest Configuration

Add `?os=windows` to the agent transport string:

```yaml
roles:
  client:
    agent: "ssh://user@windows-ip?os=windows&key=/path/to/key&agent=false"
    scenario: baseline
```

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

```yaml
agent: "ssh://user@host?key=C:/Users/name/.ssh/id_ed25519&agent=false"
```

## Architecture Notes

When using Windows as a remote agent:

- **Work directory**: `C:\Windows\Temp\cipdip-{role}`
- **PCAP files**: Written to work directory, then transferred via SFTP
- **Path handling**: SFTP uses forward slashes regardless of OS

The `?os=windows` parameter tells the orchestrator to:
1. Use Windows-compatible paths for the work directory
2. Handle any OS-specific command differences
