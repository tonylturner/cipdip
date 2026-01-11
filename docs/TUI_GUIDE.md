# CIPDIP Interactive TUI Guide

The CIPDIP TUI provides an interactive terminal interface for running client scenarios, managing server emulators, analyzing PCAP files, and browsing the CIP catalog.

## Quick Start

```bash
# Start the interactive TUI
cipdip ui --tui

# Or with a specific workspace
cipdip ui --workspace workspaces/myproject --tui
```

## Navigation

The TUI uses a flat navigation model with single-key access to all screens:

| Key | Screen | Description |
|-----|--------|-------------|
| `c` | Client | Configure and run CIP client scenarios |
| `s` | Server | Start and monitor server emulator |
| `p` | PCAP | PCAP analysis and replay tools |
| `k` | Catalog | Browse CIP classes and services |
| `r` | Runs | View past run history and artifacts |
| `m` | Menu | Return to main menu |
| `?` | Help | Show context-sensitive help |
| `q` | Quit | Exit the TUI |

## Screens

### Main Menu

The main menu shows:
- Quick actions for each screen
- Recent run activity with status indicators
- Server status (if running)

Navigate using arrow keys or press the shortcut key directly.

### Client Screen

Configure and execute CIP client scenarios against a target device.

**Fields:**
- **Target IP**: IP address of the CIP device
- **Port**: TCP port (default: 44818)
- **Scenario**: Test scenario to run (14 scenarios in 4 groups)
- **Mode**: Duration preset (Quick/Standard/Extended/Custom)

**Scenarios:**

| Group | Scenario | Description |
|-------|----------|-------------|
| **Basic** | baseline | Read-only polling of configured targets |
| | mixed | Alternating reads and writes |
| | stress | High-frequency burst traffic |
| | io | Connected I/O with Forward Open |
| | churn | Connection setup/teardown cycles |
| **Edge Cases** | edge | Protocol edge cases for DPI testing |
| | edge_valid | Protocol-valid edge cases |
| | edge_vendor | Vendor-specific edge cases |
| **Vendor Variants** | rockwell | Rockwell edge pack |
| | vendor_variants | Protocol variant testing |
| | mixed_state | UCMM + I/O interleaving |
| | unconnected_send | UCMM wrapper tests |
| **Firewall DPI** | firewall | Firewall DPI test pack (select vendor) |

When **firewall** scenario is selected, a vendor selector appears:
- All (firewall_pack), Hirschmann, Moxa, Dynics

**Mode Presets:**

| Mode | Duration | Interval |
|------|----------|----------|
| Quick | 30s | 250ms |
| Standard | 5min | 250ms |
| Extended | 30min | 250ms |
| Custom | User-defined | User-defined |

**Advanced Options** (press `a` to toggle):
- **Duration/Interval**: Editable when Custom mode selected
- **CIP Profiles**: [energy] [safety] [motion] - filter by application vertical
- **Protocol**: strict_odva, rockwell_enbt, schneider_m580, siemens_s7_1200
- **PCAP Capture**: Enable packet capture with filename
- **Metrics File**: Export latency/jitter data to CSV

**Keys:**
- `Tab` - Move between fields
- `←→` or `Space` - Change selection
- `a` - Toggle advanced options
- `Enter` - Start the run
- `e` - Edit configuration file
- `y` - Copy command to clipboard
- `x` - Stop running client
- `1/2/3` - Toggle individual CIP profiles (when focused)

**Running State:**
While running, the screen shows:
- Elapsed time
- Request count
- Success/error rates
- Average latency
- Recent errors

### Server Screen

Start and monitor the CIP server emulator.

**Fields:**
- **Listen IP**: Interface to bind (default: 0.0.0.0)
- **Port**: TCP port (default: 44818)
- **Personality**: Server behavior profile
- **Mode**: Server behavior mode

**Personalities:**

| Personality | Description |
|-------------|-------------|
| adapter | Assembly-based (like CLICK PLCs) |
| logix_like | Tag-based (like Allen-Bradley Logix) |

**Modes:**

| Mode | Description |
|------|-------------|
| baseline | Standard compliant responses |
| realistic | Realistic timing and behavior |
| dpi-torture | Edge cases to stress DPI engines |
| perf | High-performance mode for load testing |

**Advanced Options** (press `a` to toggle):
- **CIP Profiles**: [energy] [safety] [motion] - filter by application vertical
- **UDP I/O**: Enable UDP I/O on port 2222
- **PCAP Capture**: Enable packet capture with filename

**Keys:**
- `Tab` - Move between fields
- `←→` or `Space` - Change selection
- `a` - Toggle advanced options
- `Enter` - Start server
- `e` - Edit configuration
- `y` - Copy command to clipboard
- `x` - Stop server
- `1/2/3` - Toggle individual CIP profiles (when focused)

**Running State:**
While running, the screen shows:
- Uptime
- Active connections
- Recent requests
- Request statistics

### PCAP Screen

Analyze and replay PCAP files containing CIP traffic.

**Actions:**

| # | Action | Description |
|---|--------|-------------|
| 1 | Summary | Quick stats about the capture |
| 2 | Report | Detailed analysis report |
| 3 | Coverage | CIP service coverage analysis |
| 4 | Replay | Replay packets to a target |
| 5 | Rewrite | Modify and save packets |
| 6 | Dump | Hex dump of specific packets |
| 7 | Diff | Compare two PCAPs for service/timing differences |

**Diff Action:**
Compare baseline and compare PCAPs to identify:
- Added/removed CIP service codes
- Added/removed object classes
- Latency differences (request/response timing)
- RPI jitter analysis for I/O traffic

Options:
- **Baseline**: First PCAP file
- **Compare**: Second PCAP file to compare
- **Expected RPI**: Expected RPI in milliseconds (default: 20)
- **Skip Timing**: Skip latency analysis
- **Skip RPI**: Skip RPI jitter analysis

**Keys:**
- `b` - Browse for PCAP file
- `1-7` - Select action
- `Enter` - Run selected action
- `y` - Copy command to clipboard

**File Browser:**
- Navigate with arrow keys
- `Enter` to select file or enter directory
- `h` or left arrow to go to parent directory
- Only shows .pcap and .pcapng files

### Catalog Screen

Browse the CIP catalog of classes, services, and attributes.

**Features:**
- Filter entries by typing
- Expand entries to see details
- Probe devices directly from catalog entries

**Keys:**
- `/` - Start filtering
- `Enter` - Expand entry or open probe dialog
- `y` - Copy class path to clipboard
- `Esc` - Clear filter or go back

**Probe Dialog:**
Enter a target IP to probe the selected CIP object:
- `Tab` - Switch between IP and Port fields
- `Enter` - Execute probe
- `y` - Copy probe command

### Runs Screen

View and manage past run artifacts.

**Filter Types:**
- all - Show all runs
- client - Client scenario runs only
- server - Server emulator runs only
- pcap - PCAP analysis runs only

**Keys:**
- `Tab` - Cycle filter type
- `Enter` - View run details
- `d` - Delete run (with confirmation)

**Detail View:**
- `o` - Open artifact in $EDITOR
- `r` - Re-run the command
- `y` - Copy command to clipboard
- `Esc` - Return to list

**Artifacts:**
Each run saves:
- `command.txt` - The executed command
- `stdout.log` - Command output
- `resolved.yaml` - Resolved configuration
- `summary.json` - Run metadata and status

## Workspaces

The TUI operates within workspaces that organize:
- Profiles (saved configurations)
- Runs (execution artifacts)
- Plans (multi-step test sequences)
- PCAP files

```bash
# Create a new workspace
cipdip ui --new-workspace workspaces/newproject

# Use existing workspace
cipdip ui --workspace workspaces/myproject --tui
```

## Command Preview

All configuration screens show a live command preview at the bottom. This shows exactly what CLI command will be executed. Press `y` to copy it to the clipboard.

## Tips

1. **Quick Navigation**: Press `m` from any screen to return to the main menu
2. **Help Anywhere**: Press `?` on any screen for context-sensitive help
3. **Copy Commands**: Use `y` to copy commands for scripting or documentation
4. **Re-run History**: Use the Runs screen to quickly re-execute past commands
5. **Keyboard Efficiency**: Use single-key navigation (c/s/p/k/r) instead of menus

## Non-Interactive Mode

For scripting, use the CLI flags instead of the TUI:

```bash
# Show home screen preview
cipdip ui --home

# Show catalog entries
cipdip ui --catalog --catalog-query "identity"

# Generate and run a profile
cipdip ui --wizard baseline --wizard-target 10.0.0.50

# Print command without executing
cipdip ui --wizard single --wizard-ip 10.0.0.50 --print-command
```

## See Also

- `docs/EXAMPLES.md` - CLI usage examples
- `docs/CONFIGURATION.md` - Configuration file reference
- `docs/PCAP_USAGE.md` - PCAP analysis details
