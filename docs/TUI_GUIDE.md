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
- **Scenario**: Test scenario to run

**Scenarios:**
| Scenario | Description |
|----------|-------------|
| baseline | Read-only polling of configured targets |
| mixed | Alternating reads and writes |
| stress | High-frequency burst traffic |
| io | Connected I/O with Forward Open |
| edge | Protocol edge cases for DPI testing |

**Keys:**
- `Tab` - Move between fields
- `Enter` - Start the run
- `e` - Edit configuration file
- `y` - Copy command to clipboard
- `x` - Stop running client

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

**Personalities:**
| Personality | Description |
|-------------|-------------|
| adapter | Assembly-based (like CLICK PLCs) |
| logix_like | Tag-based (like Allen-Bradley Logix) |

**Keys:**
- `Tab` - Move between fields
- `Enter` - Start server
- `e` - Edit configuration
- `y` - Copy command to clipboard
- `x` - Stop server

**Running State:**
While running, the screen shows:
- Uptime
- Active connections
- Recent requests
- Request statistics

### PCAP Screen

Analyze and replay PCAP files containing CIP traffic.

**Actions:**
| Action | Description |
|--------|-------------|
| summary | Quick stats about the capture |
| report | Detailed analysis report |
| coverage | CIP service coverage analysis |
| replay | Replay packets to a target |
| rewrite | Modify and save packets |
| dump | Hex dump of specific packets |

**Keys:**
- `b` - Browse for PCAP file
- `1-6` - Select action
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
