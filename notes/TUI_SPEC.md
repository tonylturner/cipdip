# CIPDIP TUI Specification

Version: 3.0
Status: Design specification

---

## 1. Design Philosophy

**The TUI exists to reduce friction, not to impress.**

A protocol test harness serves experts who need speed and clarity. The TUI should feel like a well-organized toolbox, not an IDE.

### Principles

1. **Visible options over hidden discovery** - Users shouldn't search for features; features should be visible and organized
2. **One thing at a time** - Each screen has a single purpose with a clear exit
3. **Show the CLI** - Always display the equivalent command so users learn the CLI naturally
4. **Fail fast, fail loud** - Validation errors appear immediately, not after a wizard sequence
5. **Keyboard-native** - Every action has a single-key shortcut; mouse is optional

### Anti-patterns to avoid

- Command palettes as primary navigation (good for 500+ commands, overkill for 20)
- Multi-step wizards that hide what's happening
- Abstract "workspace" concepts that add ceremony without value
- Clever terminology that obscures simple operations

---

## 2. Screen Architecture

The TUI has five screens. Each screen is reachable in one or two keystrokes from any other.

```
                    ┌─────────────┐
                    │   MAIN      │
                    │   MENU      │
                    └──────┬──────┘
                           │
       ┌───────────┬───────┼───────┬───────────┐
       │           │       │       │           │
       v           v       v       v           v
┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│  CLIENT  │ │  SERVER  │ │   PCAP   │ │ CATALOG  │ │   RUNS   │
│  CONFIG  │ │  CONFIG  │ │  TOOLS   │ │ BROWSER  │ │  HISTORY │
└──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘
```

**Navigation is flat, not nested.** Press `m` from any screen to return to main menu.

---

## 3. Global Keys

These work on every screen:

| Key | Action |
|-----|--------|
| `q` | Quit (with confirmation if run is active) |
| `m` | Main menu |
| `?` | Help overlay for current screen |
| `Esc` | Cancel current action / close overlay |

The footer of every screen shows available keys for that context.

---

## 4. Main Menu

The entry point. Shows system status and primary actions.

```
┌─────────────────────────────────────────────────────────────┐
│  CIPDIP                                                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  [c] Client         Configure and run client scenarios      │
│  [s] Server         Start server emulator                   │
│  [p] PCAP           Analyze, replay, or rewrite captures    │
│  [k] Catalog        Browse CIP classes and services         │
│  [r] Runs           View past run results                   │
│                                                             │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│  Recent:                                                    │
│    10:41  client baseline  192.168.1.50  ✓ 847 ok / 0 err   │
│    10:38  server adapter   :44818        running...         │
│    10:22  pcap-summary     ENIP.pcap     ✓ 12,847 packets   │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  c/s/p/k/r: select    q: quit    ?: help                    │
└─────────────────────────────────────────────────────────────┘
```

### Behavior

- Recent runs show the last 5 operations with status
- A running server shows "running..." with uptime
- Arrow keys can select a recent run to view details
- Pressing the key for an already-running operation focuses that screen

---

## 5. Client Screen

Configure targets and run scenarios against a remote device.

### 5.1 Initial State (No Config)

```
┌─────────────────────────────────────────────────────────────┐
│  CLIENT                                                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Target IP: _____________    Port: 44818                    │
│                                                             │
│  Scenario:                                                  │
│    (•) baseline     Read-only polling of configured targets │
│    ( ) mixed        Alternating reads and writes            │
│    ( ) stress       High-frequency burst traffic            │
│    ( ) io           Connected I/O with Forward Open         │
│    ( ) edge         Protocol edge cases for DPI testing     │
│                                                             │
│  Config: [none - using defaults]                    [e]dit  │
│                                                             │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│  Command preview:                                           │
│  cipdip client --ip ??? --scenario baseline                 │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  Tab: next field    Enter: run    e: edit config    m: menu │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 With Config Loaded

```
┌─────────────────────────────────────────────────────────────┐
│  CLIENT                                            [config] │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Target IP: 192.168.1.50       Port: 44818                  │
│                                                             │
│  Scenario: baseline                                         │
│                                                             │
│  Targets from config:                                       │
│    read   InputBlock1     0x04/0x65/0x03                    │
│    read   InputBlock2     0x04/0x66/0x03                    │
│    write  OutputBlock1    0x04/0x67/0x03  pattern=increment │
│                                                             │
│  Protocol: strict_odva                                      │
│                                                             │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│  Command preview:                                           │
│  cipdip client --ip 192.168.1.50 --scenario baseline \      │
│    --config cipdip_client.yaml                              │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  Enter: run    e: edit config    y: copy command    m: menu │
└─────────────────────────────────────────────────────────────┘
```

### 5.3 Running State

```
┌─────────────────────────────────────────────────────────────┐
│  CLIENT                                          [RUNNING]  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Target: 192.168.1.50:44818    Scenario: baseline           │
│  Elapsed: 00:01:23             Requests: 4,231              │
│                                                             │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                             │
│  Statistics:                                                │
│    Success:     4,229  (99.95%)                             │
│    Errors:          2  (0.05%)                              │
│    Latency:     12.3ms avg   8.1ms p50   41.2ms p99         │
│                                                             │
│  Last response:                                             │
│    InputBlock1: 0x04/0x65/0x03 → 00 00 00 1A 00 00 00 00    │
│                                                             │
│  Errors:                                                    │
│    10:42:17  InputBlock2  timeout (no response in 5000ms)   │
│    10:42:31  InputBlock2  timeout (no response in 5000ms)   │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  x: stop    Space: pause/resume    l: show full log         │
└─────────────────────────────────────────────────────────────┘
```

### Keys (Client Screen)

| Key | Context | Action |
|-----|---------|--------|
| `Tab` | Editing | Next field |
| `Shift+Tab` | Editing | Previous field |
| `Enter` | Ready | Start run |
| `e` | Any | Open config in `$EDITOR` |
| `y` | Ready | Copy command to clipboard |
| `x` | Running | Stop run |
| `Space` | Running | Pause/resume |
| `l` | Running | Toggle full log view |

---

## 6. Server Screen

Start and monitor the CIP emulator.

```
┌─────────────────────────────────────────────────────────────┐
│  SERVER                                                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Listen IP: 0.0.0.0            TCP Port: 44818              │
│                                                             │
│  Personality:                                               │
│    (•) adapter      Assembly-based (like CLICK PLCs)        │
│    ( ) logix_like   Tag-based (like Allen-Bradley Logix)    │
│                                                             │
│  Config: [none - using defaults]                    [e]dit  │
│                                                             │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│  Command preview:                                           │
│  cipdip server --personality adapter --listen-ip 0.0.0.0    │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  Enter: start    e: edit config    y: copy command          │
└─────────────────────────────────────────────────────────────┘
```

### Running State

```
┌─────────────────────────────────────────────────────────────┐
│  SERVER                                          [RUNNING]  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Listening: 0.0.0.0:44818      Personality: adapter         │
│  Uptime: 00:14:32              Connections: 2 active        │
│                                                             │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                             │
│  Active connections:                                        │
│    192.168.1.100:52341  session=0x00000001  idle 2.3s       │
│    192.168.1.101:49822  session=0x00000002  idle 0.1s       │
│                                                             │
│  Recent requests:                                           │
│    10:45:01  192.168.1.101  Get_Attribute_Single 0x01/1/1   │
│    10:45:01  192.168.1.101  Get_Attribute_Single 0x04/65/3  │
│    10:45:00  192.168.1.100  List_Identity                   │
│    10:44:59  192.168.1.101  Register_Session                │
│                                                             │
│  Statistics:                                                │
│    Total requests: 1,247    Errors: 0                       │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  x: stop    l: full log    f: filter by IP                  │
└─────────────────────────────────────────────────────────────┘
```

---

## 7. PCAP Screen

Tools for capture analysis and replay.

```
┌─────────────────────────────────────────────────────────────┐
│  PCAP TOOLS                                                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  File: [select or drag file]                       [b]rowse │
│                                                             │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│  Actions (select file first):                               │
│                                                             │
│    [1] Summary       Packet counts, endpoints, timing       │
│    [2] Report        Detailed CIP request/response analysis │
│    [3] Coverage      Which CIP classes/services are present │
│    [4] Replay        Send packets to a target device        │
│    [5] Rewrite       Modify IPs/MACs and save new capture   │
│    [6] Dump          Hex dump of specific packets           │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  b: browse files    1-6: select action    m: menu           │
└─────────────────────────────────────────────────────────────┘
```

### After Selecting File + Action

Example: Summary selected

```
┌─────────────────────────────────────────────────────────────┐
│  PCAP > Summary                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  File: pcaps/stress/ENIP.pcap                               │
│  Size: 45.5 MB    Packets: 12,847                           │
│                                                             │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│  Command preview:                                           │
│  cipdip pcap-summary --input pcaps/stress/ENIP.pcap         │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  Enter: run    y: copy command    Esc: back                 │
└─────────────────────────────────────────────────────────────┘
```

### Replay Configuration

When "Replay" is selected, show additional options:

```
┌─────────────────────────────────────────────────────────────┐
│  PCAP > Replay                                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  File: pcaps/stress/ENIP.pcap                               │
│                                                             │
│  Target IP: _____________                                   │
│                                                             │
│  Options:                                                   │
│    [x] Rewrite IP/MAC addresses                             │
│    [ ] Preserve original timing                             │
│    [ ] Application-layer only (skip raw replay)             │
│                                                             │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│  Command preview:                                           │
│  cipdip pcap-replay --input pcaps/stress/ENIP.pcap \        │
│    --server-ip ??? --rewrite                                │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  Tab: next    Space: toggle    Enter: run    Esc: back      │
└─────────────────────────────────────────────────────────────┘
```

---

## 8. Catalog Screen

Browse CIP classes, services, and attributes.

```
┌─────────────────────────────────────────────────────────────┐
│  CIP CATALOG                                                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Filter: __________                                         │
│                                                             │
│  Classes:                                                   │
│  ─────────────────────────────────────────────────────────  │
│  > Identity Object            0x01                          │
│    Message Router             0x02                          │
│    Assembly                   0x04                          │
│    Connection Manager         0x06                          │
│    TCP/IP Interface           0xF5                          │
│    Ethernet Link              0xF6                          │
│    ...                                                      │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  ↑↓: navigate    Enter: expand    /: filter    m: menu      │
└─────────────────────────────────────────────────────────────┘
```

### Expanded Class

```
┌─────────────────────────────────────────────────────────────┐
│  CIP CATALOG > Identity Object (0x01)                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Instance 1 Attributes:                                     │
│  ─────────────────────────────────────────────────────────  │
│    1   Vendor ID              UINT                          │
│    2   Device Type            UINT                          │
│    3   Product Code           UINT                          │
│    4   Revision               UINT[2]                       │
│    5   Status                 WORD                          │
│    6   Serial Number          UDINT                         │
│  > 7   Product Name           SHORT_STRING                  │
│                                                             │
│  Services:                                                  │
│  ─────────────────────────────────────────────────────────  │
│    0x01  Get_Attribute_All                                  │
│    0x0E  Get_Attribute_Single                               │
│    0x10  Set_Attribute_Single                               │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  Enter: probe this attribute    y: copy path    Esc: back   │
└─────────────────────────────────────────────────────────────┘
```

### Probe Dialog

When pressing Enter on an attribute:

```
┌─────────────────────────────────────────────────────────────┐
│  PROBE: Identity Object / Product Name                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Path: 0x01 / 0x01 / 0x07                                   │
│                                                             │
│  Target IP: _____________    Port: 44818                    │
│                                                             │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│  Command:                                                   │
│  cipdip single --ip ??? --class 0x01 --instance 0x01 \      │
│    --attribute 0x07 --service 0x0E                          │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  Enter: run    y: copy command    Esc: cancel               │
└─────────────────────────────────────────────────────────────┘
```

---

## 9. Runs Screen

View history and results of past operations.

```
┌─────────────────────────────────────────────────────────────┐
│  RUN HISTORY                                                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Filter: [all]  client | server | pcap                      │
│                                                             │
│  ─────────────────────────────────────────────────────────  │
│  > 2026-01-10 10:41  client baseline  192.168.1.50   ✓      │
│    2026-01-10 10:38  server adapter   :44818         ✓ 14m  │
│    2026-01-10 10:22  pcap-summary     ENIP.pcap      ✓      │
│    2026-01-09 16:05  client stress    192.168.1.50   ✗ err  │
│    2026-01-09 15:30  pcap-replay      test.pcap      ✓      │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  Enter: view details    d: delete    Tab: filter    m: menu │
└─────────────────────────────────────────────────────────────┘
```

### Run Detail View

```
┌─────────────────────────────────────────────────────────────┐
│  RUN: 2026-01-10 10:41 client baseline                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Status: completed successfully                             │
│  Duration: 5m 23s                                           │
│  Target: 192.168.1.50:44818                                 │
│                                                             │
│  Command:                                                   │
│  cipdip client --ip 192.168.1.50 --scenario baseline \      │
│    --config cipdip_client.yaml                              │
│                                                             │
│  Results:                                                   │
│    Requests:  4,231                                         │
│    Success:   4,229 (99.95%)                                │
│    Errors:        2 (0.05%)                                 │
│    Avg latency: 12.3ms                                      │
│                                                             │
│  Artifacts:                                                 │
│    summary.json    resolved.yaml    stdout.log              │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  o: open artifact    r: re-run    y: copy command    Esc    │
└─────────────────────────────────────────────────────────────┘
```

---

## 10. Run Artifacts

Every run automatically saves:

| File | Purpose |
|------|---------|
| `command.txt` | Exact CLI command that was executed |
| `stdout.log` | Complete terminal output |
| `summary.json` | Structured results (counts, timings, errors) |

Location: `runs/<timestamp>_<type>_<scenario>/`

Example: `runs/2026-01-10_10-41_client_baseline/`

**No configuration required.** Artifacts are always generated.

---

## 11. Error Handling

### Validation Errors

Show immediately, inline, without modal dialogs:

```
┌─────────────────────────────────────────────────────────────┐
│  CLIENT                                                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Target IP: 192.168.1      ← invalid IP address             │
│             ^^^^^^^^^^^^                                    │
│                                                             │
```

### Runtime Errors

Show in a non-blocking status bar, with option to view details:

```
├─────────────────────────────────────────────────────────────┤
│  ERROR: connection refused to 192.168.1.50:44818    [v]iew  │
└─────────────────────────────────────────────────────────────┘
```

### Fatal Errors

Replace screen content with error and recovery options:

```
┌─────────────────────────────────────────────────────────────┐
│  ERROR                                                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Failed to bind to port 44818: address already in use       │
│                                                             │
│  Another process is using this port. Options:               │
│                                                             │
│    [1] Use different port                                   │
│    [2] Find and stop conflicting process                    │
│    [3] Return to menu                                       │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  1/2/3: select    q: quit                                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 12. Help System

Pressing `?` shows context-sensitive help as an overlay:

```
┌─────────────────────────────────────────────────────────────┐
│  CLIENT                                                     │
├────────────────────────────────────────┬────────────────────┤
│                                        │ HELP               │
│  Target IP: 192.168.1.50               │                    │
│                                        │ This screen        │
│  Scenario: baseline                    │ configures a CIP   │
│                                        │ client to connect  │
│  ...                                   │ to a remote device │
│                                        │ and run test       │
│                                        │ scenarios.         │
│                                        │                    │
│                                        │ Keys:              │
│                                        │ Tab    next field  │
│                                        │ Enter  start run   │
│                                        │ e      edit config │
│                                        │ y      copy cmd    │
│                                        │                    │
│                                        │ Press ? or Esc     │
│                                        │ to close           │
├────────────────────────────────────────┴────────────────────┤
│  ?: close help                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 13. Implementation Notes

### Dependencies

- `bubbletea` - TUI framework
- `lipgloss` - Styling
- `huh` - Form inputs (optional, only if complex forms needed)

### State Management

Each screen is a bubbletea `Model` with:
- `Init()` - Load relevant data
- `Update()` - Handle keypresses and messages
- `View()` - Render current state

Global state (active runs, server status) lives in a shared `AppState` struct passed to all models.

### Screen Transitions

```go
type Screen int

const (
    ScreenMain Screen = iota
    ScreenClient
    ScreenServer
    ScreenPCAP
    ScreenCatalog
    ScreenRuns
)

// Navigation is a simple state machine
func (m Model) handleGlobalKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
    switch msg.String() {
    case "m":
        return m.switchTo(ScreenMain)
    case "q":
        if m.hasActiveRun() {
            return m.showQuitConfirmation()
        }
        return m, tea.Quit
    case "?":
        return m.toggleHelp()
    }
    return m, nil
}
```

### CLI Command Generation

Every screen that can execute a command maintains a `buildCommand()` method that returns the equivalent CLI invocation. This is displayed in the preview area and used for:

1. Actually executing the command
2. Copying to clipboard
3. Saving to `command.txt` in run artifacts

---

## 14. Acceptance Criteria

The TUI is complete when:

1. `cipdip ui` launches and shows main menu
2. Each screen (client, server, pcap, catalog, runs) is functional
3. All operations show command preview before execution
4. Running operations show live status
5. All runs save artifacts automatically
6. `?` shows help on every screen
7. `m` returns to main menu from anywhere
8. Error messages are clear and actionable
