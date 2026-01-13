# Distributed Orchestration Guide

CIPDIP supports distributed test orchestration using a Controller/Agent model. This enables multi-host test coordination where the controller manages execution across local and remote agents via SSH.

## Overview

The orchestration system consists of:

- **Run Manifests** - YAML files declaring test configuration, roles, and agents
- **Run Bundles** - Self-contained artifact archives with reproducible results
- **Controller** - Orchestrates execution phases across agents
- **Agents** - Execute roles (client/server) on local or remote hosts

## Quick Start

### 1. Create a Run Manifest

```yaml
# manifest.yaml
api_version: v1
run_id: auto

profile:
  path: profiles/baseline.yaml
  distribution: inline

network:
  data_plane:
    target_ip: 192.168.1.100
    server_listen_ip: 0.0.0.0

roles:
  server:
    agent: local
    personality: adapter
  client:
    agent: local
    scenario: baseline
    duration_seconds: 60
```

### 2. Run Locally

```bash
# Execute the manifest
cipdip run manifest manifest.yaml

# Dry run (validate and plan only)
cipdip run manifest manifest.yaml --dry-run

# Show execution plan
cipdip run manifest manifest.yaml --print-plan
```

### 3. Verify Results

```bash
# Check bundle integrity
cipdip bundle verify runs/2026-01-13_14-30-00

# Show bundle info
cipdip bundle info runs/2026-01-13_14-30-00

# Compare with baseline
cipdip diff run runs/baseline-run runs/new-run
```

## Remote Execution

### Check Agent Capabilities

```bash
# Local agent status
cipdip agent status

# Remote agent check
cipdip agent check ssh://user@192.168.1.10
cipdip agent check user@server.local
```

### Run with Remote Agents

```bash
# Specify agents on command line
cipdip run manifest manifest.yaml \
  --agent server=ssh://user@192.168.1.10 \
  --agent client=local
```

Or define agents in the manifest:

```yaml
roles:
  server:
    agent: A1  # Maps to --agent A1=ssh://...
    personality: adapter
  client:
    agent: local
    scenario: baseline
    duration_seconds: 60
```

## Execution Phases

The controller executes through these phases:

1. **init** - Create bundle, generate run ID, resolve manifest
2. **stage** - Copy profiles to agents (if distribution=push)
3. **server_start** - Launch server role
4. **server_ready** - Wait for server readiness
5. **client_start** - Launch client role
6. **client_done** - Wait for client completion
7. **server_stop** - Gracefully stop server
8. **collect** - Gather artifacts from agents
9. **bundle** - Finalize bundle, compute hashes
10. **analyze** - Run PCAP analysis (optional)
11. **diff** - Compare with baseline (optional)

## Run Bundle Structure

```
runs/<run_id>/
├── manifest.yaml           # Original manifest
├── manifest_resolved.yaml  # Resolved with checksums
├── profile.yaml            # Staged profile
├── run_meta.json           # Run metadata
├── versions.json           # Tool versions
├── hashes.txt              # SHA256 hashes
├── roles/
│   ├── server/
│   │   ├── server.pcap
│   │   ├── stdout.log
│   │   ├── stderr.log
│   │   └── role_meta.json
│   └── client/
│       ├── client.pcap
│       ├── stdout.log
│       ├── stderr.log
│       └── role_meta.json
└── analysis/
    └── summary.json
```

## TUI Integration

The TUI includes an Orchestration panel accessible via `[o]`:

- **Controller View** - Configure and execute orchestrated runs
  - Manifest path and validation
  - Bundle directory and timeout settings
  - Dry run and verbose options
  - Execution phase progress

- **Agent View** - Local agent status
  - Version and system info
  - Workdir and PCAP capabilities
  - Network interfaces

Press `[Tab]` to switch between Controller and Agent views.

## Server Readiness

The controller detects server readiness using:

1. **Structured stdout** (default) - Server emits JSON:
   ```json
   {"event":"server_ready","listen":"0.0.0.0:44818"}
   ```

2. **TCP connect** (fallback) - Polls TCP connection to server port

Configure in manifest:
```yaml
readiness:
  method: structured_stdout  # or tcp_connect
  timeout_seconds: 30
```

## CLI Reference

### `cipdip run manifest`

Execute an orchestrated run.

```
Usage:
  cipdip run manifest <manifest.yaml> [flags]

Flags:
      --agent strings      Agent mapping (role=transport)
      --bundle-dir string  Output directory for bundles (default "runs")
      --dry-run            Validate and plan only
      --no-analyze         Skip post-run analysis
      --no-diff            Skip diff even if baseline specified
      --print-plan         Print execution plan
      --timeout duration   Overall run timeout (default 5m)
  -v, --verbose            Verbose output
```

### `cipdip bundle verify`

Verify bundle integrity.

```
Usage:
  cipdip bundle verify <bundle-path> [flags]

Flags:
      --json    Output as JSON
```

### `cipdip bundle info`

Show bundle information.

```
Usage:
  cipdip bundle info <bundle-path> [flags]

Flags:
      --json    Output as JSON
```

### `cipdip agent status`

Show local agent capabilities.

```
Usage:
  cipdip agent status [flags]

Flags:
      --json            Output as JSON
      --workdir string  Agent working directory
```

### `cipdip agent check`

Validate remote agent connectivity.

```
Usage:
  cipdip agent check <transport> [flags]

Flags:
      --json              Output as JSON
      --timeout duration  Connection timeout (default 30s)
      --workdir string    Remote working directory
```

### `cipdip diff run`

Compare two run bundles.

```
Usage:
  cipdip diff run <baseline> <compare> [flags]

Flags:
      --format string   Output format: text, json, markdown (default "text")
  -o, --output string   Output file (default stdout)
      --raw             Raw pcap-diff output without bundle context
      --role string     Role to compare: client, server (default "client")
```

## Transport Specifications

Transport specs define how to connect to agents:

| Format | Description |
|--------|-------------|
| `local` | Local execution |
| `ssh://user@host` | SSH with default port |
| `ssh://user@host:2222` | SSH with custom port |
| `user@host` | SSH shorthand |
| `ssh://user@host?key=/path/to/key` | SSH with key file |
| `ssh://user@host?insecure=true` | Skip host key verification |

## Best Practices

1. **Use dry-run first** - Validate manifests before execution
2. **Check agents** - Verify connectivity before orchestrated runs
3. **Preserve bundles** - Keep baseline bundles for comparison
4. **Use bundle verify** - Check integrity after transfer
5. **Meaningful run IDs** - Use descriptive IDs or let auto-generate

## Troubleshooting

### Server not ready

- Check server is binding to correct address
- Verify firewall allows the port
- Increase readiness timeout
- Check server stdout for errors

### SSH connection failed

- Verify SSH key or agent is available
- Check known_hosts or use `insecure=true` for testing
- Verify user has access to the host

### Bundle verification failed

- Check hash mismatches indicate file corruption
- Missing files may indicate incomplete collection
- Re-run if artifacts were modified after collection
