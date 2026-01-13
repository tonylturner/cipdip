# Run Manifest Schema Reference

Run Manifests are YAML files that declare the configuration for orchestrated test runs.

## Schema Version

Current schema version: `v1`

## Complete Schema

```yaml
# Run Manifest Schema v1
api_version: v1                    # Required: must be "v1"

# Run identification
run_id: auto                       # Optional: "auto" generates timestamped ID
seed: 1337                         # Optional: RNG seed for deterministic runs

# Profile configuration
profile:
  path: profiles/baseline.yaml     # Required: path to process profile
  distribution: inline             # Optional: inline|push|preinstalled (default: inline)
  checksum: sha256:abc123...       # Optional: expected checksum

# Network configuration
network:
  control_plane: management        # Optional: descriptive label
  data_plane:
    client_bind_ip: 10.10.10.10    # Optional: client bind address
    server_listen_ip: 10.10.10.20  # Required if server role defined
    target_ip: 10.10.10.20         # Required: where client connects
    target_port: 44818             # Optional: default 44818

# Role definitions
roles:
  server:                          # Optional: server role
    agent: A1                      # Required: agent ID or "local"
    mode: baseline                 # Optional: server mode
    personality: adapter           # Optional: adapter|logix_like
    args:                          # Optional: additional CLI args
      pcap: server.pcap
      responses_only: false
      enable_udp_io: false
      log_level: info

  client:                          # Optional: client role
    agent: local                   # Required: agent ID or "local"
    scenario: baseline             # Required: scenario name or "profile"
    profile_role: hmi              # Required if scenario=profile
    duration_seconds: 60           # Required: run duration
    interval_ms: 250               # Optional: polling interval
    args:                          # Optional: additional CLI args
      pcap: client.pcap
      verbose: false
      debug: false

# Readiness configuration
readiness:
  method: structured_stdout        # Optional: structured_stdout|tcp_connect
  timeout_seconds: 30              # Optional: default 30

# Artifact configuration
artifacts:
  bundle_format: dir               # Optional: dir|zip (default: dir)
  include:                         # Optional: patterns to include
    - manifest_resolved.yaml
    - profile.yaml
    - run_meta.json
    - "*.pcap"
    - "logs/*.log"

# Post-run actions
post_run:
  analyze: true                    # Optional: run PCAP analysis
  diff_baseline: ""                # Optional: path to baseline bundle
```

## Field Reference

### Top-Level Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `api_version` | string | Yes | - | Must be "v1" |
| `run_id` | string | No | auto | Run identifier; "auto" generates timestamp |
| `seed` | integer | No | - | RNG seed for deterministic runs |

### Profile Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `profile.path` | string | Yes | - | Path to process profile YAML |
| `profile.distribution` | string | No | inline | How profile is distributed to agents |
| `profile.checksum` | string | No | - | Expected SHA256 checksum |

**Distribution modes:**
- `inline` - Profile embedded in bundle
- `push` - Profile copied to remote agents via SFTP
- `preinstalled` - Profile already exists on agents

### Network Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `network.control_plane` | string | No | - | Descriptive label for control plane |
| `network.data_plane.client_bind_ip` | string | No | - | Client bind address |
| `network.data_plane.server_listen_ip` | string | Conditional | - | Server listen address (required if server role) |
| `network.data_plane.target_ip` | string | Yes | - | Target IP for client connections |
| `network.data_plane.target_port` | integer | No | 44818 | Target port |

### Server Role

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `roles.server.agent` | string | Yes | - | Agent ID or "local" |
| `roles.server.mode` | string | No | - | Server mode |
| `roles.server.personality` | string | No | adapter | Server personality |
| `roles.server.args` | object | No | - | Additional CLI arguments |

**Personality values:**
- `adapter` - Basic CIP adapter emulation
- `logix_like` - Logix-like controller emulation

### Client Role

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `roles.client.agent` | string | Yes | - | Agent ID or "local" |
| `roles.client.scenario` | string | Yes | - | Scenario name or "profile" |
| `roles.client.profile_role` | string | Conditional | - | Profile role (required if scenario=profile) |
| `roles.client.duration_seconds` | integer | Yes | - | Run duration in seconds |
| `roles.client.interval_ms` | integer | No | - | Polling interval in milliseconds |
| `roles.client.args` | object | No | - | Additional CLI arguments |

**Scenario values:**
- `baseline` - Basic CIP operations
- `stress` - High-rate stress test
- `io` - I/O connection testing
- `edge` - Edge case testing
- `mixed` - Mixed operations
- `firewall` - DPI testing
- `vendor_variants` - Vendor-specific testing
- `profile` - Profile-based scenario

### Readiness Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `readiness.method` | string | No | structured_stdout | How to detect server ready |
| `readiness.timeout_seconds` | integer | No | 30 | Readiness timeout |

**Readiness methods:**
- `structured_stdout` - Parse JSON from server stdout
- `tcp_connect` - Poll TCP connection to server

### Artifacts Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `artifacts.bundle_format` | string | No | dir | Bundle format: dir or zip |
| `artifacts.include` | array | No | - | Glob patterns for files to include |

### Post-Run Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `post_run.analyze` | boolean | No | false | Run PCAP analysis |
| `post_run.diff_baseline` | string | No | - | Path to baseline bundle for diff |

## Validation Rules

1. `api_version` must be "v1"
2. `profile.path` must be specified
3. `profile.distribution` must be: inline, push, or preinstalled
4. `network.data_plane.target_ip` must be a valid IP address
5. At least one role (server or client) must be defined
6. If server role defined: `network.data_plane.server_listen_ip` required
7. If client role defined: `scenario` and `duration_seconds` required
8. If `scenario` is "profile": `profile_role` required
9. `roles.server.personality` must be: adapter or logix_like
10. `readiness.method` must be: structured_stdout or tcp_connect
11. `artifacts.bundle_format` must be: dir or zip
12. All agent IDs must map to provided `--agent` specs

## Examples

### Minimal Server-Only

```yaml
api_version: v1
profile:
  path: profiles/minimal.yaml
network:
  data_plane:
    target_ip: 0.0.0.0
    server_listen_ip: 0.0.0.0
roles:
  server:
    agent: local
```

### Minimal Client-Only

```yaml
api_version: v1
profile:
  path: profiles/minimal.yaml
network:
  data_plane:
    target_ip: 192.168.1.100
roles:
  client:
    agent: local
    scenario: baseline
    duration_seconds: 30
```

### Full Local Run

```yaml
api_version: v1
run_id: baseline-test

profile:
  path: profiles/baseline.yaml
  distribution: inline

network:
  data_plane:
    server_listen_ip: 0.0.0.0
    target_ip: 127.0.0.1

roles:
  server:
    agent: local
    personality: adapter
    args:
      pcap: server.pcap

  client:
    agent: local
    scenario: baseline
    duration_seconds: 60
    args:
      pcap: client.pcap

readiness:
  method: structured_stdout
  timeout_seconds: 30

post_run:
  analyze: true
```

### Remote Execution

```yaml
api_version: v1
run_id: remote-test

profile:
  path: profiles/stress.yaml
  distribution: push

network:
  data_plane:
    server_listen_ip: 10.0.0.50
    target_ip: 10.0.0.50
    client_bind_ip: 10.0.0.10

roles:
  server:
    agent: server-host  # Maps to --agent server-host=ssh://...
    personality: logix_like
    args:
      pcap: server.pcap
      enable_udp_io: true

  client:
    agent: local
    scenario: stress
    duration_seconds: 300
    interval_ms: 100
    args:
      pcap: client.pcap
      verbose: true

readiness:
  method: tcp_connect
  timeout_seconds: 60

artifacts:
  bundle_format: dir

post_run:
  analyze: true
  diff_baseline: runs/previous-baseline
```

### Profile-Based Scenario

```yaml
api_version: v1
seed: 42

profile:
  path: profiles/hmi_simulation.yaml
  distribution: inline
  checksum: sha256:abc123...

network:
  data_plane:
    target_ip: 192.168.1.100

roles:
  client:
    agent: local
    scenario: profile
    profile_role: hmi
    duration_seconds: 120
    args:
      pcap: hmi_traffic.pcap

post_run:
  analyze: true
```

## Resolved Manifest

When a manifest is executed, the controller generates `manifest_resolved.yaml` with:

- Computed checksums for profile
- Expanded CLI arguments
- Resolved paths
- Timestamp information

This file is included in the bundle for reproducibility.
