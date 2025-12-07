# CIP Scanner (Go) – Full EtherNet/IP CIP Client Spec for DPI Test Lab

This document specifies a **Go-based EtherNet/IP / CIP scanner tool** to drive traffic through industrial firewalls (Moxa, Tofino, Dynics) for the **Track B** tests in the CIP DPI evaluation plan.

The intent is that Cursor (or another AI coding assistant) can implement this tool directly from this spec.

---

## 1. Purpose & Scope

### 1.1 Goals

The tool shall:

1. Act as a **CIP/EtherNet-IP client/scanner** that connects to a target adapter (e.g., CLICK PLUS C2-03CPU).
2. Generate **repeatable, controllable CIP traffic** for DPI testing through firewalls.
3. Support multiple **traffic scenarios (“profiles”)**:
   - `baseline` – Low-frequency, read-only polling.
   - `mixed` – Medium-frequency mixed reads and writes.
   - `stress` – High-frequency reads to stress DPI and latency.
   - `churn` – Frequent connection setup/teardown.
4. Provide a **generic CIP client** that can invoke **any CIP service** over EtherNet/IP (UCMM and, optionally, connected messaging).
5. Be controlled via a **CLI** with flags (for IP, scenario, duration, etc.).
6. Produce **structured logs** (human-readable + CSV/JSON metrics) for offline analysis.
7. Be modular so adding new scenarios or CIP targets is straightforward.

### 1.2 In-Scope vs Out-of-Scope

- **In scope**
  - CIP over **EtherNet/IP only** (TCP/UDP port 44818).
  - UCMM (unconnected messaging) and, optionally, connected messaging (Forward Open / Forward Close).
  - All CIP services that can be sent via `SendRRData` (and `SendUnitData` if connected messaging is implemented).

- **Out of scope**
  - Non-Ethernet transports (DeviceNet, ControlNet, etc.).
  - Vendor-specific transport layers outside EtherNet/IP.
  - A full-blown ICS HMI/SCADA client.

The tool **does not** need to support every possible CIP object model; it needs to provide a **generic service invocation mechanism** plus convenient helpers for common services.

---

## 2. Technology & Dependencies

### 2.1 Language & Version

- **Language:** Go  
- **Minimum Version:** Go 1.21 (or higher)

### 2.2 External Dependencies

Prefer using an existing Go **EtherNet/IP / CIP client library** if one is available and actively maintained.

If none is suitable, implement a **minimal ENIP/CIP client** with:

- TCP client to port 44818.
- Session registration and unregistration.
- Ability to craft and parse:
  - `RegisterSession` / `UnregisterSession`.
  - `ListServices`, `ListIdentity`, `ListInterfaces` (optional but useful).
  - `SendRRData` for UCMM (unconnected CIP).
  - Optionally `SendUnitData` for connected CIP messaging.
- Ability to encode/decode:
  - CIP Service code (1 byte).
  - CIP Request/Response data.
  - CIP Path (class/instance/attribute, plus optional connection path).

The spec should be fulfilled **without hardcoding any specific library name**; Cursor can pick or implement as needed.

### 2.3 Other Go Packages

Use standard library packages unless a strong reason exists:

- `flag` or `spf13/cobra` for CLI.
- `log` or `zap`/`logrus` for logging.
- `time`, `context`, `sync`, `math`, `os/signal`, `os`, `encoding/csv`, `encoding/json`.

External logging/CLI libraries are allowed if they simplify implementation, but the code should be easy to build with:

```bash
go build ./...
```

after a `go mod tidy`.

---

## 3. High-Level Architecture

### 3.1 Components

1. **`cmd/cipscanner/main.go`**
   - Parses CLI flags.
   - Loads config file.
   - Initializes logger and metrics writer.
   - Selects and runs the chosen scenario.

2. **`config` package**
   - Loads and validates CIP target configuration.
   - Describes which CIP paths and services to access.

3. **`cipclient` package**
   - Wraps EtherNet/IP / CIP operations.
   - Exposes:
     - A **generic service invocation API**.
     - Convenience helpers for common services.

4. **`scenario` package**
   - Defines the scenario interface and concrete implementations:
     - `baseline`
     - `mixed`
     - `stress`
     - `churn`
   - Each scenario:
     - Receives a `Client`, config, and runtime parameters.
     - Runs until duration expires or context is cancelled.

5. **`metrics` package**
   - Collects timing and error statistics.
   - Writes metrics to CSV/JSON on completion.

---

## 4. Configuration File

### 4.1 Purpose

The configuration file defines **which CIP paths and services** to target on the adapter (CLICK or other device). This keeps the code generic across devices and firmware versions.

### 4.2 Format

Use **YAML** (preferred) or JSON.

Example YAML:

```yaml
# cip_targets.yaml

adapter:
  name: "CLICK C2-03CPU"   # Human-friendly name (for logs only)
  port: 44818              # EtherNet/IP TCP port (default 44818)

# CIP targets to read/write.
# Each entry may specify:
# - service: e.g., get_attribute_single, set_attribute_single, custom
# - service_code: optional explicit numeric code (0x0E, 0x10, etc.)
# - path: class/instance/attribute
read_targets:
  - name: "InputBlock1"
    service: "get_attribute_single"
    class: 0x04
    instance: 0x65
    attribute: 0x03

  - name: "InputBlock2"
    service: "get_attribute_single"
    class: 0x04
    instance: 0x66
    attribute: 0x03

write_targets:
  - name: "OutputBlock1"
    service: "set_attribute_single"
    class: 0x04
    instance: 0x67
    attribute: 0x03
    pattern: "increment"        # "increment", "toggle", or "constant"
    initial_value: 0

# Optional generic/custom services (broader support)
# These entries allow specifying any service code and raw payload template.
custom_targets:
  - name: "CustomServiceExample"
    service: "custom"
    service_code: 0x01          # e.g., Get_Attribute_All, or any CIP service
    class: 0x01                 # example class
    instance: 0x01              # example instance
    attribute: 0x00             # may be unused depending on service
    request_payload_hex: ""     # raw hex string for request body (optional)
```

> Note: Exact class/instance/attribute values must be aligned with the CLICK’s EtherNet/IP mapping or any other target device’s object model. This spec defines the **structure**, not the exact numbers.

### 4.3 Go Config Struct

Suggested structs:

```go
type AdapterConfig struct {
    Name string `yaml:"name"`
    Port int    `yaml:"port"`
}

type ServiceType string

const (
    ServiceGetAttributeSingle ServiceType = "get_attribute_single"
    ServiceSetAttributeSingle ServiceType = "set_attribute_single"
    ServiceCustom             ServiceType = "custom"
    // extendable
)

type CIPTarget struct {
    Name        string      `yaml:"name"`
    Service     ServiceType `yaml:"service"`
    ServiceCode uint8       `yaml:"service_code,omitempty"` // used for custom services
    Class       uint16      `yaml:"class"`
    Instance    uint16      `yaml:"instance"`
    Attribute   uint8       `yaml:"attribute"`

    // Optional fields for write/custom behavior
    Pattern      string `yaml:"pattern,omitempty"`
    InitialValue int64  `yaml:"initial_value,omitempty"`

    // Optional raw payload for custom services (hex-encoded string)
    RequestPayloadHex string `yaml:"request_payload_hex,omitempty"`
}

type Config struct {
    Adapter       AdapterConfig `yaml:"adapter"`
    ReadTargets   []CIPTarget   `yaml:"read_targets"`
    WriteTargets  []CIPTarget   `yaml:"write_targets"`
    CustomTargets []CIPTarget   `yaml:"custom_targets"`
}
```

The loader should:

- Apply defaults (e.g., port 44818 if 0).
- Validate that at least one of `read_targets`, `write_targets`, or `custom_targets` is populated.
- Ensure `ServiceCode` is provided when `Service == ServiceCustom`.

---

## 5. Command-Line Interface

### 5.1 Example Usage

```bash
go run ./cmd/cipscanner \
  --ip 10.0.0.50 \
  --scenario baseline \
  --interval-ms 250 \
  --duration-seconds 300 \
  --config ./cip_targets.yaml \
  --log-file ./logs/cip_scanner.log \
  --metrics-file ./logs/cip_metrics.csv
```

### 5.2 Flags

**Required:**

- `--ip` (string)  
  Target CIP adapter IP (e.g., CLICK CPU).

- `--scenario` (string)  
  One of: `baseline`, `mixed`, `stress`, `churn`.

**Optional:**

- `--port` (int, default: `44818`)  
  EtherNet/IP TCP port.

- `--interval-ms` (int)  
  Base polling interval; scenario-specific defaults if omitted:
  - `baseline`: 250 ms
  - `mixed`: 100 ms
  - `stress`: 20 ms
  - `churn`: 100 ms (connection cycle timing)

- `--duration-seconds` (int, default: `300`)  
  Total run time in seconds.

- `--config` (string, default: `cip_targets.yaml`)  
  Path to YAML config file.

- `--log-file` (string, optional)  
  Path for detailed log output. If omitted, log to stdout only.

- `--metrics-file` (string, optional)  
  Path for CSV/JSON metrics. If omitted, metrics can still be printed at the end.

- `--verbose` (bool, default: false)  
  Enable debug-level logging.

### 5.3 Behavior on Invalid Inputs

- Missing required flags → print usage and exit with non-zero status.
- Invalid scenario name → print error and usage, exit non-zero.
- Invalid or missing config file → print error, exit non-zero.

---

## 6. CIP Client API (Go)

### 6.1 Types

Define a CIP path and service request abstraction:

```go
type CIPPath struct {
    Class     uint16
    Instance  uint16
    Attribute uint8
    Name      string // from config, for logging
}

type CIPServiceCode uint8

// Common CIP service codes (non-exhaustive)
const (
    CIPServiceGetAttributeAll    CIPServiceCode = 0x01
    CIPServiceSetAttributeAll    CIPServiceCode = 0x02
    CIPServiceGetAttributeList   CIPServiceCode = 0x03
    CIPServiceSetAttributeList   CIPServiceCode = 0x04
    CIPServiceReset              CIPServiceCode = 0x05
    CIPServiceStart              CIPServiceCode = 0x06
    CIPServiceStop               CIPServiceCode = 0x07
    CIPServiceCreate             CIPServiceCode = 0x08
    CIPServiceDelete             CIPServiceCode = 0x09
    CIPServiceMultipleService    CIPServiceCode = 0x0A
    CIPServiceApplyAttributes    CIPServiceCode = 0x0D
    CIPServiceGetAttributeSingle CIPServiceCode = 0x0E
    CIPServiceSetAttributeSingle CIPServiceCode = 0x10
    CIPServiceFindNextObjectInst CIPServiceCode = 0x11
    // ... extendable as necessary
)

type CIPRequest struct {
    Service   CIPServiceCode
    Path      CIPPath
    Payload   []byte // raw CIP request body (no service/path)
}

type CIPResponse struct {
    Service   CIPServiceCode
    Path      CIPPath
    Status    uint8  // general status from CIP response
    ExtStatus []byte // optional additional status data
    Payload   []byte // raw response data
}
```

### 6.2 Client Interface

```go
type Client interface {
    Connect(ctx context.Context, ip string, port int) error
    Disconnect(ctx context.Context) error

    // Generic CIP service invocation (unconnected messaging over SendRRData)
    InvokeService(ctx context.Context, req CIPRequest) (CIPResponse, error)

    // Convenience helpers for common services
    ReadAttribute(ctx context.Context, path CIPPath) (CIPResponse, error)
    WriteAttribute(ctx context.Context, path CIPPath, value []byte) (CIPResponse, error)

    // Optional: connected messaging support
    ForwardOpen(ctx context.Context, connectionParams ConnectionParams) (ConnectionID uint32, err error)
    ForwardClose(ctx context.Context, connectionID uint32) error
}
```

**Implementation notes:**

- `Connect`:
  - Open a TCP connection to `ip:port`.
  - Send `RegisterSession`.
  - Optionally perform `ListIdentity` for debugging.

- `Disconnect`:
  - Optionally send `UnregisterSession`.
  - Close TCP connection.

- `InvokeService`:
  - Encapsulate the CIP request in EtherNet/IP `SendRRData`.
  - Encode path in EPATH format (logical segment for class/instance/attribute).
  - Decode CIP response general status and additional status.
  - Return `CIPResponse` with raw payload for further parsing.

- `ReadAttribute` / `WriteAttribute`:
  - Use `InvokeService` under the hood with service codes:
    - `0x0E` for Get Attribute Single.
    - `0x10` for Set Attribute Single.

- `ForwardOpen` / `ForwardClose`:
  - Optional for connected messaging; not required for basic DPI testing but the API should allow future expansion.

---

## 7. Scenarios

Implement a `Scenario` interface:

```go
type ScenarioParams struct {
    Interval    time.Duration
    Duration    time.Duration
    MetricsSink *metrics.Sink
    Logger      *log.Logger // or structured logger
}

type Scenario interface {
    Run(ctx context.Context, client Client, cfg Config, params ScenarioParams) error
}
```

### 7.1 `baseline` Scenario

**Goal:** Low-frequency, read-only polling (HMI-like behavior).

Behavior:

1. On start, log configuration and selected `read_targets`.
2. Loop until `Duration` or context cancel:
   - For each `read_target`:
     - Build a `CIPPath` and call `ReadAttribute`.
     - Measure RTT (round-trip time).
     - Record:
       - Timestamp
       - Target name
       - Success/failure
       - Status code
       - Error message (if any)
   - Sleep `Interval`.
3. On exit, summarize:
   - Total reads, successes, failures.
   - Min/avg/max RTT.

Default interval: **250 ms**.

### 7.2 `mixed` Scenario

**Goal:** Moderate load, mixed reads and writes.

Behavior:

1. Same as `baseline`, but each loop:
   - For all `read_targets`:
     - Perform reads as in `baseline`.
   - For all `write_targets`:
     - Generate data based on `pattern`:
       - `"increment"` → integer value increments and wraps.
       - `"toggle"` → bitwise toggle pattern.
       - `"constant"` → fixed value.
     - Encode value into bytes as appropriate (e.g., 16-bit or 32-bit, configurable later).
     - Call `WriteAttribute`.
2. Optionally perform writes less frequently (e.g., every N loops) if needed.

Default interval: **100 ms**.

Metrics:

- Separate RTT stats and error counts for reads vs writes.

### 7.3 `stress` Scenario

**Goal:** High-frequency reads to stress DPI and identify latency/jitter issues.

Behavior:

1. Use all `read_targets` (or a subset if configured).
2. Loop until `Duration`:
   - For each `read_target`:
     - Issue `ReadAttribute` one after another (serial is acceptable; concurrency can be added if easy).
   - Sleep `Interval` (e.g., 20 ms).
3. Collect:
   - RTT histogram (if feasible).
   - Count of timeouts / failed calls.

Default interval: **20 ms** (or lower if the target can handle it).

### 7.4 `churn` Scenario

**Goal:** Repeated connection setup/teardown to stress firewall state tracking and CIP session handling.

Behavior:

1. Outer loop runs until `Duration`:
   - `Connect` client.
   - For each `read_target`, perform 1–3 reads.
   - `Disconnect`.
   - Sleep `Interval` between cycles.
2. Metrics:
   - Cycle count.
   - Failed connections.
   - Errors during per-cycle reads.

Default interval: **100 ms** between connection cycles.

---

## 8. Logging & Metrics

### 8.1 Logging

Minimum log content:

- Startup:
  - Scenario name.
  - Target IP/port.
  - Interval and duration.
  - Loaded config summary (number of read/write/custom targets).

- Per operation (info level):
  - Timestamp.
  - Scenario name.
  - Operation type (`READ`, `WRITE`, `CUSTOM`).
  - Target name.
  - Service code.
  - CIP status and error (if any).
  - RTT (ms).

Allow a `--verbose` flag to include debug-level logs (e.g., raw hex of request/response).

### 8.2 Metrics File

Use **CSV** or **JSON**. CSV example:

```text
timestamp,scenario,operation,target_name,service_code,success,rtt_ms,status,error
2025-12-07T18:45:01.123Z,baseline,READ,InputBlock1,0x0E,true,2.5,0,
2025-12-07T18:45:01.123Z,baseline,READ,InputBlock2,0x0E,false,,1,timeout
2025-12-07T18:45:01.223Z,mixed,WRITE,OutputBlock1,0x10,true,3.1,0,
```

On completion, print a summary to stdout:

- Total operations (per scenario).
- Success rate.
- Min/avg/max RTT (per scenario and per operation type).
- Number of timeouts / connection failures.

---

## 9. Error Handling & Signals

- Use `context.Context` with cancellation and deadlines for all CIP operations.
- On `SIGINT` (`Ctrl+C`):
  - Cancel the root context.
  - Allow the current scenario to exit its loop cleanly.
  - Flush metrics and close files.

On startup failures (e.g., cannot connect):

- Log a clear error message.
- Exit with non-zero status code.

---

## 10. Extensibility

Design for:

- **Config-driven behavior**:
  - CIP paths, service codes, and patterns live in `cip_targets.yaml`.
  - Scenarios *only* read from the config; no hard-coded CIP constants outside `cipclient`.

- **Generic CIP support**:
  - `InvokeService` must be able to send arbitrary CIP service codes and payloads to any path.
  - New scenarios can use `InvokeService` directly for more complex flows (e.g., `Multiple Service Packet`, `ForwardOpen`, `ForwardClose`, etc.).

- **Non-breaking changes**:
  - Adding new scenarios should not require changing existing ones.
  - Changing config structure should be additive (avoid breaking existing fields).

This provides a flexible, research-friendly EtherNet/IP CIP client suitable for your DPI tests and future protocol experiments.
