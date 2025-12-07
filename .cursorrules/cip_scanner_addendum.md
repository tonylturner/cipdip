# Addendum: Connected CIP I/O Support for Go EtherNet/IP Scanner

This addendum extends the original **CIP Scanner (Go) – Full EtherNet/IP CIP Client Spec** to add:

1. **Connected Class 1 I/O–style behavior** using `ForwardOpen` / `ForwardClose`.
2. A new scenario, `io`, that more closely resembles **CompactLogix/ControlLogix I/O connections**.
3. Minor extensions to the client interface and config to support I/O-style connections.

You can treat this file as an additional Cursor rule alongside the main spec.

---

## 1. Goals of the Addendum

The original spec focuses on **unconnected explicit messaging (UCMM)**. This addendum adds:

- Support for **connected messaging** using:
  - `Forward Open`
  - `Forward Close`
- A new scenario (`io`) that:
  - Opens one or more **CIP I/O connections**.
  - Sends/receives I/O-style cyclic traffic to better approximate **PLC → adapter** behavior.
- This remains **EtherNet/IP only**, with no non-Ethernet transports.

The goal is to get **closer to CompactLogix v32 I/O patterns** without requiring Rockwell hardware or Studio 5000.

---

## 2. Config Extensions

We extend `cip_targets.yaml` to add an optional `io_connections` section that describes the connected Class 1-style I/O relationships.

### 2.1 New Config Section

```yaml
# New section in cip_targets.yaml for connected I/O behavior

io_connections:
  - name: "IOConn1"
    o_to_t_rpi_ms: 20          # Requested Packet Interval (originator to target)
    t_to_o_rpi_ms: 20          # Requested Packet Interval (target to originator)
    o_to_t_size_bytes: 8       # Size of O->T connection data (bytes)
    t_to_o_size_bytes: 8       # Size of T->O connection data (bytes)
    priority: "scheduled"      # or "low", "high", "urgent" (map to CIP priority / connection type)
    transport_class_trigger: 3 # CIP transport class; 1, 2, or 3 (typically 1 or 3 for cyclic)
    // Logical CIP path to the target object or assembly
    class: 0x04
    instance: 0x65
    // Optional: connection path overrides (e.g., routing segments)
    connection_path_hex: ""    # Optional raw hex path if needed for complex routing
```

### 2.2 Go Structs

Extend the config package with:

```go
type IOConnectionConfig struct {
    Name                 string `yaml:"name"`
    OToTRPIMs            int    `yaml:"o_to_t_rpi_ms"`
    TToORPIMs            int    `yaml:"t_to_o_rpi_ms"`
    OToTSizeBytes        int    `yaml:"o_to_t_size_bytes"`
    TToOSizeBytes        int    `yaml:"t_to_o_size_bytes"`
    Priority             string `yaml:"priority"`
    TransportClassTrigger int   `yaml:"transport_class_trigger"`

    Class    uint16 `yaml:"class"`
    Instance uint16 `yaml:"instance"`

    ConnectionPathHex string `yaml:"connection_path_hex,omitempty"`
}

type Config struct {
    Adapter       AdapterConfig       `yaml:"adapter"`
    ReadTargets   []CIPTarget         `yaml:"read_targets"`
    WriteTargets  []CIPTarget         `yaml:"write_targets"`
    CustomTargets []CIPTarget         `yaml:"custom_targets"`
    IOConnections []IOConnectionConfig `yaml:"io_connections"` // new
}
```

Validation rules:

- `IOConnections` may be empty (then the `io` scenario can be disabled or no-op).
- If present:
  - `OToTRPIMs`, `TToORPIMs` must be > 0.
  - `OToTSizeBytes`, `TToOSizeBytes` must be > 0.
  - `TransportClassTrigger` must be 1, 2, or 3.
  - `Class` and `Instance` must be set.

---

## 3. `cipclient` Extensions for Connected Messaging

We extend the `Client` interface to better support **ForwardOpen / ForwardClose** and to send/receive I/O-style data.

### 3.1 New Types

```go
type ConnectionParams struct {
    Name                  string
    OToTRPIMs             int
    TToORPIMs             int
    OToTSizeBytes         int
    TToOSizeBytes         int
    Priority              string
    TransportClassTrigger int

    // CIP logical path (class/instance) or raw connection path override
    Class             uint16
    Instance          uint16
    ConnectionPathHex string // optional raw EPATH override
}

// Represents an active connected I/O connection
type IOConnection struct {
    ID               uint32 // connection ID or identifying handle
    Params           ConnectionParams
    LastOToTDataSent []byte
    LastTToODataRecv []byte
}
```

### 3.2 Client Interface Additions

Update `Client`:

```go
type Client interface {
    Connect(ctx context.Context, ip string, port int) error
    Disconnect(ctx context.Context) error

    InvokeService(ctx context.Context, req CIPRequest) (CIPResponse, error)
    ReadAttribute(ctx context.Context, path CIPPath) (CIPResponse, error)
    WriteAttribute(ctx context.Context, path CIPPath, value []byte) (CIPResponse, error)

    // New: Connected messaging support

    // Establish a connected I/O-style connection using Forward Open
    ForwardOpen(ctx context.Context, params ConnectionParams) (*IOConnection, error)

    // Terminate a connection using Forward Close
    ForwardClose(ctx context.Context, conn *IOConnection) error

    // Send O->T (originator-to-target) I/O data over a connected path
    SendIOData(ctx context.Context, conn *IOConnection, data []byte) error

    // Receive T->O (target-to-originator) I/O data if the underlying transport supports it
    // Implementation may poll or read from a background loop depending on ENIP model chosen.
    ReceiveIOData(ctx context.Context, conn *IOConnection) ([]byte, error)
}
```

### 3.3 Implementation Notes

- `ForwardOpen`:
  - Encapsulate in a CIP `Forward Open` service (typically service code 0x54 under the Connection Manager object, class 0x06).
  - Build the connection parameters (RPIs, data sizes, priority, transport trigger).
  - Use `ConnectionPathHex` if provided; otherwise, construct an EPATH based on `Class`/`Instance`.
  - Return an `IOConnection` with a unique connection ID / handle.

- `ForwardClose`:
  - Use `Forward Close` service (e.g., 0x4E) with the connection ID.
  - Clean up any local state.

- `SendIOData` / `ReceiveIOData`:
  - Depending on implementation:
    - Data can be sent using `SendUnitData` encapsulating the I/O payload.
    - T->O data may be polled or read from a background goroutine managing a UDP/TCP I/O channel.
  - A minimal implementation can treat I/O as periodic `SendUnitData` messages with fixed payload sizes.

> The addendum does **not** require a full UDT/assembly abstraction; a fixed number of bytes per O->T and T->O is sufficient for DPI testing.

---

## 4. New `io` Scenario

Add a fifth scenario, `io`, in the `scenario` package.

### 4.1 CLI

Extend the `--scenario` flag:

- Valid values now: `baseline`, `mixed`, `stress`, `churn`, `io`.

### 4.2 Scenario Definition

```go
type IOScenario struct{}
```

Implement:

```go
func (s *IOScenario) Run(ctx context.Context, client Client, cfg Config, params ScenarioParams) error
```

### 4.3 IO Scenario Behavior

**Goal:** Approximate PLC I/O behavior with connected Class 1 traffic:

1. **Initialization**
   - Parse `cfg.IOConnections`.
   - If empty, log a warning and return gracefully.
   - For each `IOConnectionConfig`:
     - Build a `ConnectionParams`.
     - Call `client.ForwardOpen` to establish the connection.
     - Store resulting `IOConnection` objects in a slice.
     - Log each connection’s parameters.

2. **Main Loop**
   - Run a loop until `params.Duration` or context cancellation.
   - For each active `IOConnection`:
     - Build O->T payload:
       - Use a simple pattern: e.g., a counter or timestamp written into the first 4–8 bytes.
       - Ensure payload length = `OToTSizeBytes`.
     - Call `client.SendIOData` with that payload.
     - Measure O->T RTT (if meaningful) or at least measure send time.
     - Attempt to read T->O payload via `client.ReceiveIOData`:
       - Ensure payload length = `TToOSizeBytes`.
       - Record any data changes.
     - Record metrics:
       - Per-connection send/receive success.
       - Any timeouts or errors.
   - Between iterations:
     - Sleep for a period derived from the **shortest RPI** among connections or `params.Interval`, whichever is smaller.

3. **Shutdown**
   - On exit, for each `IOConnection`:
     - Call `client.ForwardClose`.
     - Log success or failure.
   - Summarize metrics:
     - Number of successful I/O cycles.
     - Number of failed sends/receives.
     - Per-connection error counts.

### 4.4 Default Timing for `io` Scenario

- If `--interval-ms` is not supplied:
  - Default to **10 ms**.
  - The scenario may internally clamp/adjust the loop timing based on each connection’s RPI.

---

## 5. Metrics & Logging for IO Scenario

### 5.1 Additional Metrics

For `io` scenario, add fields to the metrics CSV:

```text
timestamp,scenario,connection_name,operation,success,rtt_ms,error
2025-12-07T18:45:01.000Z,io,IOConn1,O_TO_T_SEND,true,1.2,
2025-12-07T18:45:01.000Z,io,IOConn1,T_TO_O_RECV,true,1.5,
2025-12-07T18:45:01.010Z,io,IOConn2,O_TO_T_SEND,false,,timeout
```

Operations for `io`:

- `O_TO_T_SEND`
- `T_TO_O_RECV`
- `FORWARD_OPEN`
- `FORWARD_CLOSE`

### 5.2 Logging

- Log each `ForwardOpen` / `ForwardClose` attempt with:
  - Connection name.
  - Parameters (RPIs, sizes, class/instance).
  - Outcome and any error.
- In the main loop:
  - For each connection:
    - If `SendIOData` fails, log error with connection name and error detail.
    - If `ReceiveIOData` fails, log but continue unless errors are persistent.

---

## 6. Interaction With Existing Scenarios

- The new `io` scenario is **independent** from `baseline`, `mixed`, `stress`, and `churn`.
- All scenarios share:
  - The same `Client` implementation.
  - The same `Config` struct (now extended).
  - The same logging and metrics infrastructure.

**Important:** The presence of `IOConnections` in the config should **not** affect behavior of the other scenarios unless they explicitly opt into using them.

---

## 7. Summary

This addendum:

- Extends the Go CIP scanner spec to support **connected CIP I/O via ForwardOpen/ForwardClose**.
- Introduces a new `io` scenario that:
  - More closely resembles **PLC-style I/O connections**.
  - Provides richer, more realistic traffic for testing **ICS firewall CIP DPI**.
- Keeps everything:
  - **EtherNet/IP only**.
  - Config-driven.
  - Integrable with the existing architecture and metrics model.

Include this file and the main spec in your `cursorrules` so Cursor understands both **unconnected explicit messaging** and **connected I/O** requirements.
