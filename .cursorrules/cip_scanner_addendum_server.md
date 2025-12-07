# Addendum v3: Server / Emulator Mode for Go EtherNet/IP CIP Tool

This addendum extends the existing Go EtherNet/IP CIP scanner specs to add:

1. **Server / emulator capabilities** so the tool can act as:
   - A **client** (scanner) – as already specified.
   - A **server/emulator** – a CIP endpoint the client can talk to.
2. A **ControlLogix-like “tag server” personality** for more realistic Logix-style traffic.
3. An **adapter-style personality** that remains compatible with the CLICK’s assembly-style model.
4. A clarified test matrix with three target types:
   - Real device: **CLICK C2-03CPU** (adapter).
   - **Go-based emulator** (server mode).
   - **PCAP replay** (external tool, already covered in the test plan).

You can include this as an additional Cursor rule alongside the main spec and previous addenda.

---

## 1. High-Level Goals for Server Mode

The tool shall support two **modes of operation** via CLI:

- `--mode client`  
  The existing scanner behavior: connect to a CIP target and generate traffic.

- `--mode server`  
  New: act as an EtherNet/IP / CIP endpoint (emulator) that:
  - Listens on **TCP 44818** (and optionally **UDP 2222** for I/O).
  - Supports **explicit messaging** and optionally I/O-style behavior.
  - Offers two “personalities”:
    - `adapter` – assembly-style object model (CLICK-like).
    - `logix_like` – tag-style interface (ControlLogix-like).

The same binary can therefore run on **both sides of the firewall**:

- On one side in `client` mode.
- On the other side in `server` mode.

---

## 2. CLI Extensions

### 2.1 Mode Flag

Add a new CLI flag:

- `--mode` (string, default: `"client"`)  
  Valid values:
  - `"client"` – current behavior (scanner).
  - `"server"` – new emulator mode.

### 2.2 Server Options

When `--mode=server`, additional flags become relevant:

- `--listen-ip` (string, default: `"0.0.0.0"`)  
  IP address to bind the server to (TCP 44818; optional UDP 2222).

- `--listen-port` (int, default: `44818`)  
  TCP port for EtherNet/IP sessions.

- `--server-config` (string, default: `server_config.yaml`)  
  Path to server/emulator configuration file (see Section 3).

- `--personality` (string, default: `"adapter"`)  
  Valid values:
  - `"adapter"`
  - `"logix_like"`

- `--enable-udp-io` (bool, default: `false`)  
  If true, the server also binds a UDP port (2222) to simulate Class 1 I/O-style traffic for the `io` scenario.

When `--mode=client` (default), these flags may be ignored or rejected if provided incorrectly.

---

## 3. Server Configuration (`server_config.yaml`)

The server config describes **what the emulator exposes** to CIP clients.

### 3.1 Top-Level Structure

Use YAML (consistent with the client config):

```yaml
server:
  name: "Go CIP Emulator"
  personality: "adapter"   # or "logix_like"
  tcp_port: 44818
  udp_io_port: 2222        # optional, used if enable-udp-io

# For adapter-style behavior (CLICK-like assemblies)
adapter_assemblies:
  - name: "InputAssembly1"
    class: 0x04
    instance: 0x65
    attribute: 0x03
    size_bytes: 16
    update_pattern: "counter"   # "counter", "static", "random"

  - name: "OutputAssembly1"
    class: 0x04
    instance: 0x67
    attribute: 0x03
    size_bytes: 16
    writable: true
    update_pattern: "reflect_inputs"

# For logix-like behavior (tag server)
logix_tags:
  - name: "scada"
    type: "DINT"
    array_length: 1000
    update_pattern: "counter"   # "counter", "static", "random", "sawtooth"

  - name: "realval"
    type: "REAL"
    array_length: 1
    update_pattern: "sine"

# Optional: tag namespace used for logging / client convenience
tag_namespace: "Program:MainProgram"
```

### 3.2 Go Structs (Server-Side)

Minimal struct outlines:

```go
type ServerConfig struct {
    Server struct {
        Name        string `yaml:"name"`
        Personality string `yaml:"personality"` // "adapter" or "logix_like"`
        TCPPort     int    `yaml:"tcp_port"`
        UDPIOPort   int    `yaml:"udp_io_port"`
    } `yaml:"server"`

    AdapterAssemblies []AdapterAssemblyConfig `yaml:"adapter_assemblies"`
    LogixTags         []LogixTagConfig        `yaml:"logix_tags"`
    TagNamespace      string                  `yaml:"tag_namespace"`
}

type AdapterAssemblyConfig struct {
    Name          string `yaml:"name"`
    Class         uint16 `yaml:"class"`
    Instance      uint16 `yaml:"instance"`
    Attribute     uint8  `yaml:"attribute"`
    SizeBytes     int    `yaml:"size_bytes"`
    Writable      bool   `yaml:"writable"`
    UpdatePattern string `yaml:"update_pattern"` // "counter", "static", "random", "reflect_inputs"
}

type LogixTagConfig struct {
    Name          string `yaml:"name"`
    Type          string `yaml:"type"`          // "BOOL", "SINT", "INT", "DINT", "REAL", etc.
    ArrayLength   int    `yaml:"array_length"`
    UpdatePattern string `yaml:"update_pattern"` // "counter", "static", "random", "sine", "sawtooth"
}
```

Validation:

- `Personality` must be `"adapter"` or `"logix_like"`.
- For `adapter`:
  - At least one `AdapterAssemblyConfig` should be defined.
- For `logix_like`:
  - At least one `LogixTagConfig` should be defined.
- Types and sizes should be internally consistent.

---

## 4. Server Architecture

Add a new `server` package to the Go project:

```go
package server

type Server interface {
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
}
```

Provide at least one implementation:

- `ENIPServer` – implements EtherNet/IP session handling and CIP service dispatch.

### 4.1 ENIP / CIP Handling (Server-Side)

The server should:

1. Listen on **TCP 44818** for new connections.
2. Handle ENIP commands:
   - `RegisterSession` / `UnregisterSession`.
   - `SendRRData` / `SendUnitData` (for explicit messaging).
3. Parse CIP requests from encapsulated ENIP payloads:
   - Extract service code, path, payload.
4. Dispatch requests to handlers depending on `personality`:
   - Adapter assembly handler.
   - Logix-like tag handler.

Error cases:

- Unknown services → respond with appropriate CIP error status.
- Invalid paths → CIP path error status.

---

## 5. Adapter Personality (CLICK-Compatible)

The **adapter** personality should emulate an **assembly-style adapter**:

- Recognize CIP paths for configured assemblies (class/instance/attribute).
- Respond to at least:
  - `Get_Attribute_Single` (0x0E).
  - `Set_Attribute_Single` (0x10) if `Writable == true`.
- Use `SizeBytes` to determine payload length.

### 5.1 Backing Data

For each `AdapterAssemblyConfig`, maintain an in-memory byte slice:

```go
type AdapterAssembly struct {
    Config AdapterAssemblyConfig
    Data   []byte
    mu     sync.RWMutex
}
```

Initially:

- For `update_pattern == "static"`: zero-filled or fixed pattern.
- For `update_pattern == "counter"`: increment a counter in the first 4 bytes at some periodic interval (e.g., in a background goroutine).
- For `update_pattern == "random"`: randomize bytes periodically.
- For `update_pattern == "reflect_inputs"`:
  - For output assemblies, mirror some or all bytes of one or more input assemblies.

### 5.2 CIP Behavior

- On `Get_Attribute_Single`:
  - Return `assembly.Data` (truncated or padded to `SizeBytes` if necessary).
- On `Set_Attribute_Single` (if writable):
  - Update `assembly.Data` with the incoming bytes.
- Unknown paths:
  - Return CIP status indicating path or attribute not supported.

This allows the **Go client** (or any other CIP client) to talk to the server in the same way it talks to the **CLICK**.

---

## 6. Logix-Like Personality (Tag Server)

The **logix_like** personality emulates a simple **ControlLogix-style tag server**:

### 6.1 Tag Model

Maintain a set of tags:

```go
type TagType int

const (
    TagBool TagType = iota
    TagSInt
    TagInt
    TagDInt
    TagReal
    // Extend if needed
)

type LogixTag struct {
    Config LogixTagConfig
    Type   TagType
    Data   interface{}   // e.g., []int32 for DINT, []float32 for REAL
    mu     sync.RWMutex
}
```

Support simple **update patterns**:

- `counter` – increment integer(s) each cycle.
- `static` – fixed values.
- `random` – random values within a sensible range.
- `sine` / `sawtooth` – floating point patterns for REAL tags.

### 6.2 Services to Support

The server should support at least:

- Standard CIP services for identity, etc., as needed.
- A **Logix-like tag read/write service model**, inspired by tag operations in typical Logix comms:
  - For example:
    - A vendor-specific service code for “Read Tag” / “Write Tag”, or
    - Emulate tag reads as reads from a configuration-specific class/instance model.

**Important:** We do **not** need to replicate the exact Rockwell proprietary service codes. The goal is:

- Provide **symbolic, tag-based access**:
  - CIP requests specify a tag name (e.g., `"tag_namespace:scada[10]"`).
  - Server parses tag name, index, and returns/updates the appropriate element(s).
- So that:
  - The Go client can implement a “tag mode” scenario later.
  - DPI products see traffic that looks like **tag services** (symbolic names, larger payloads, etc.), even if codes are not identical to Rockwell’s.

### 6.3 Path / Payload Format (Abstract)

In this addendum, you can let Cursor choose a concrete encoding. Requirements:

- Tag name and optional indices must be present in the CIP request.
- Server must:
  - Decode the tag name and index.
  - Map to `LogixTag` and element index.
  - Read/write values.
  - Encode response payload in a way the Go client can parse.

---

## 7. Client–Server Test Scenarios

With server mode implemented, your lab gains a **third major traffic source**:

1. **CLICK C2-03CPU** (real adapter)
2. **Go emulator** in `server` mode:
   - `personality=adapter`
   - `personality=logix_like`
3. **PCAP replay** (unchanged, handled by tcpreplay or similar)

### 7.1 Emulator Test Topology

```text
[ Go client mode ]  ----  [ Firewall ]  ----  [ Go server mode ]

        (baseline/mixed/stress/io/tag)     (adapter or logix_like personality)
```

You can run the same scenarios with:

- Target IP = CLICK  
- Target IP = Emulator (adapter personality)  
- Target IP = Emulator (logix_like personality)

This lets you:

- Compare firewall DPI behavior across:
  - Simple assembly-style device (CLICK).
  - Synthetic assembly device with more control (emulator adapter).
  - Synthetic tag-based “controller” (logix_like).
- Reuse the same logging / metrics infrastructure.

---

## 8. Logging & Metrics Additions

Add an optional **`target_type`** field to metrics (or infer it from config):

- `click` – when the target IP is the CLICK PLC.
- `emulator_adapter` – when server personality is adapter.
- `emulator_logix` – when server personality is logix_like.
- `pcap_replay` – for PCAP-based tests (if you log them separately).

Example CSV row:

```text
timestamp,scenario,target_type,operation,target_name,service_code,success,rtt_ms,status,error
2025-12-07T18:45:01.123Z,baseline,click,READ,InputBlock1,0x0E,true,2.5,0,
2025-12-07T18:45:01.223Z,mixed,emulator_adapter,WRITE,OutputAssembly1,0x10,true,1.8,0,
2025-12-07T18:45:01.323Z,stress,emulator_logix,READ,scada[10],0x??,false,,1,timeout
```

> Note: For logix-like services, `service_code` can be whatever you choose; the important thing is consistency in logging so you can filter and compare.

---

## 9. Summary

This v3 addendum:

- Adds **server/emulator mode** to the Go EtherNet/IP CIP tool.
- Introduces two **personalities**:
  - `adapter` – assembly-style emulation compatible with the CLICK.
  - `logix_like` – symbolic tag-style emulation, more ControlLogix-flavored.
- Allows the same binary to act as:
  - A client-side scanner.
  - A server-side emulator for more complex test setups.
- Integrates cleanly with the existing:
  - Scenarios (`baseline`, `mixed`, `stress`, `churn`, `io`).
  - IO/transport addenda (TCP 44818, UDP 2222, optional UDP 44818).
- Enables you to test DPI behavior against:
  - A real adapter (CLICK),
  - A flexible emulator (Go server),
  - And PCAP replay, giving you **three complementary sources of CIP traffic**.

Include this file with your existing `cursorrules` and specs so Cursor understands the combined client–server design and can implement a single binary that supports **both sides of your EtherNet/IP lab.**
