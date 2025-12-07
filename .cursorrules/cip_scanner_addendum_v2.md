# Addendum v2: Transport Coverage (UDP 2222, UDP 44818) for Go EtherNet/IP Scanner

This short addendum is meant to be **appended to the existing CIP scanner addendum**. It clarifies which EtherNet/IP transports the tool should support and how they map to the scenarios, especially the `io` (I/O-style) scenario.

You can paste this into the end of the existing `cip_scanner_addendum.md` or keep it as a separate rule.

---

## 8. Transport Coverage Requirements

The scanner shall explicitly support the following EtherNet/IP transports:

1. **TCP 44818** – Explicit Messaging  
   - Used for:
     - UCMM / unconnected explicit messaging (e.g., `SendRRData`).
     - Connected explicit messaging (e.g., `SendUnitData` after `ForwardOpen`).
   - Already required in the main spec and first addendum.

2. **UDP 2222** – Class 1 I/O (Implicit Messaging)  
   - Must be supported for **I/O-style cyclic data** in the `io` scenario.
   - Originator-to-Target (O→T) and Target-to-Originator (T→O) payloads should be carried via UDP 2222 using appropriate EtherNet/IP encapsulation.
   - This is the **primary transport** for I/O traffic in the `io` scenario.

3. **UDP 44818** – Discovery (Optional but Recommended)  
   - Recommended to support **ListIdentity** discovery:
     - Send `ListIdentity` as a broadcast/multicast to UDP 44818.
     - Log discovered devices (IP, product name, vendor ID, etc.).
   - Can be implemented as:
     - A small helper function, or
     - An optional `discovery` scenario (e.g., `--scenario discovery`).

4. **TCP 2222** – Optional  
   - Some implementations may support Class 1-like traffic over TCP 2222.
   - Support for TCP 2222 is **optional**; if implemented, it should reuse the same I/O abstraction as UDP 2222, with the transport configured via `io_connections` config.

---

## 9. Config Extension for Transport Selection (IO Scenario)

Extend `IOConnectionConfig` with a `transport` field:

```yaml
io_connections:
  - name: "IOConn1"
    transport: "udp"          # "udp" (default) or "tcp"
    o_to_t_rpi_ms: 20
    t_to_o_rpi_ms: 20
    o_to_t_size_bytes: 8
    t_to_o_size_bytes: 8
    priority: "scheduled"
    transport_class_trigger: 3
    class: 0x04
    instance: 0x65
```

Go struct update:

```go
type IOConnectionConfig struct {
    Name                 string `yaml:"name"`
    Transport            string `yaml:"transport"`             // "udp" (default) or "tcp"
    OToTRPIMs            int    `yaml:"o_to_t_rpi_ms"`
    TToORPIMs            int    `yaml:"t_to_o_rpi_ms"`
    OToTSizeBytes        int    `yaml:"o_to_t_size_bytes"`
    TToOSizeBytes        int    `yaml:"t_to_o_size_bytes"`
    Priority             string `yaml:"priority"`
    TransportClassTrigger int   `yaml:"transport_class_trigger"`
    Class                uint16 `yaml:"class"`
    Instance             uint16 `yaml:"instance"`
    ConnectionPathHex    string `yaml:"connection_path_hex,omitempty"`
}
```

Validation:

- If `Transport` is empty, treat as `"udp"`.
- Only `"udp"` and `"tcp"` are valid; any other value should cause a config validation error.

---

## 10. Client Behavior for IO Transports

The `Client` implementation should:

- For **UDP 2222 (transport == "udp")**:
  - Create and manage a UDP socket bound to an appropriate local port.
  - Send O→T I/O data to the target’s UDP 2222.
  - Receive T→O I/O data from the target on the same socket.
  - Ensure payload lengths match `OToTSizeBytes` / `TToOSizeBytes`.

- For **TCP 2222 (transport == "tcp")** (if implemented):
  - Establish a TCP connection to target:2222 per I/O connection or share one connection as appropriate.
  - Use similar framing semantics as UDP I/O payloads, encapsulated in EtherNet/IP, as supported by the device under test.

The `io` scenario logic remains the same; it delegates transport details to the `Client` based on `IOConnectionConfig.Transport`.

---

## 11. Optional Discovery Helper (UDP 44818)

Add an optional helper or scenario to send `ListIdentity` requests:

- **Helper function** (example):

  ```go
  func DiscoverDevices(ctx context.Context, logger *log.Logger, iface string, timeout time.Duration) ([]DiscoveredDevice, error)
  ```

- **Behavior:**
  - Open a UDP socket on the desired interface.
  - Broadcast a `ListIdentity` request to UDP 44818.
  - Collect responses until `timeout`.
  - Return a slice of `DiscoveredDevice` structs containing IP, identity, and product information.

This discovery capability is not mandatory for the core DPI test scenarios, but it is useful in your lab to:

- Verify device presence.
- See how the firewalls treat EtherNet/IP discovery traffic.

---

By incorporating this addendum, the Go scanner will:

- Exercise **explicit messaging over TCP 44818**.
- Exercise **Class 1 I/O cyclic traffic over UDP 2222**, which is critical for realistic PLC/adaptor flows.
- Optionally exercise **UDP 44818 discovery traffic**, giving you broader coverage of EtherNet/IP behaviors relevant to DPI firewalls.
