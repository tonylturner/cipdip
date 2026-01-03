# Configuration Guide

This guide explains how to configure CIPDIP client and server configuration files.

## Overview

CIPDIP uses YAML configuration files to define:
- **Client Config** (`cipdip_client.yaml`): CIP targets, I/O connections, and adapter settings for client/scanner mode
- **Server Config** (`cipdip_server.yaml`): Server personality, assemblies, tags, and network settings for server/emulator mode

Configuration files are loaded automatically from the current directory, or you can specify a custom path using `--config` or `--server-config` flags.

## Client Configuration (`cipdip_client.yaml`)

The client configuration file defines what CIP targets to read/write and how to connect to them.

### File Location

- **Default**: `cipdip_client.yaml` in the current directory
- **Custom**: Use `--config` flag: `cipdip client --config /path/to/config.yaml`

### Configuration Sections

#### 1. `adapter` Section

Defines the target CIP adapter/device information.

```yaml
adapter:
  name: "CLICK C2-03CPU"   # Human-friendly name (for logs only)
  port: 44818              # EtherNet/IP TCP port (default: 44818)
```

**Fields:**
- `name` (string, optional): Human-readable device name. Used only for logging and identification. Does not affect functionality.
- `port` (integer, optional): TCP port for EtherNet/IP explicit messaging. Default: `44818` if not specified.

**Example:**
```yaml
adapter:
  name: "Production PLC"
  port: 44818
```

#### 2. `protocol` Section

Controls strict ODVA compliance and optional vendor-variant behavior.

```yaml
protocol:
  mode: "strict_odva"        # "strict_odva", "vendor_variant", or "legacy_compat"
  variant: ""                # vendor preset name when mode=vendor_variant
  overrides:
    enip_endianness: "little"        # "little" or "big"
    cip_endianness: "little"         # "little" or "big"
    cip_path_size: true              # include path size byte in CIP requests
    cip_response_reserved: true      # include reserved/status-size fields in CIP responses
    use_cpf: true                    # encode CPF items for SendRRData/SendUnitData
    io_sequence_mode: "increment"    # "increment", "random", or "omit"
```

**Notes:**
- `mode: strict_odva` is the default and enforces ODVA-compliant framing.
- `vendor_variant` should be used with captured, validated deviations.
- `legacy_compat` preserves historical behavior for regression comparisons.
- Known vendor presets (if available): `rockwell_v32`, `schneider_m580`, `siemens_s7_1200`.

#### 2.1 `protocol_variants` Section

Optional list of protocol profiles used by the `vendor_variants` scenario.

```yaml
protocol_variants:
  - mode: "strict_odva"
  - mode: "vendor_variant"
    variant: "rockwell_v32"
  - mode: "vendor_variant"
    variant: "schneider_m580"
  - mode: "vendor_variant"
    variant: "pcap_capture"
  - mode: "vendor_variant"
    variant: "rockwell_enbt"     # use only when Vendor ID=0x0001 and Product Name=1756-ENBT/A
```

**Notes:**
- Each entry follows the same structure as `protocol`.
- Missing `mode` defaults to `vendor_variant`.

#### 2.2 `cip_profiles` Section

Optional CIP application profiles to include in coverage and CLI-driven target generation.

```yaml
cip_profiles:
  - "energy"
  - "safety"
  - "motion"
  # - "all"
```

**Notes:**
- Supported profiles: `energy`, `safety`, `motion`, or `all`.
- `all` expands to `energy`, `safety`, and `motion`.
- Use `--cip-profile` on the CLI to override or add profiles without editing YAML.
- CIPDIP also includes a broader baseline class set when profiles are enabled, covering File Object, Event Log, Time Sync, Modbus, and Symbol/Template classes.
- For classes with limited public payload layouts, CIPDIP uses conservative `Get_Attribute_Single` probes or minimal request payloads. Use `custom_targets` for explicit payload control.

#### 2.3 `cip_profile_classes` Section

Optional profile class overrides (use hex class IDs).

```yaml
cip_profile_classes:
  energy:
    - 0x004E # Base Energy Object
    - 0x004F # Electrical Energy Object
    - 0x0050 # Non-Electrical Energy Object
    - 0x0053 # Power Management Object
```

**Notes:**
- Overrides take precedence over built-in defaults for a profile.
- Useful when you need to align vendor profiles to specific application classes.
- Profile auto-targets are adjusted for some classes based on public evidence. You can override or disable by providing your own `custom_targets`.

#### 2.4 Profile Auto-Targets (evidence-based defaults)

When `cip_profiles` is enabled, CIPDIP creates additional `custom_targets` for classes where public sources limit safe defaults. These are intended to confirm DPI behavior without relying on unpublished ODVA layouts.

Current defaults:
- **File Object (0x37):** `Get_Attribute_Single` instance 0 attr 0x02 (Max Instance)
- **Event Log (0x41):** `Get_Attribute_Single` instance 0 attr 0x20 (Time Format)
- **Time Sync (0x43):** `Get_Attribute_Single` instance 1 attr 0x01 (PTP Enable)
- **Modbus (0x44):** `Read Holding Registers` (service 0x4E) instance 1 payload `00000100` (start=0x0000, qty=0x0001)
- **Motion Axis (0x42):** `Get Axis Attributes List` (service 0x4B) instance 1
- **Safety Supervisor (0x39):** `Get_Attribute_Single` instance 1 attr 0x0B (Device Status)
- **Safety Validator (0x3A):** `Get_Attribute_Single` instance 1 attr 0x01 (Validator State)

If you need vendor-specific payloads (e.g., File Transfer, Modbus writes, Safety Reset), add `custom_targets` with `request_payload_hex`.

#### 3. `read_targets` Section

Defines CIP paths to read using Get Attribute Single service.

```yaml
read_targets:
  - name: "InputBlock1"
    service: "get_attribute_single"
    class: 0x04
    instance: 0x65
    attribute: 0x03
```

**Fields (per target):**
- `name` (string, required): Unique identifier for this target. Used in logs and metrics.
- `service` (string, required): Must be `"get_attribute_single"` for read targets.
- `class` (hex integer, required): CIP class ID (e.g., `0x04` for Assembly class).
- `instance` (hex integer, required): CIP instance ID within the class.
- `attribute` (hex integer, required): CIP attribute ID to read.
- `tags` (list of strings, optional): Labels used to select targets for specific scenarios (e.g., firewall packs).

**Example:**
```yaml
read_targets:
  - name: "InputAssembly1"
    service: "get_attribute_single"
    class: 0x04
    instance: 0x65
    attribute: 0x03

  - name: "InputAssembly2"
    service: "get_attribute_single"
    class: 0x04
    instance: 0x66
    attribute: 0x03
```

**Notes:**
- Used by `baseline`, `mixed`, and `stress` scenarios.
- Values are read periodically based on scenario interval.
- Results are logged and included in metrics.

#### 4. `write_targets` Section

Defines CIP paths to write using Set Attribute Single service.

```yaml
write_targets:
  - name: "OutputBlock1"
    service: "set_attribute_single"
    class: 0x04
    instance: 0x67
    attribute: 0x03
    pattern: "increment"        # "increment", "toggle", or "constant"
    initial_value: 0
```

**Fields (per target):**
- `name` (string, required): Unique identifier for this target.
- `service` (string, required): Must be `"set_attribute_single"` for write targets.
- `class` (hex integer, required): CIP class ID.
- `instance` (hex integer, required): CIP instance ID.
- `attribute` (hex integer, required): CIP attribute ID to write.
- `pattern` (string, optional): Write pattern:
  - `"increment"`: Value increments by 1 each write
  - `"toggle"`: Value alternates between 0 and 1
  - `"constant"`: Value remains at `initial_value`
- `initial_value` (integer, optional): Starting value for the pattern. Default: `0`.
- `tags` (list of strings, optional): Labels used to select targets for specific scenarios (e.g., firewall packs).

**Example:**
```yaml
write_targets:
  - name: "OutputAssembly1"
    service: "set_attribute_single"
    class: 0x04
    instance: 0x67
    attribute: 0x03
    pattern: "increment"
    initial_value: 0

  - name: "OutputAssembly2"
    service: "set_attribute_single"
    class: 0x04
    instance: 0x68
    attribute: 0x03
    pattern: "toggle"
    initial_value: 0
```

**Notes:**
- Used by `mixed` scenario (alternates with reads).
- Write patterns help generate predictable, repeatable traffic.
- Ensure target device supports writes to these paths.

#### 5. `custom_targets` Section

Defines custom CIP services with arbitrary service codes and payloads.

```yaml
custom_targets:
  - name: "CustomServiceExample"
    service: "custom"
    service_code: 0x01          # CIP service code
    class: 0x01                 # CIP class
    instance: 0x01              # CIP instance
    attribute: 0x00             # May be unused depending on service
    request_payload_hex: ""      # Raw hex string for request body (optional)
```

**Fields (per target):**
- `name` (string, required): Unique identifier for this target.
- `service` (string, required): Must be `"custom"` for custom targets.
- `service_code` (hex integer, required): CIP service code (e.g., `0x01` for Get_Attribute_All, `0x03` for Get_Attribute_List).
- `class` (hex integer, required): CIP class ID.
- `instance` (hex integer, required): CIP instance ID.
- `attribute` (hex integer, optional): CIP attribute ID (may be unused depending on service).
- `request_payload_hex` (string, optional): Raw hexadecimal string for additional request payload. Leave empty if not needed.
- `tags` (list of strings, optional): Labels used to select targets for specific scenarios (e.g., firewall packs).

**Example:**
```yaml
custom_targets:
  - name: "GetAttributeAll"
    service: "custom"
    service_code: 0x01          # Get_Attribute_All
    class: 0x01                 # Identity class
    instance: 0x01
    attribute: 0x00
    request_payload_hex: ""

  - name: "CustomService"
    service: "custom"
    service_code: 0x03          # Get_Attribute_List
    class: 0x04
    instance: 0x65
    attribute: 0x00
    request_payload_hex: "0002"  # Attribute count = 2
```

**Notes:**
- Used for testing non-standard services or vendor-specific extensions.
- Requires knowledge of CIP service codes and payload formats.
- Useful for DPI testing of edge cases.

#### 6. `edge_targets` Section

Defines protocol-valid edge case requests for DPI falsification.

```yaml
edge_targets:
  - name: "Class16_Instance8_Attr8"
    service: "get_attribute_single"
    class: 0x0100
    instance: 0x65
    attribute: 0x03
    expected_outcome: "success"
  - name: "Class8_Instance16_Attr16"
    service: "get_attribute_single"
    class: 0x04
    instance: 0x0100
    attribute: 0x0100
    expected_outcome: "success"
  - name: "InvalidClass_Error"
    service: "get_attribute_single"
    class: 0xFFFF
    instance: 0x0001
    attribute: 0x0001
    expected_outcome: "error"
    force_status: 0x01          # optional metrics override for unconnected_send
  - name: "PCAP_Class0067_Path"
    service: "get_attribute_single"
    class: 0x0067
    instance: 0x0001
    attribute: 0x0000
    expected_outcome: "any"
  - name: "PCAP_Class00A1_Path"
    service: "get_attribute_single"
    class: 0x00A1
    instance: 0x0001
    attribute: 0x0000
    expected_outcome: "any"
  - name: "PCAP_Unknown_0x4B"
    service: "custom"
    service_code: 0x4B
    class: 0x0067
    instance: 0x0001
    attribute: 0x0000
    expected_outcome: "any"
  - name: "PCAP_Unknown_0x4D"
    service: "custom"
    service_code: 0x4D
    class: 0x00A1
    instance: 0x0001
    attribute: 0x0000
    expected_outcome: "any"
  - name: "PCAP_Unknown_0x52"
    service: "custom"
    service_code: 0x52
    class: 0x0067
    instance: 0x0001
    attribute: 0x0000
    expected_outcome: "any"
  - name: "PCAP_Unknown_0x51"
    service: "custom"
    service_code: 0x51
    class: 0x00A1
    instance: 0x0001
    attribute: 0x0000
    expected_outcome: "any"
  - name: "Rockwell_Read_Tag"
    service: "custom"
    service_code: 0x4C
    class: 0x0067
    instance: 0x0001
    attribute: 0x0000
    expected_outcome: "any"
  - name: "Rockwell_Write_Tag"
    service: "custom"
    service_code: 0x4D
    class: 0x0067
    instance: 0x0001
    attribute: 0x0000
    expected_outcome: "any"
  - name: "Rockwell_Read_Tag_Fragmented"
    service: "custom"
    service_code: 0x52
    class: 0x0067
    instance: 0x0001
    attribute: 0x0000
    expected_outcome: "any"
  - name: "Rockwell_Write_Tag_Fragmented"
    service: "custom"
    service_code: 0x53
    class: 0x0067
    instance: 0x0001
    attribute: 0x0000
    expected_outcome: "any"
  - name: "ConnMgr_Get_Connection_Data"
    service: "custom"
    service_code: 0x56
    class: 0x0006
    instance: 0x0001
    attribute: 0x0000
    expected_outcome: "any"
  - name: "ConnMgr_Search_Connection_Data"
    service: "custom"
    service_code: 0x57
    class: 0x0006
    instance: 0x0001
    attribute: 0x0000
    expected_outcome: "any"
  - name: "ConnMgr_Get_Connection_Owner"
    service: "custom"
    service_code: 0x5A
    class: 0x0006
    instance: 0x0001
    attribute: 0x0000
    expected_outcome: "any"
  - name: "ConnMgr_Large_Forward_Open"
    service: "custom"
    service_code: 0x5B
    class: 0x0006
    instance: 0x0001
    attribute: 0x0000
    expected_outcome: "any"
```

**Fields (per target):**
- `name` (string, required): Unique identifier for this edge case.
- `service` (string, required): `get_attribute_single`, `set_attribute_single`, or `custom`.
- `service_code` (hex integer, required for `custom`): CIP service code.
- `class` / `instance` / `attribute` (hex integer, required): CIP path segments.
- `request_payload_hex` (string, optional): Hex-encoded payload.
- `expected_outcome` (string, optional): `success`, `error`, `timeout`, or `any`.
- `force_status` (hex integer, optional): Override status used for metrics in `unconnected_send` (does not change on-wire response).
- `tags` (list of strings, optional): Labels used to select targets for specific scenarios (e.g., firewall packs).

**Notes:**
- Used by the `edge_valid` and `unconnected_send` scenarios.
- Use 16-bit values to force 16-bit EPATH segments.

#### 7. `scenario_jitter_ms` Section

Optional per-operation jitter (milliseconds) injected into edge cases and mixed-state traffic.

```yaml
scenario_jitter_ms: 5
```

#### 8. `io_connections` Section

Defines connected Class 1 I/O connections for the `io` scenario.

```yaml
io_connections:
  - name: "IOConn1"
    transport: "udp"             # "udp" (default) or "tcp"
    o_to_t_rpi_ms: 20           # Requested Packet Interval (originator to target)
    t_to_o_rpi_ms: 20           # Requested Packet Interval (target to originator)
    o_to_t_size_bytes: 8         # Size of O->T connection data (bytes)
    t_to_o_size_bytes: 8         # Size of T->O connection data (bytes)
    priority: "scheduled"        # "low", "high", "urgent", or "scheduled"
    transport_class_trigger: 3    # CIP transport class; 1, 2, or 3
    class: 0x04                  # Logical CIP path to the target object or assembly
    instance: 0x65
    connection_path_hex: ""      # Optional raw hex path if needed for complex routing
```

**Fields (per connection):**
- `name` (string, required): Unique identifier for this I/O connection.
- `transport` (string, optional): Transport protocol for I/O data:
  - `"udp"` (default): UDP port 2222 for Class 1 I/O (implicit messaging)
  - `"tcp"`: TCP port 44818 (explicit messaging over existing connection)
- `o_to_t_rpi_ms` (integer, required): Requested Packet Interval in milliseconds for originator-to-target data. Must be > 0.
- `t_to_o_rpi_ms` (integer, required): Requested Packet Interval in milliseconds for target-to-originator data. Must be > 0.
- `o_to_t_size_bytes` (integer, required): Size in bytes of originator-to-target connection data. Must be > 0.
- `t_to_o_size_bytes` (integer, required): Size in bytes of target-to-originator connection data. Must be > 0.
- `priority` (string, required): Connection priority:
  - `"low"`: Low priority
  - `"high"`: High priority
  - `"urgent"`: Urgent priority
  - `"scheduled"`: Scheduled priority (typical for cyclic I/O)
- `transport_class_trigger` (integer, required): CIP transport class trigger. Must be 1, 2, or 3:
  - `1`: Cyclic (most common for I/O)
  - `2`: Change of state
  - `3`: Application object
- `class` (hex integer, required): CIP class ID for the target assembly/object.
- `instance` (hex integer, required): CIP instance ID for the target assembly/object.
- `connection_path_hex` (string, optional): Raw hexadecimal connection path for complex routing. Leave empty for simple paths.
- `tags` (list of strings, optional): Labels used to select connections for specific scenarios (e.g., firewall packs).

**Example:**
```yaml
io_connections:
  - name: "InputIO"
    transport: "udp"
    o_to_t_rpi_ms: 20
    t_to_o_rpi_ms: 20
    o_to_t_size_bytes: 8
    t_to_o_size_bytes: 8
    priority: "scheduled"
    transport_class_trigger: 3
    class: 0x04
    instance: 0x65

  - name: "OutputIO"
    transport: "udp"
    o_to_t_rpi_ms: 10
    t_to_o_rpi_ms: 10
    o_to_t_size_bytes: 16
    t_to_o_size_bytes: 16
    priority: "scheduled"
    transport_class_trigger: 1
    class: 0x04
    instance: 0x67
```

**Notes:**
- Required for the `io` scenario.
- ForwardOpen/ForwardClose (control plane) always uses TCP 44818.
- I/O data (SendIOData/ReceiveIOData) uses the specified transport (UDP 2222 or TCP 44818).
- RPI values typically range from 10-100ms for most devices.
- Connection sizes are usually 8, 16, 32, or 64 bytes.
- Transport class trigger 1 or 3 is typical for cyclic I/O.

### Complete Client Config Example

```yaml
adapter:
  name: "CLICK C2-03CPU"
  port: 44818

protocol:
  mode: "strict_odva"
  overrides:
    use_cpf: true

read_targets:
  - name: "InputBlock1"
    service: "get_attribute_single"
    class: 0x04
    instance: 0x65
    attribute: 0x03

write_targets:
  - name: "OutputBlock1"
    service: "set_attribute_single"
    class: 0x04
    instance: 0x67
    attribute: 0x03
    pattern: "increment"
    initial_value: 0

io_connections:
  - name: "IOConn1"
    transport: "udp"
    o_to_t_rpi_ms: 20
    t_to_o_rpi_ms: 20
    o_to_t_size_bytes: 8
    t_to_o_size_bytes: 8
    priority: "scheduled"
    transport_class_trigger: 3
    class: 0x04
    instance: 0x65
```

### Client Config Validation

The following rules apply:
- At least one of `read_targets`, `write_targets`, `custom_targets`, or `edge_targets` must be populated.
- All targets must have a `name` and `service`.
- Custom targets must have a `service_code` when `service` is `"custom"`.
- Edge targets must have a `service_code` when `service` is `"custom"`.
- `protocol_variants` entries must use valid `mode` and optional `variant`.
- I/O connections must have all required fields with valid values (RPI > 0, sizes > 0, etc.).

## Server Configuration (`cipdip_server.yaml`)

The server configuration file defines how the CIPDIP emulator behaves and what data it exposes.

### File Location

- **Default**: `cipdip_server.yaml` in the current directory
- **Custom**: Use `--server-config` flag: `cipdip server --server-config /path/to/config.yaml`

### Configuration Sections

#### 1. `server` Section

Defines server network settings and personality.

```yaml
server:
  name: "Go CIP Emulator"
  personality: "adapter"        # "adapter" or "logix_like"
  listen_ip: "0.0.0.0"          # IP address to bind to
  tcp_port: 44818               # TCP port for explicit messaging
  udp_io_port: 2222             # UDP port for I/O (optional, used if enable_udp_io is true)
  enable_udp_io: false          # Enable UDP I/O server on port 2222
  connection_timeout_ms: 10000  # I/O connection inactivity timeout (ms)
  rng_seed: 0                   # RNG seed (0 = time-based) for deterministic personalities
  identity_vendor_id: 0x0000        # Identity Object Attribute 1
  identity_device_type: 0x0000      # Identity Object Attribute 2
  identity_product_code: 0x0000     # Identity Object Attribute 3
  identity_rev_major: 1             # Identity Object Attribute 4 (major)
  identity_rev_minor: 0             # Identity Object Attribute 4 (minor)
  identity_status: 0x0000           # Identity Object Attribute 5
  identity_serial: 0x00000000       # Identity Object Attribute 6
  identity_product_name: "Go CIP Emulator" # Identity Object Attribute 7 (short string)
```

**Fields:**
- `name` (string, optional): Server name for logging. Default: `"Go CIP Emulator"`.
- `personality` (string, required): Server personality type:
  - `"adapter"`: Assembly-style object model (like CLICK PLCs)
  - `"logix_like"`: Tag-based interface (like Allen-Bradley Logix controllers)
- `listen_ip` (string, optional): IP address to bind the server to. Default: `"0.0.0.0"` (all interfaces).
- `tcp_port` (integer, optional): TCP port for explicit messaging. Default: `44818`.
- `udp_io_port` (integer, optional): UDP port for Class 1 I/O. Default: `2222`.
- `enable_udp_io` (boolean, optional): Enable UDP I/O server. Default: `false`.
- `connection_timeout_ms` (integer, optional): I/O connection inactivity timeout in milliseconds. Default: `10000`.
- `rng_seed` (integer, optional): Seed for deterministic random data patterns. Default: `0` (time-based).
- `identity_vendor_id` (hex integer, optional): Identity Object attribute 1 (Vendor ID).
- `identity_device_type` (hex integer, optional): Identity Object attribute 2 (Device Type).
- `identity_product_code` (hex integer, optional): Identity Object attribute 3 (Product Code).
- `identity_rev_major` (integer, optional): Identity Object attribute 4 (Major Revision).
- `identity_rev_minor` (integer, optional): Identity Object attribute 4 (Minor Revision).
- `identity_status` (hex integer, optional): Identity Object attribute 5 (Status).
- `identity_serial` (hex integer, optional): Identity Object attribute 6 (Serial Number).
- `identity_product_name` (string, optional): Identity Object attribute 7 (Product Name, short string).

**Example:**
```yaml
server:
  name: "Test Emulator"
  personality: "adapter"
  listen_ip: "0.0.0.0"
  tcp_port: 44818
  udp_io_port: 2222
  enable_udp_io: true
```

**Notes:**
- `listen_ip` can be set to a specific IP (e.g., `"192.168.1.100"`) to bind to one interface.
- `enable_udp_io` must be `true` for the `io` scenario to work with UDP 2222.
- CLI flags (`--listen-ip`, `--listen-port`, `--enable-udp-io`) override config file values.
- Identity Object attributes apply to Get_Attribute_Single and Get_Attribute_All requests to Class 0x01, Instance 0x01.

#### 2. `protocol` Section

Same structure as the client `protocol` section; controls protocol framing for server responses.

```yaml
protocol:
  mode: "strict_odva"
  variant: ""
  overrides:
    enip_endianness: "little"
    cip_endianness: "little"
    cip_path_size: true
    cip_response_reserved: true
    use_cpf: true
    io_sequence_mode: "increment"

cip_profiles:
  - "energy"
  - "safety"
  - "motion"

cip_profile_classes:
  energy:
    - 0x004E # Base Energy Object
    - 0x004F # Electrical Energy Object
    - 0x0050 # Non-Electrical Energy Object
    - 0x0053 # Power Management Object
```

#### 3. `adapter_assemblies` Section

Defines assembly objects for adapter personality. Only used when `personality: "adapter"`.

```yaml
adapter_assemblies:
  - name: "InputAssembly1"
    class: 0x04
    instance: 0x65
    attribute: 0x03
    size_bytes: 16
    update_pattern: "counter"   # "counter", "static", "random", or "reflect_inputs"
    writable: false
```

**Fields (per assembly):**
- `name` (string, required): Unique identifier for this assembly.
- `class` (hex integer, required): CIP class ID (typically `0x04` for Assembly class).
- `instance` (hex integer, required): CIP instance ID.
- `attribute` (hex integer, required): CIP attribute ID (typically `0x03` for data).
- `size_bytes` (integer, required): Size of assembly data in bytes.
- `update_pattern` (string, required): How the assembly data updates:
  - `"counter"`: Data increments continuously
  - `"static"`: Data remains constant
  - `"random"`: Data changes randomly
  - `"reflect_inputs"`: Data reflects written values (for writable assemblies)
- `writable` (boolean, required): Whether clients can write to this assembly.

**Example:**
```yaml
adapter_assemblies:
  - name: "InputAssembly1"
    class: 0x04
    instance: 0x65
    attribute: 0x03
    size_bytes: 16
    update_pattern: "counter"
    writable: false

  - name: "OutputAssembly1"
    class: 0x04
    instance: 0x67
    attribute: 0x03
    size_bytes: 16
    update_pattern: "reflect_inputs"
    writable: true
```

**Notes:**
- At least one assembly is required when `personality: "adapter"`.
- Assemblies respond to Get/Set Attribute Single requests.
- Writable assemblies with `"reflect_inputs"` pattern echo back written values.

#### 4. `logix_tags` Section

Defines tags for logix_like personality. Only used when `personality: "logix_like"`.

```yaml
logix_tags:
  - name: "scada"
    type: "DINT"                 # "BOOL", "SINT", "INT", "DINT", "REAL", etc.
    array_length: 1000
    update_pattern: "counter"    # "counter", "static", "random", "sawtooth", or "sine"
```

**Fields (per tag):**
- `name` (string, required): Tag name (e.g., `"scada"`, `"temperature"`).
- `type` (string, required): Tag data type:
  - `"BOOL"`: Boolean (1 bit)
  - `"SINT"`: Signed 8-bit integer
  - `"INT"`: Signed 16-bit integer
  - `"DINT"`: Signed 32-bit integer
  - `"REAL"`: 32-bit floating point
  - Other types may be supported
- `array_length` (integer, required): Array length (use `1` for scalar tags).
- `update_pattern` (string, required): How the tag value updates:
  - `"counter"`: Value increments
  - `"static"`: Value remains constant
  - `"random"`: Value changes randomly
  - `"sawtooth"`: Value increases then resets (waveform)
  - `"sine"`: Value follows sine wave (for REAL types)

**Example:**
```yaml
logix_tags:
  - name: "scada"
    type: "DINT"
    array_length: 1000
    update_pattern: "counter"

  - name: "temperature"
    type: "REAL"
    array_length: 1
    update_pattern: "sine"

  - name: "status"
    type: "BOOL"
    array_length: 1
    update_pattern: "static"
```

**Notes:**
- At least one tag is required when `personality: "logix_like"`.
- Tags respond to tag read/write requests.
- Array tags can be indexed (e.g., `scada[0]`, `scada[1]`).

#### 5. `tag_namespace` Section

Optional namespace prefix for logix_like tags.

```yaml
tag_namespace: "Program:MainProgram"
```

**Fields:**
- `tag_namespace` (string, optional): Namespace prefix for tags (e.g., `"Program:MainProgram"`). Used for logging and client convenience.

**Example:**
```yaml
tag_namespace: "Program:MainProgram"
```

**Notes:**
- Only used with `logix_like` personality.
- Does not affect functionality, only logging/display.

### Complete Server Config Examples

#### Adapter Personality

```yaml
server:
  name: "CLICK Emulator"
  personality: "adapter"
  listen_ip: "0.0.0.0"
  tcp_port: 44818
  udp_io_port: 2222
  enable_udp_io: true

protocol:
  mode: "strict_odva"

adapter_assemblies:
  - name: "InputAssembly1"
    class: 0x04
    instance: 0x65
    attribute: 0x03
    size_bytes: 16
    update_pattern: "counter"
    writable: false

  - name: "OutputAssembly1"
    class: 0x04
    instance: 0x67
    attribute: 0x03
    size_bytes: 16
    update_pattern: "reflect_inputs"
    writable: true
```

#### Logix-Like Personality

```yaml
server:
  name: "Logix Emulator"
  personality: "logix_like"
  listen_ip: "0.0.0.0"
  tcp_port: 44818
  udp_io_port: 2222
  enable_udp_io: false

protocol:
  mode: "strict_odva"

logix_tags:
  - name: "scada"
    type: "DINT"
    array_length: 1000
    update_pattern: "counter"

  - name: "temperature"
    type: "REAL"
    array_length: 1
    update_pattern: "sine"

tag_namespace: "Program:MainProgram"
```

### Server Config Validation

The following rules apply:
- `personality` must be `"adapter"` or `"logix_like"`.
- If `personality: "adapter"`, at least one `adapter_assemblies` entry is required.
- If `personality: "logix_like"`, at least one `logix_tags` entry is required.
- All required fields must be present and valid.

## Configuration Tips

### Finding CIP Paths

To configure client targets, you need to know the CIP paths (class/instance/attribute):

1. **Device Documentation**: Check your device's EtherNet/IP documentation for object model.
2. **Discovery**: Use `cipdip discover` to find devices, but paths still need documentation.
3. **Common Paths**:
   - Assembly class: `class: 0x04`
   - Common instances: `0x65`, `0x66`, `0x67`, `0x68` (varies by device)
   - Data attribute: `attribute: 0x03`

### I/O Connection Parameters

For I/O connections, typical values are:

- **RPI**: 10-100ms (20ms is common)
- **Connection Sizes**: 8, 16, 32, or 64 bytes (check device documentation)
- **Transport Class**: 1 or 3 for cyclic I/O
- **Priority**: `"scheduled"` for most I/O

### Testing Configurations

1. **Start with Simple Config**: Begin with one read target to verify connectivity.
2. **Test Connectivity First**: Use `cipdip test --ip <device-ip>` before running scenarios.
3. **Use Verbose Logging**: Add `--verbose` to see detailed operation logs.
4. **Validate Config**: The tool validates config on load and reports errors.

## Common Issues

### "at least one of read_targets, write_targets, custom_targets, or edge_targets must be populated"

**Solution**: Add at least one target to your client config.

### "io_connections[0]: transport must be 'udp' or 'tcp'"

**Solution**: Set `transport: "udp"` or `transport: "tcp"` in your I/O connection config.

### "adapter_assemblies must have at least one entry when personality is 'adapter'"

**Solution**: Add at least one assembly to your server config when using adapter personality.

### Invalid CIP Paths

**Symptoms**: Requests fail with CIP error codes.

**Solution**: Verify class/instance/attribute values match your device's object model. Check device documentation.

## See Also

- `configs/cipdip_client.yaml.example` - Example client configuration
- `configs/cipdip_server.yaml.example` - Example server configuration
- `docs/TROUBLESHOOTING.md` - Troubleshooting guide
- `docs/HARDWARE_SETUP.md` - Hardware setup guide
- `docs/EXAMPLES.md` - Usage examples

