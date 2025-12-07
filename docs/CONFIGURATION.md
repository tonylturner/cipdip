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

#### 2. `read_targets` Section

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

#### 3. `write_targets` Section

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

#### 4. `custom_targets` Section

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
- `service_code` (hex integer, required): CIP service code (e.g., `0x01` for Get_Attribute_All, `0x0E` for Get_Attribute_List).
- `class` (hex integer, required): CIP class ID.
- `instance` (hex integer, required): CIP instance ID.
- `attribute` (hex integer, optional): CIP attribute ID (may be unused depending on service).
- `request_payload_hex` (string, optional): Raw hexadecimal string for additional request payload. Leave empty if not needed.

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
    service_code: 0x0E          # Get_Attribute_List
    class: 0x04
    instance: 0x65
    attribute: 0x00
    request_payload_hex: "0002"  # Attribute count = 2
```

**Notes:**
- Used for testing non-standard services or vendor-specific extensions.
- Requires knowledge of CIP service codes and payload formats.
- Useful for DPI testing of edge cases.

#### 5. `io_connections` Section

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
- At least one of `read_targets`, `write_targets`, or `custom_targets` must be populated.
- All targets must have a `name` and `service`.
- Custom targets must have a `service_code` when `service` is `"custom"`.
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

#### 2. `adapter_assemblies` Section

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

#### 3. `logix_tags` Section

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
    update_pattern: "toggle"
```

**Notes:**
- At least one tag is required when `personality: "logix_like"`.
- Tags respond to tag read/write requests.
- Array tags can be indexed (e.g., `scada[0]`, `scada[1]`).

#### 4. `tag_namespace` Section

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

### "at least one of read_targets, write_targets, or custom_targets must be populated"

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

