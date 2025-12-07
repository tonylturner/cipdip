# Test Coverage Gaps

## Current Test Coverage ✅

- **CIP Client Core**: ✅ Comprehensive
  - CIP encoding/decoding (`cip_test.go`)
  - ENIP encapsulation (`enip_test.go`)
  - Response parsing (`response_test.go`)
  - Transport layer (`transport_test.go`)
  - Compliance tests (`compliance_test.go`, `compliance_audit_test.go`)
  - Integration tests (`integration_test.go` - disabled by default)

- **PCAP Analysis**: ✅ Complete
  - Packet analysis (`analyzer_test.go`)
  - Hex dump utilities (`hexdump_test.go`)

- **Configuration**: ✅ Basic
  - Config loading (`config_test.go`)

## Missing Test Coverage ❌

### High Priority

1. **Server Tests** (`internal/server/`)
   - `server_test.go`: Server lifecycle, session management, request handling
   - `adapter_test.go`: Adapter personality behavior (assembly reads/writes)
   - `logix_test.go`: Logix-like personality behavior (tag access)
   - Test cases:
     - Server startup/shutdown
     - Session registration/unregistration
     - Multiple concurrent sessions
     - CIP request handling (Get/Set Attribute Single)
     - Error responses (invalid paths, missing assemblies)
     - Assembly update patterns (counter, static, random, reflect_inputs)

2. **Scenario Tests** (`internal/scenario/`)
   - `baseline_test.go`: Baseline scenario execution
   - `mixed_test.go`: Mixed scenario (reads + writes)
   - `stress_test.go`: Stress scenario (high frequency)
   - `churn_test.go`: Churn scenario (connection cycles)
   - `io_test.go`: I/O scenario (ForwardOpen/Close, SendIOData/ReceiveIOData)
   - Test cases:
     - Scenario execution with mock client
     - Interval/duration handling
     - Metrics recording
     - Error handling
     - Context cancellation

3. **Discovery Tests** (`internal/cipclient/discovery_test.go`)
   - ListIdentity request building
   - Response parsing
   - Broadcast address calculation
   - Interface selection
   - Timeout handling
   - Multiple device discovery

### Medium Priority

4. **Metrics Writer Tests** (`internal/metrics/writer_test.go`)
   - CSV output formatting
   - JSON output formatting
   - File creation/error handling
   - Metrics flushing
   - Writer cleanup

5. **Logging Tests** (`internal/logging/logger_test.go`)
   - Log level filtering
   - File output
   - Structured log formatting
   - Operation logging

### Lower Priority

6. **CLI Command Tests** (`cmd/cipdip/`)
   - Flag parsing
   - Config loading from CLI
   - Error message formatting
   - Exit code handling
   - Help text generation

7. **End-to-End Integration Tests**
   - Full client-server interaction
   - Multiple scenarios against server
   - Discovery with mock server
   - Metrics collection end-to-end

## Recommended Test Implementation Order

1. **Server Tests** (High priority - server is complex and critical)
   - Start with `server_test.go` for basic lifecycle
   - Add `adapter_test.go` for assembly handling
   - Add `logix_test.go` for tag handling

2. **Scenario Tests** (High priority - scenarios are core functionality)
   - Use mock client to test scenario logic
   - Test each scenario independently
   - Verify metrics are recorded correctly

3. **Discovery Tests** (High priority - used by `cipdip discover` command)
   - Test ListIdentity packet building/parsing
   - Test broadcast logic
   - Mock UDP responses

4. **Metrics/Logging Tests** (Medium priority - important but less critical)
   - Test output formatting
   - Test file handling

5. **CLI Tests** (Lower priority - can be tested manually)
   - Focus on critical error paths

## Test Utilities Needed

- **Mock Client**: For testing scenarios without real connections
- **Mock Server**: For testing client behavior
- **Test Helpers**: Common test utilities for building CIP packets, responses, etc.

