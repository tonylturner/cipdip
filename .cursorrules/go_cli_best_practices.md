# Go CLI Best Practices – Cursor Rule for This Project

This document defines **CLI design rules** for our Go-based EtherNet/IP / CIP tool (and any related utilities). Cursor should follow these from the start so the UX stays consistent.

The goals are:
- Simple, predictable commands.
- Minimal noise in output.
- Easy to script and automate.

No emojis or decorative characters should ever be used.

---

## 1. Overall CLI Shape

### 1.1 Command Name

- Primary binary name: `cipdip` (example; adjust if needed).
- All commands should follow the pattern:

  ```bash
  cipdip <command> [arguments] [options]
  ```

- Avoid leading dashes for the main verbs. Prefer:

  ```bash
  cipdip help
  cipdip client ...
  cipdip server ...
  ```

  over:

  ```bash
  cipdip --help
  ```

### 1.2 Subcommands vs Flags

- Prefer **subcommands** for major modes instead of top-level flags:
  - `cipdip client` – run in client/scanner mode.
  - `cipdip server` – run in server/emulator mode.
  - `cipdip version` – print version.
  - `cipdip help` – show help.

- Within each subcommand, options can still use flags (short `-h` or long `--help` is fine), but the primary interaction style should rely on subcommands.

Example:

```bash
cipdip client --ip 10.0.0.50 --scenario baseline
cipdip server --listen-ip 0.0.0.0 --personality adapter
```

---

## 2. Help and Usage

### 2.1 Help Command

- `cipdip help` should:
  - Print a short top-level usage.
  - List available subcommands with one-line descriptions.
  - Exit with status code 0.

- `cipdip help <command>` should show detailed help for that command.

### 2.2 `-h` / `--help` Flags

- Each subcommand should also support:
  - `cipdip client -h`
  - `cipdip server --help`

- These should print a concise usage message and exit 0.

### 2.3 Help Content Style

- Keep help **short and scannable**:
  - One-line description.
  - Usage example.
  - List of options with short descriptions.
- Avoid verbose prose in help output. Use documentation or comments in code for deeper explanations, not the CLI itself.

---

## 3. Output Style

### 3.1 Default Output

- Default output should be:
  - Plain text.
  - Single-line or short multi-line summaries.
  - No ASCII art, no banners, no emojis.

- For routine success cases:
  - Either print nothing or a brief confirmation line.
  - Examples:
    - `OK`
    - `Completed scenario 'baseline' in 60s (1200 operations, 0 errors)`

### 3.2 Verbosity Levels

Support at most three levels:

1. **Silent / minimal** (default):
   - Only necessary output.
   - Errors go to stderr.

2. **Verbose** (`--verbose`):
   - Extra operational details (connections, scenario parameters, summary).
   - Still no excessive chatter.

3. **Debug** (optional, via `--debug` or environment variable):
   - Detailed logs for troubleshooting.
   - May include raw packet hex dumps or structured debug logs.

Never print debug-level information at default verbosity.

### 3.3 Machine-Readable Output

- Where structured data is appropriate (e.g., metrics or summaries), provide:
  - `--json` or `--output=json` options if needed in the future.
  - Or use dedicated output files for CSV/JSON as already in the spec.

The default stdout should favor human-readable, compact lines.

---

## 4. Errors and Exit Codes

### 4.1 Exit Codes

- `0` – success.
- `1` – CLI or usage error (invalid flags, missing required arguments).
- `2` – runtime error (network failure, CIP error that aborts the run).
- No other exit codes unless clearly documented.

### 4.2 Error Messages

- Write errors to `stderr`.
- Format:
  - `"error: <short description>"`
  - Optionally followed by a hint:
    - `"error: missing --ip; try 'cipdip help client'"`
- Avoid stack traces by default.
  - Only show stack traces or detailed debug info in debug mode.

---

## 5. Flags and Naming Conventions

### 5.1 Flag Naming

- Long flags should be:

  - Lowercase.
  - Hyphen-separated words:
    - `--listen-ip`
    - `--listen-port`
    - `--scenario`
    - `--duration-seconds`

- Short flags are optional and should only be used where very common (`-h`, `-v`).

### 5.2 Required vs Optional Flags

- Required flags must be clearly documented in the help output.
- The CLI should validate required flags and show a clear error when missing, with a pointer to the relevant help:

  ```text
  error: --ip is required for 'client'
  See 'cipdip help client' for usage.
  ```

---

## 6. Configuration and Defaults

### 6.1 Default Values

- Provide sensible defaults for:
  - Ports (`44818`, `2222`).
  - Interval/duration where it makes sense.
  - Config file paths (`cip_targets.yaml`, `server_config.yaml`).

- Always show default values in help text, e.g.:

  ```text
  --port int   CIP TCP port (default 44818)
  ```

### 6.2 Config Files

- Use explicit `--config` and `--server-config` flags.
- Never auto-create config files without the user’s explicit action.
- If a config file is missing:
  - Print a short error.
  - Do not silently ignore.

---

## 7. Subcommand Design for This Project

Recommended subcommands:

- `cipdip help`
- `cipdip version`
- `cipdip client`
- `cipdip server`
- (Optional) `cipdip discover` for ListIdentity tests

Each subcommand should:

- Have a single, clear responsibility.
- Fail fast on invalid input.
- Offer examples in the `help` output.

Example help sketch:

```text
Usage:
  cipdip client --ip IP --scenario NAME [options]

Options:
  --ip string            Target CIP adapter IP (required)
  --port int             CIP TCP port (default 44818)
  --scenario string      Scenario name (baseline|mixed|stress|churn|io) (required)
  --interval-ms int      Base interval in milliseconds
  --duration-seconds int Total run time in seconds (default 300)
  --config string        CIP targets config file (default "cip_targets.yaml")
  --log-file string      Log file path
  --metrics-file string  Metrics output file path
  --verbose              Enable verbose output
  -h, --help             Show help for client
```

---

## 8. Logging vs CLI Output

- CLI stdout/stderr should be **separate from detailed logs**.
- Use a logging system (even if minimal) for:
  - Detailed operational events, written to a log file if `--log-file` is provided.
- By default:
  - Only high-level summaries or errors appear in the terminal.
  - Internal debug/info logs go to the log file when enabled.

---

## 9. Testing and Stability

- Always include simple end-to-end tests for the CLI:
  - `cipdip help` should succeed.
  - `cipdip client` without required flags should fail with a helpful message.
  - `cipdip client --ip 127.0.0.1 --scenario baseline` should start, run briefly, then exit cleanly in a test mode.

- Avoid breaking CLI changes once the tool is in use. If a breaking change is required, update:
  - `cipdip help`
  - Any docs and comments in the spec.

---

By adopting these CLI best practices from the beginning, the Go tool will remain consistent, scriptable, and easy to reason about, while keeping output simple and free of unnecessary noise.
