# OS API POC (Linux userspace broker)

This repository contains a working v0 proof-of-concept for a **userspace OS-API broker** using **local IPC (Unix domain sockets)** and **capability-first, fail-closed** behavior.

## Workspace crates

- `os-api-core` — shared protocol/types, manifest format, structured errors, message codec.
- `os-api-broker` — broker daemon (policy + enforcement in userspace session state).
- `os-api-client` — app-side client library for broker IPC.
- `os-api-demo` — demo app showing denied/allowed flows.

## Protocol (v0)

JSON messages over Unix domain sockets (newline-delimited):

- `hello { version, app_id }` / `hello_ack`
- `request_capabilities { capabilities[] }`
- `invoke { token, operation }`

`token` is a broker-scoped opaque grant handle bound to the current connection session.

## Capabilities implemented

- `fs.read` with scope directory allowlist from manifest (`read_file(relative_path)` behavior via `invoke fs_read`)
- `net.connect` is denied by default in v0

## Manifest format (TOML)

Example: `os-api-demo/examples/demo.manifest.toml`

```toml
app_id = "demo-app"

[[capabilities]]
name = "fs.read"
scope_dir = "/tmp/os-api-poc-demo/allowed"

[[capabilities]]
name = "net.connect"
```

## Run the POC

From repo root:

```bash
# 1) Prepare demo files
mkdir -p /tmp/os-api-poc-demo/allowed
echo "hello from allowed scope" > /tmp/os-api-poc-demo/allowed/hello.txt
echo "top-secret" > /tmp/os-api-poc-demo/secret.txt

# 2) Start broker (terminal A)
cargo run -p os-api-broker -- /tmp/os-api-broker.sock os-api-demo/examples/demo.manifest.toml

# 3) Run demo app (terminal B)
cargo run -p os-api-demo -- /tmp/os-api-broker.sock os-api-demo/examples/demo.manifest.toml hello.txt
```

## Expected demo output highlights

- `invoke fs.read` before grants: **denied** (`unknown or unauthorized capability token`)
- `request_capabilities`:
  - `fs.read` capability: **granted** with opaque token
  - `net.connect`: **denied by broker policy**
- `invoke fs.read hello.txt` with token: **success**
- `invoke fs.read ../secret.txt` with token: **denied** (path traversal blocked)

## Tests

- Manifest parsing unit tests in `os-api-core`
- Scope/path traversal prevention unit tests in `os-api-broker`
