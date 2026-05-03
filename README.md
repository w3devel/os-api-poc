# OS API POC (Linux userspace broker)

This repository contains a working v0 proof-of-concept for a **userspace OS-API broker** using **local IPC (Unix domain sockets)** and **capability-first, fail-closed** behavior.

## Workspace crates

- `os-api-core` — shared protocol/types, manifest format, structured errors, message codec.
- `os-api-broker` — broker daemon (policy + enforcement in userspace session state).
- `os-api-client` — app-side client library for broker IPC.
- `os-api-demo` — demo app showing denied/allowed flows.

## Protocol (v0)
## OS-API broker v0 (Linux local IPC PoC)

This repository now also includes a **strictly local userspace broker** PoC:

- `os-api-broker`: daemon listening on a Unix domain socket (`/tmp/os-api-broker.sock` by default)
- `os-api-client`: client library and v0 capability traits (`fs.read`, `fs.write`, `net.connect`, `proc.spawn`)
- `os-api-example`: demo app showing allowed `fs.read` and fail-closed denied `fs.write`

### Run broker

```bash
cargo run --bin os-api-broker -- /tmp/os-api-broker.sock ./policy.example.toml
```

### Run example app

```bash
cargo run --bin os-api-example -- /tmp/os-api-broker.sock ./os-api-example/manifest.toml
```

### Policy and manifest

- Broker policy: `policy.example.toml` (`app_id -> allowed capabilities/scopes`)
- App manifest: `os-api-example/manifest.toml` (requested capabilities)
- Security posture: **default deny** for missing app entries and out-of-scope operations

---

## Table of Contents

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
os-api-poc/
├── Cargo.toml          # Workspace definition (ties the two crates together)
├── README.md           # This file
├── TO-DO.md            # Suggested next steps
│
├── os-api-broker/      # Local Unix-socket broker daemon (policy + enforcement)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs          # Policy loader + request enforcement
│       └── main.rs         # Unix socket server entrypoint
│
├── os-api-client/      # Client library + protocol types + capability traits
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs
│
├── os-api-example/     # Example app using manifest + client library
│   ├── Cargo.toml
│   ├── manifest.toml
│   └── src/
│       └── main.rs
│
├── os-api/             # The reusable library crate
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs          # Module declarations and top-level documentation
│       ├── error.rs        # Shared error type (ApiError)
│       ├── kernel.rs       # Mock kernel — simulates raw syscalls
│       ├── security.rs     # Capability model and SecurityContext
│       ├── boot.rs         # Boot sequence and first-run setup
│       ├── filesystem.rs   # File system operations
│       ├── process.rs      # Process management
│       └── package.rs      # Package management (Debian/APT style)
│
└── os-api-demo/        # Runnable demo binary
    ├── Cargo.toml
    └── src/
        └── main.rs         # Walks through all API scenarios
```

---

## Run the POC

From repo root:

```bash
# 1) Prepare demo files
mkdir -p /tmp/os-api-poc-demo/allowed
echo "hello from allowed scope" > /tmp/os-api-poc-demo/allowed/hello.txt
echo "top-secret" > /tmp/os-api-poc-demo/secret.txt
# Build everything
cargo build

# Run all tests (30 unit tests + 5 doc-tests)
cargo test

# Run the interactive demo
cargo run --bin os-api-demo

# Run local broker + capability demo app (in separate terminals)
cargo run --bin os-api-broker -- /tmp/os-api-broker.sock ./policy.example.toml
cargo run --bin os-api-example -- /tmp/os-api-broker.sock ./os-api-example/manifest.toml

# Check code style and correctness
cargo clippy
```

### What the demo shows

The demo (`cargo run --bin os-api-demo`) walks through six scenarios:

1. **System boot** — four-stage sequence: firmware → kernel loaded →
   root filesystem mounted → services started → user space ready.
2. **First-run setup** — hostname, user creation, locale, timezone.
3. **File system operations** — open, read, write, and a path-traversal
   attack that the API correctly rejects.
4. **Process management** — launch Firefox and a text editor, list running
   processes, terminate one.
5. **Package management** — search, install `curl` (with automatic dependency
   resolution), remove.
6. **Security** — a normal user trying to install a package is blocked at the
   API layer before the kernel is ever asked.

---

## API Modules

### `error` — `ApiError`

One error enum covers all modules.  Every API call returns
`Result<T, ApiError>`.

```rust
use os_api::error::ApiError;
```

### `kernel` — `MockKernel`

Simulates a small subset of Linux syscalls (`open`, `read`, `write`, `close`,
`fork`+`execve`, `kill`, `mkdir`, `mount`).  In a real implementation this
module would call `libc` or use inline assembly; here it just prints what it
would do.

```rust
use os_api::kernel::MockKernel;
let k = MockKernel::new();
let fd = k.sys_open("/etc/os-release", true)?;
```

### `security` — `Capability` + `SecurityContext`

Every API call receives a `&SecurityContext`.  The context holds a set of
`Capability` tokens that were granted at login/launch time.

```rust
use os_api::security::{Capability, SecurityContext};

let ctx = SecurityContext::for_user("alice", vec![
    Capability::ReadFiles,
    Capability::WriteFiles,
    Capability::LaunchProcesses,
    Capability::TerminateProcesses,
    Capability::NetworkAccess,
]);

ctx.check(Capability::ManagePackages)?; // → Err(PermissionDenied)
```

Pre-built contexts:

| Constructor | Capabilities |
|-------------|-------------|
| `SecurityContext::superuser()` | All capabilities (equivalent to root) |
| `SecurityContext::normal_user(name)` | ReadFiles, WriteFiles, LaunchProcesses, TerminateProcesses, NetworkAccess |
| `SecurityContext::for_user(name, caps)` | Exactly what you specify |

### `boot` — `BootManager`

Drives the system through the four boot stages in order.  Out-of-order calls
return an `InvalidOperation` error.

```rust
use os_api::boot::BootManager;
let mut bm = BootManager::new();
bm.run_full_boot(&root_ctx)?;
bm.first_run_setup(&root_ctx, "myhostname", "alice")?;
```

Boot stages: `Firmware` → `KernelLoaded` → `RootFsMounted` →
`ServicesStarted` → `UserSpaceReady`

### `filesystem` — `FileSystem`

```rust
use os_api::filesystem::FileSystem;
let fs = FileSystem::new();
let fh = fs.open_file(&ctx, "/home/alice/readme.txt", true)?;
let data = fs.read_file(&ctx, &fh, 4096)?;
fs.close_file(&ctx, fh)?;
```

Security features built in:

* Path traversal (`..`) rejected before the kernel is called.
* Read-only handles cannot be written to.
* `WriteFiles` capability required to open for writing.

### `process` — `ProcessManager`

```rust
use os_api::process::ProcessManager;
let mut pm = ProcessManager::new();
let pid = pm.launch(&ctx, "/usr/bin/firefox", &[])?;
pm.terminate(&ctx, pid)?;
let running = pm.list_running();
```

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
