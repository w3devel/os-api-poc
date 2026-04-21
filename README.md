# OS API — Proof of Concept

> **A demonstration of how an API layer between applications and the OS kernel
> can improve security, auditability, and portability.**

This repository contains a Rust library (`os-api`) and a runnable demo
(`os-api-demo`) that mock how an operating system could expose its services
through a structured API rather than letting applications call the kernel
directly.

---

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

1. [The Problem](#the-problem)
2. [The Solution — an OS API](#the-solution--an-os-api)
3. [Linux vs Unix — what's the difference?](#linux-vs-unix--whats-the-difference)
4. [Project Layout](#project-layout)
5. [Quick Start](#quick-start)
6. [API Modules](#api-modules)
7. [How Debian Works Today (and how an API improves it)](#how-debian-works-today-and-how-an-api-improves-it)
8. [What macOS (XNU) does differently](#what-macos-xnu-does-differently)
9. [Continuing from here](#continuing-from-here)

---

## The Problem

On every mainstream operating system, programs talk to the kernel through
**system calls** (syscalls).  A syscall is a special CPU instruction that
switches the processor from unprivileged "user mode" into privileged "kernel
mode" so the kernel can perform the requested work (read a file, allocate
memory, start a process …).

```
Application
    │
    │  open("/etc/passwd", O_RDONLY)    ← direct syscall
    ▼
Linux Kernel
```

This works, but it has significant drawbacks:

| Problem | Detail |
|---------|--------|
| **Security** | Once an app is running it can make *any* syscall the kernel permits for its user.  The only gatekeeping is Unix file permission bits and (optional, complex) tools like SELinux/AppArmor. |
| **No policy layer** | There is nothing between "I want to read this file" and "here you go" that can enforce an organisation's rules. |
| **Not portable** | Syscall numbers differ between Linux, macOS (XNU), FreeBSD, and others.  Code targeting the Linux ABI directly breaks on macOS. |
| **Hard to audit** | Logging every syscall made by every process is expensive and noisy.  There is no standard, structured audit API. |
| **Fragile** | The kernel's internal ABI (how syscalls work at the binary level) can change between kernel versions. |

---

## The Solution — an OS API

Insert a thin **API layer** between applications and the kernel:

```
Application
    │
    │  os_api::filesystem::open_file(ctx, "/etc/passwd", read_only=true)
    ▼
┌─────────────────────────────────────────┐
│               OS  API                   │
│                                         │
│  1. Check caller's capability set       │
│  2. Sanitise / validate the request     │
│  3. Write to the audit log              │
│  4. Call the kernel on the app's behalf │
└────────────────┬────────────────────────┘
                 │  sys_open("/etc/passwd", O_RDONLY)
                 ▼
          Linux Kernel
```

Benefits:

* **Security by default** — every operation requires the caller to hold an
  explicit **capability token**.  A service that only needs to read files
  cannot install packages even if it is compromised.
* **Auditability** — every API call is logged in a structured way before the
  kernel is invoked.
* **Portability** — the API surface is the same on Linux, macOS, and BSD.
  Only the kernel-adapter layer needs to differ.
* **Stable versioning** — applications pin to an API version.  Kernel upgrades
  do not break them.

---

## Linux vs Unix — what's the difference?

This question comes up constantly, so here is a clear answer:

| Term | Meaning |
|------|---------|
| **Unix** | A family of operating systems created at Bell Labs (AT&T) in the late 1960s–70s.  Defines the concepts of processes, files-as-byte-streams, pipes, shells, and the C programming interface. |
| **POSIX** | A set of IEEE standards that codify the Unix programming interface.  Any OS that conforms to POSIX can run the same C programs. |
| **Linux** | A *Unix-like* kernel written from scratch by Linus Torvalds starting in 1991.  It is not certified Unix, but it is POSIX-compatible and behaves like Unix in almost every way. |
| **GNU/Linux** | The complete OS: the Linux kernel plus the GNU userspace tools (bash, coreutils, glibc …).  What people usually mean when they say "Linux". |
| **macOS (XNU)** | Apple's operating system uses the **XNU** kernel, which combines the **Mach** microkernel with a **BSD** (Berkeley Software Distribution) Unix layer.  macOS is a *certified* Unix. |
| **FreeBSD / OpenBSD / NetBSD** | Direct descendants of the original BSD Unix code.  More legally "Unix" than Linux, but less popular on the desktop. |

**For an OS API, the key insight is:** the API surface can be *identical* on all
these systems.  Only the thin kernel-adapter layer at the bottom needs to
handle the platform differences (different syscall numbers, different ioctls,
different proc filesystems, etc.).

---

## Project Layout

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

## Quick Start

**Prerequisites:** [Rust](https://rustup.rs/) 1.65 or later.

```bash
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

### `package` — `PackageManager`

```rust
use os_api::package::{PackageManager, Repository};
let repo = Repository::demo(); // pre-populated with sample packages
let mut mgr = PackageManager::new(repo);
mgr.install(&root_ctx, "curl")?;  // resolves deps automatically
mgr.remove(&root_ctx, "curl")?;
let results = mgr.search("ssh");
```

---

## How Debian Works Today (and how an API improves it)

### Today — `apt install firefox`

```
1. Read /etc/apt/sources.list  (repository URLs)
2. Fetch & parse Packages.gz   (package index)
3. Resolve dependencies        (recursive, version-constrained)
4. Download .deb files         (GPG-verified)
5. dpkg --unpack               (extracts files as root)
6. Run preinst / postinst      (shell scripts, run as root — big risk!)
7. Update /var/lib/dpkg/status (package database)
```

The danger is step 6: a `postinst` script has **unlimited root access** and
can do anything on the machine.  APT verifies the GPG signature of the
package but trusts the script unconditionally.

### With an OS API

```
1. app calls PackageManager::install(&root_ctx, "firefox")
2. API checks ManagePackages capability  ← new: explicit gating
3. API resolves dependencies             (same as today)
4. API downloads & verifies signature    (same as today)
5. API calls kernel.sys_exec(postinst)   with a sandboxed capability set
   that only allows writing to /usr/** — the script cannot touch /etc/passwd
6. API logs every step to audit trail    ← new: structured audit
```

### First-run on a new Debian install

On a fresh Debian install `debian-installer` (or `calamares`) runs as root
and performs steps similar to those in `BootManager::first_run_setup`:

* Partition and format disks
* Mount the new root filesystem
* Unpack the base system tarball
* `chroot` into the new system and run `dpkg --configure -a`
* Set hostname, create the first user, configure locale/timezone
* Install GRUB into the MBR/EFI partition
* Reboot into the new system

An OS API would wrap each of these steps behind a `BootControl` capability
check and emit an audit record for every action.

---

## What macOS (XNU) does differently

macOS uses the **XNU** kernel (X is Not Unix), which is a hybrid:

* **Mach** microkernel at the core — handles threads, IPC (inter-process
  communication), and virtual memory.
* **BSD layer** on top of Mach — provides the POSIX API (files, processes,
  sockets) that most programs use.
* **I/O Kit** — object-oriented driver framework (written in a subset of C++).

From a developer's perspective macOS looks almost identical to Linux because
both expose the POSIX API.  Key differences:

| Feature | Linux | macOS (XNU) |
|---------|-------|-------------|
| Package management | APT/RPM/pacman (distro-specific) | Homebrew (community) / Mac App Store (sandboxed) |
| Init system | systemd (most distros) | launchd |
| Filesystem | ext4, btrfs, xfs … | APFS (Apple File System) |
| Dynamic linker | ld-linux.so | dyld |
| Kernel modules | `.ko` files, `insmod` / `modprobe` | `.kext` files, SIP-protected |
| Syscall ABI | Stable across kernel versions | Not guaranteed; use libSystem |
| Binary format | ELF | Mach-O |

The Mac App Store is the closest thing macOS has to an OS API for application
installation: apps are sandboxed, signed, and their capabilities (camera,
microphone, network, files …) are declared upfront and enforced by the OS.
This is exactly the model this PoC is advocating for Linux.

---

## Continuing from here

See [TO-DO.md](TO-DO.md) for a prioritised checklist of next steps.

At a high level, the next meaningful milestones are:

1. **Replace the mock kernel with real syscalls** using the `libc` crate, so
   actual files are read/written on the host machine.
2. **Persist state** — use a SQLite database (via `rusqlite`) to store the
   installed package list and running process table across restarts.
3. **Expose the API over IPC** — use Unix domain sockets or D-Bus so that
   real application processes can call the API.
4. **Write a simple shell** that drives the API instead of calling syscalls
   directly, making it a real proof-of-concept.
