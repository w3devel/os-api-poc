# TO-DO — OS API Proof of Concept

This file lists suggested next steps, roughly in priority order.  Items
marked **PoC** are required to turn this mock-up into a genuine
proof-of-concept running on a real Linux system.  Items marked **Design**
are architectural decisions that should be made before writing a lot of code.
Items marked **Stretch** are longer-term goals.

---

## Phase 1 — Make it real on Linux

- [ ] **PoC** Replace `MockKernel` with real syscalls via the `libc` crate.
  - `sys_open` → `libc::open`
  - `sys_read` / `sys_write` / `sys_close` → `libc::read` / `libc::write` / `libc::close`
  - `sys_exec` → `libc::fork` + `libc::execvp`
  - `sys_kill` → `libc::kill`
  - `sys_mkdir` → `libc::mkdir`
  - Gate this behind a Cargo feature flag (`real-kernel`) so the mock still
    works for tests on any platform.

- [ ] **PoC** Add a `FileSystem::list_dir` method that wraps `opendir` / `readdir`.

- [ ] **PoC** Make `ProcessManager` watch real PIDs using `/proc/<pid>/status`
  so `list_running` reflects actual system state.

- [ ] **PoC** Implement `PackageManager::update_index` that fetches and parses
  a real Debian `Packages.gz` file from a repository mirror.

---

## Phase 2 — Persist state

- [ ] **PoC** Store the installed package database in a SQLite file
  (`/var/lib/os-api/packages.db`) using the `rusqlite` crate.

- [ ] **PoC** Store the security policy (which users/services hold which
  capabilities) in a TOML or JSON config file under `/etc/os-api/`.

- [ ] **PoC** Write the audit log to a structured file (JSON Lines format)
  at `/var/log/os-api/audit.log` instead of stdout.

---

## Phase 3 — IPC and multi-process

- [ ] **Design** Choose an IPC mechanism:
  - **Unix domain sockets** — simple, fast, works everywhere.
  - **D-Bus** — already standard on Linux desktops; use `zbus` crate.
  - **Cap'n Proto / gRPC** — typed, versioned, language-neutral.

- [ ] **PoC** Run the OS API as a daemon (`os-apid`) that listens on a Unix
  socket.  Client programs connect and send serialised requests.

- [ ] **PoC** Write a minimal CLI client (`os-api-cli`) that wraps the daemon:
  ```
  os-api-cli file open /home/alice/test.txt
  os-api-cli process launch /usr/bin/firefox
  os-api-cli package install curl
  ```

- [ ] **PoC** Authenticate callers — use the socket's peer credentials
  (`SO_PEERCRED`) to verify the UID of the connecting process.

---

## Phase 4 — Security hardening

- [ ] **Design** Define a formal capability grant file format (similar to
  Android's `AndroidManifest.xml` or macOS's entitlements `.plist`).

- [ ] **PoC** When launching a process, drop all capabilities not listed in
  its grant file using Linux `prctl(PR_SET_SECCOMP)` / `seccomp-BPF`.

- [ ] **PoC** Use Linux namespaces (`clone(CLONE_NEWNS)` etc.) to sandbox
  package `postinst` scripts so they cannot write outside `/usr/`.

- [ ] **PoC** Verify package signatures against a GPG keyring before unpacking.

- [ ] **Stretch** Implement Mandatory Access Control (MAC) labels on files,
  similar to SELinux, enforced through the API rather than in the kernel.

---

## Phase 5 — Boot integration

- [ ] **Design** Decide where the OS API daemon starts in the boot order:
  - Option A: Start it as an early systemd service (after `local-fs.target`).
  - Option B: Build it into the `initrd` so it is active from the first stage
    of boot.

- [ ] **PoC** Write a systemd unit file (`os-apid.service`) that starts the
  daemon at boot.

- [ ] **PoC** Add a `boot::BootManager::prepare_initrd` function that generates
  a minimal `initrd` image containing the OS API daemon.

- [ ] **Stretch** Replace the `systemd` service-start loop with a native
  `BootManager` implementation that reads a TOML service manifest instead
  of systemd unit files.

---

## Phase 6 — Desktop / GUI considerations

> The problem statement deliberately defers deep DE (Desktop Environment)
> work, but here is where it would go.

- [ ] **Design** Define a `display` module with APIs for:
  - Opening a window (wrapping Wayland / X11 protocol).
  - Clipboard access (requires explicit `ClipboardAccess` capability).
  - Screen capture (requires explicit `ScreenCapture` capability).

- [ ] **Stretch** Integrate with the existing Wayland compositor protocol
  (Weston or KWin) as a proof that the OS API can mediate display access.

---

## Phase 7 — Cross-platform

- [ ] **Design** Define a `KernelAdapter` trait that `MockKernel` and a future
  `LinuxKernel`, `MacosKernel`, and `BsdKernel` all implement.

- [ ] **Stretch** Implement `MacosKernel` using `libc` on macOS (XNU syscalls
  are accessed through `libSystem`, not directly).

- [ ] **Stretch** Run the full test suite on macOS in CI (GitHub Actions
  `macos-latest` runner).

---

## Documentation

- [ ] Add `#[doc(hidden)]` to internal helpers.
- [ ] Publish the crate docs to GitHub Pages with `cargo doc --no-deps`.
- [ ] Add a `CONTRIBUTING.md` explaining how to run tests and submit PRs.
- [ ] Write a blog-post-style `EXPLAINER.md` going deeper into the OS/kernel
  theory for readers with no prior Linux experience.

---

## Testing

- [ ] Add integration tests in `os-api/tests/` that exercise the full
  API stack end-to-end (boot → file I/O → process → package).
- [ ] Add property-based tests with `proptest` for the dependency resolver.
- [ ] Set up GitHub Actions CI to run `cargo test` and `cargo clippy` on
  every pull request.
- [ ] Add `cargo bench` benchmarks for the hot paths (file open, capability
  check) once the real kernel adapter exists.
