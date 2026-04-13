//! # os-api — Operating System API Proof-of-Concept
//!
//! ## What is this?
//!
//! Modern operating systems (Linux, macOS, FreeBSD …) let user-space programs
//! talk **directly** to the kernel through "system calls" (syscalls).  A
//! syscall is just a special CPU instruction that drops the program into
//! privileged kernel mode so it can ask for memory, read a file, create a
//! process, and so on.
//!
//! ```text
//!   ┌──────────────────────────────┐
//!   │   Application (e.g. Firefox) │
//!   └──────────────┬───────────────┘
//!                  │  syscall (read, write, open, fork …)
//!                  ▼
//!   ┌──────────────────────────────┐
//!   │         Linux Kernel         │
//!   └──────────────────────────────┘
//! ```
//!
//! The problem with this direct model is:
//!
//! * **Security** — any bug in the application or kernel can expose the whole
//!   system.  There is no policy layer between "I want to read this file" and
//!   "here you go".
//! * **Portability** — Linux syscall numbers differ from macOS (XNU/BSD),
//!   FreeBSD, Solaris, etc.  Code that calls the kernel directly is
//!   platform-specific.
//! * **Versioning** — there is no stable, versioned contract between the app
//!   and the kernel.  Kernel updates can silently change behaviour.
//! * **Auditability** — it is hard to log or intercept what every process asks
//!   the kernel to do.
//!
//! ## The OS API concept
//!
//! This crate demonstrates an **API layer** that sits between applications and
//! the kernel:
//!
//! ```text
//!   ┌──────────────────────────────┐
//!   │   Application (e.g. Firefox) │
//!   └──────────────┬───────────────┘
//!                  │  OS API calls (open_file, launch_app, install_package …)
//!                  ▼
//!   ┌──────────────────────────────┐
//!   │          OS  API             │  ← this crate
//!   │  • validates permissions     │
//!   │  • audits every request      │
//!   │  • provides stable interface │
//!   └──────────────┬───────────────┘
//!                  │  kernel interface (mocked here)
//!                  ▼
//!   ┌──────────────────────────────┐
//!   │         Linux Kernel         │
//!   └──────────────────────────────┘
//! ```
//!
//! ## Linux vs Unix: a short note
//!
//! | Term  | What it means |
//! |-------|---------------|
//! | **Unix** | A family of OSes born at Bell Labs in the 1970s. Defines concepts like files-as-streams, processes, pipes, and the C library. |
//! | **POSIX** | A standard that codifies Unix behaviour so that programs can run on any conforming OS. |
//! | **Linux** | A *Unix-like* (or POSIX-compliant) kernel written from scratch by Linus Torvalds in 1991. It is **not** a certified Unix but behaves like one. |
//! | **macOS** | Apple's OS, based on **XNU** — a kernel that combines the Mach microkernel with a BSD (Berkeley Software Distribution) Unix layer.  macOS *is* a certified Unix. |
//! | **FreeBSD / OpenBSD** | Direct Unix descendants. Similar to Linux from the user's perspective but with different kernel internals and licensing. |
//!
//! An OS API layer is especially valuable because it can **abstract away**
//! these differences: the same API call works whether the kernel underneath is
//! Linux, XNU, or a BSD variant.
//!
//! ## Module overview
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`error`] | Shared error types used across all modules |
//! | [`kernel`] | Mock kernel — simulates raw syscalls |
//! | [`security`] | Permission and policy checks |
//! | [`boot`] | Boot sequence and first-run setup |
//! | [`filesystem`] | File and directory operations |
//! | [`process`] | Process and application management |
//! | [`package`] | Package management (Debian/APT style) |

// Make every sub-module visible to callers of this crate.
pub mod boot;
pub mod error;
pub mod filesystem;
pub mod kernel;
pub mod package;
pub mod process;
pub mod security;
