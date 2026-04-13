//! # Security and permissions layer
//!
//! One of the biggest benefits of an OS API is that it can enforce a
//! **security policy** before passing any request to the kernel.
//!
//! ## The problem today
//!
//! On a conventional Linux system, once a program is running as a particular
//! user it can make any syscall the kernel allows for that user.  The only
//! controls are:
//!
//! * **Unix DAC** (Discretionary Access Control) — file permission bits
//!   (`rwxrwxrwx`) and ownership.
//! * **Linux capabilities** — a process can be granted a subset of root
//!   powers (e.g. `CAP_NET_BIND_SERVICE` to bind port 80) without full root.
//! * **seccomp-BPF** — a process can opt-in to a filter that blocks certain
//!   syscalls. Used by Chrome, Docker, etc.
//! * **SELinux / AppArmor** — Mandatory Access Control (MAC) policies.
//!
//! These are added-on mechanisms.  They are not part of a unified API.
//!
//! ## What the OS API adds
//!
//! This module implements a **capability model**: every process is given a set
//! of [`Capability`] tokens at launch time.  Before any operation is
//! performed the API checks whether the calling process holds the required
//! capability.  If not, the operation fails immediately — the kernel is never
//! even asked.

use std::collections::HashSet;

use crate::error::ApiError;

/// A capability token grants the holder permission to perform a class of
/// operations.
///
/// In a full implementation these would be much more fine-grained (e.g.
/// `ReadFile("/etc/passwd")` rather than just `ReadFiles`), and could be
/// backed by a cryptographic proof so they cannot be forged.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Capability {
    /// May open and read files.
    ReadFiles,
    /// May create and write files.
    WriteFiles,
    /// May launch new processes.
    LaunchProcesses,
    /// May terminate (kill) processes.
    TerminateProcesses,
    /// May install or remove packages.
    ManagePackages,
    /// May read and modify network configuration.
    NetworkAccess,
    /// May perform privileged boot-time operations.
    BootControl,
    /// Full access — equivalent to UNIX root. Use sparingly.
    Superuser,
}

/// A security context holds the capabilities granted to one process (or
/// one API session).
///
/// # Example
///
/// ```
/// use os_api::security::{Capability, SecurityContext};
///
/// let ctx = SecurityContext::for_user("alice", vec![
///     Capability::ReadFiles,
///     Capability::WriteFiles,
/// ]);
///
/// assert!(ctx.check(Capability::ReadFiles).is_ok());
/// assert!(ctx.check(Capability::ManagePackages).is_err());
/// ```
#[derive(Debug, Clone)]
pub struct SecurityContext {
    /// The username (or service name) this context belongs to.
    pub username: String,
    /// The set of capabilities granted to this principal.
    capabilities: HashSet<Capability>,
}

impl SecurityContext {
    /// Create a context for the given user with the specified capabilities.
    pub fn for_user(username: &str, caps: Vec<Capability>) -> Self {
        SecurityContext {
            username: username.to_string(),
            capabilities: caps.into_iter().collect(),
        }
    }

    /// Create a context with **all** capabilities (equivalent to root).
    ///
    /// Should only be used during system boot or by the init process.
    pub fn superuser() -> Self {
        SecurityContext::for_user(
            "root",
            vec![
                Capability::ReadFiles,
                Capability::WriteFiles,
                Capability::LaunchProcesses,
                Capability::TerminateProcesses,
                Capability::ManagePackages,
                Capability::NetworkAccess,
                Capability::BootControl,
                Capability::Superuser,
            ],
        )
    }

    /// Create a restricted context suitable for a normal desktop user.
    ///
    /// A normal user can launch and terminate their own processes, read/write
    /// their own files, and use the network.  They cannot install packages or
    /// perform privileged boot operations.
    pub fn normal_user(username: &str) -> Self {
        SecurityContext::for_user(
            username,
            vec![
                Capability::ReadFiles,
                Capability::WriteFiles,
                Capability::LaunchProcesses,
                Capability::TerminateProcesses,
                Capability::NetworkAccess,
            ],
        )
    }

    /// Check whether this context holds `cap`.
    ///
    /// Returns `Ok(())` on success and `Err(ApiError::PermissionDenied)`
    /// otherwise.
    pub fn check(&self, cap: Capability) -> Result<(), ApiError> {
        // Superuser can do anything.
        if self.capabilities.contains(&Capability::Superuser) {
            return Ok(());
        }
        if self.capabilities.contains(&cap) {
            Ok(())
        } else {
            Err(ApiError::PermissionDenied(format!(
                "user '{}' does not hold capability {:?}",
                self.username, cap
            )))
        }
    }

    /// Log a security event to stdout.
    ///
    /// In a real system this would write to a tamper-evident audit log file
    /// (e.g. `/var/log/os-api/audit.log`).  Audit logs intentionally record
    /// the identity of who performed each action — that is their purpose.
    pub fn audit(&self, action: &str, resource: &str, allowed: bool) {
        let verdict = if allowed { "ALLOW" } else { "DENY" };
        let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S");
        // NOTE: logging the username here is intentional — an audit log must
        // record who performed each action so administrators can review it.
        println!(
            "[security] {timestamp} {verdict} user='{}' action='{action}' resource='{resource}'",
            self.username
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn superuser_can_do_everything() {
        let ctx = SecurityContext::superuser();
        assert!(ctx.check(Capability::ReadFiles).is_ok());
        assert!(ctx.check(Capability::ManagePackages).is_ok());
        assert!(ctx.check(Capability::BootControl).is_ok());
    }

    #[test]
    fn normal_user_cannot_manage_packages() {
        let ctx = SecurityContext::normal_user("alice");
        let result = ctx.check(Capability::ManagePackages);
        assert!(result.is_err());
        if let Err(ApiError::PermissionDenied(msg)) = result {
            assert!(msg.contains("alice"));
        }
    }

    #[test]
    fn normal_user_can_read_files() {
        let ctx = SecurityContext::normal_user("bob");
        assert!(ctx.check(Capability::ReadFiles).is_ok());
    }

    #[test]
    fn custom_context() {
        let ctx = SecurityContext::for_user("svc-backup", vec![Capability::ReadFiles]);
        assert!(ctx.check(Capability::ReadFiles).is_ok());
        assert!(ctx.check(Capability::WriteFiles).is_err());
    }
}
