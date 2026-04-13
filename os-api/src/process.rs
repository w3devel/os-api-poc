//! # Process and application management
//!
//! ## How processes work today
//!
//! On Linux, every running program is a **process**.  A process has:
//!
//! * A **PID** (Process ID) — a unique number.
//! * A **UID/GID** — which user and group it runs as.
//! * A set of open **file descriptors**.
//! * A virtual memory address space.
//!
//! Creating a new process today uses two syscalls:
//!
//! 1. **`fork(2)`** — copies the current process (the "parent") to create a
//!    child that is an exact duplicate.
//! 2. **`execve(2)`** — in the child, replaces the process image with a new
//!    program binary.
//!
//! This fork/exec pattern is the basis of everything on Unix: shells,
//! daemons, graphical launchers.
//!
//! ## What the OS API adds
//!
//! * **Capability check** — only processes with `LaunchProcesses` can start
//!   new programs.
//! * **Process registry** — the OS API tracks what is running, allowing
//!   queries and clean shutdown.
//! * **Sandboxing hooks** — before launching, the API could set up a
//!   namespace or seccomp filter for the child process (not mocked here but
//!   documented as a TODO).

use std::collections::HashMap;

use crate::error::ApiError;
use crate::kernel::MockKernel;
use crate::security::{Capability, SecurityContext};

/// Information about a running (or recently stopped) process.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: u32,
    /// The executable that was launched.
    pub executable: String,
    /// Command-line arguments.
    pub args: Vec<String>,
    /// The user who launched the process.
    pub owner: String,
    /// Whether the process is still running.
    pub running: bool,
}

/// Process management API.
///
/// # Example
///
/// ```
/// use os_api::process::ProcessManager;
/// use os_api::security::SecurityContext;
///
/// let ctx = SecurityContext::normal_user("alice");
/// let mut pm = ProcessManager::new();
/// let pid = pm.launch(&ctx, "/usr/bin/firefox", &[]).expect("launch failed");
/// pm.terminate(&ctx, pid).expect("terminate failed");
/// ```
pub struct ProcessManager {
    kernel: MockKernel,
    /// In-memory table of all processes started through this API.
    processes: HashMap<u32, ProcessInfo>,
    /// Counter used to generate unique (mock) PIDs.
    next_pid: u32,
}

impl ProcessManager {
    /// Create a new `ProcessManager`.
    pub fn new() -> Self {
        ProcessManager {
            kernel: MockKernel::new(),
            processes: HashMap::new(),
            next_pid: 1000,
        }
    }

    /// Launch a new process.
    ///
    /// # Arguments
    ///
    /// * `ctx`        — security context of the caller.
    /// * `executable` — absolute path to the binary (e.g. `/usr/bin/firefox`).
    /// * `args`       — command-line arguments for the binary.
    ///
    /// Returns the PID of the new process.
    pub fn launch(
        &mut self,
        ctx: &SecurityContext,
        executable: &str,
        args: &[&str],
    ) -> Result<u32, ApiError> {
        ctx.check(Capability::LaunchProcesses)?;

        // The OS API can apply a sandbox here before calling the kernel.
        // For this mock we just log the intent.
        println!("[process] Preparing sandbox for '{executable}' …");
        println!("[process] Applying seccomp-BPF filter (mock) …");

        let _kernel_pid = self.kernel.sys_exec(executable, args)?;

        // Use our own sequential PID so the demo output is deterministic.
        let pid = self.next_pid;
        self.next_pid += 1;

        let info = ProcessInfo {
            pid,
            executable: executable.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            owner: ctx.username.clone(),
            running: true,
        };
        self.processes.insert(pid, info);

        ctx.audit("launch", executable, true);
        println!("[process] Process launched: pid={pid} executable='{executable}'");
        Ok(pid)
    }

    /// Terminate a running process with SIGTERM (graceful shutdown).
    ///
    /// If the process does not respond within a timeout a real implementation
    /// would follow up with SIGKILL.
    pub fn terminate(&mut self, ctx: &SecurityContext, pid: u32) -> Result<(), ApiError> {
        ctx.check(Capability::TerminateProcesses)?;

        let info = self.processes.get_mut(&pid).ok_or_else(|| {
            ApiError::NotFound(format!("no process with pid {pid}"))
        })?;

        if !info.running {
            return Err(ApiError::InvalidOperation(format!(
                "process {pid} is not running"
            )));
        }

        // SIGTERM = 15
        self.kernel.sys_kill(pid, 15)?;
        info.running = false;

        ctx.audit("terminate", &info.executable, true);
        println!("[process] Process {pid} terminated.");
        Ok(())
    }

    /// Return a list of all currently running processes.
    pub fn list_running(&self) -> Vec<&ProcessInfo> {
        self.processes.values().filter(|p| p.running).collect()
    }

    /// Look up information about a specific process by PID.
    pub fn get(&self, pid: u32) -> Option<&ProcessInfo> {
        self.processes.get(&pid)
    }
}

impl Default for ProcessManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_and_list() {
        let ctx = SecurityContext::normal_user("alice");
        let mut pm = ProcessManager::new();
        let pid = pm.launch(&ctx, "/usr/bin/gedit", &["/home/alice/file.txt"]).unwrap();
        let running = pm.list_running();
        assert_eq!(running.len(), 1);
        assert_eq!(running[0].pid, pid);
    }

    #[test]
    fn terminate_removes_from_running() {
        let ctx = SecurityContext::normal_user("alice");
        let mut pm = ProcessManager::new();
        let pid = pm.launch(&ctx, "/usr/bin/top", &[]).unwrap();
        pm.terminate(&ctx, pid).unwrap();
        assert_eq!(pm.list_running().len(), 0);
        assert!(!pm.get(pid).unwrap().running);
    }

    #[test]
    fn cannot_terminate_nonexistent_process() {
        let ctx = SecurityContext::normal_user("alice");
        let mut pm = ProcessManager::new();
        let result = pm.terminate(&ctx, 99999);
        assert!(result.is_err());
    }

    #[test]
    fn launch_requires_capability() {
        // A context with no LaunchProcesses capability.
        let ctx = SecurityContext::for_user("restricted", vec![]);
        let mut pm = ProcessManager::new();
        let result = pm.launch(&ctx, "/usr/bin/ls", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn multiple_processes() {
        let ctx = SecurityContext::normal_user("alice");
        let mut pm = ProcessManager::new();
        let pid1 = pm.launch(&ctx, "/usr/bin/vim", &[]).unwrap();
        let pid2 = pm.launch(&ctx, "/usr/bin/firefox", &[]).unwrap();
        assert_ne!(pid1, pid2);
        assert_eq!(pm.list_running().len(), 2);
    }
}
