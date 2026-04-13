//! # Mock Kernel Interface
//!
//! In a real OS, this layer would issue CPU instructions called **system
//! calls** (or "syscalls") to ask the kernel to do work on the process's
//! behalf.  Common Linux syscalls include:
//!
//! | Syscall | What it does |
//! |---------|-------------|
//! | `read`  | Read bytes from a file descriptor |
//! | `write` | Write bytes to a file descriptor |
//! | `open`  | Open a file and return a descriptor |
//! | `fork`  | Clone the current process |
//! | `execve`| Replace the current process image with a new program |
//! | `mmap`  | Map memory (allocate RAM) |
//! | `kill`  | Send a signal to a process |
//!
//! On **Linux** these calls are made via the `syscall` assembly instruction
//! with a number in register `rax` (x86-64).  On **macOS / XNU** the same
//! ideas exist but the numbers are different and the ABI (calling convention)
//! has a BSD flavour.
//!
//! In this proof-of-concept we **simulate** the kernel rather than making
//! real syscalls, so the code runs safely in user space without needing root
//! privileges or a real kernel.

use crate::error::ApiError;

/// Simulates a very small subset of Linux/Unix syscalls.
///
/// Each method prints what a real kernel would do, then returns success or a
/// mocked error.  A real implementation would use `libc` or inline assembly
/// to make actual syscalls.
pub struct MockKernel;

impl MockKernel {
    /// Create a new handle to the (mock) kernel.
    pub fn new() -> Self {
        MockKernel
    }

    /// `sys_open` — ask the kernel to open a file.
    ///
    /// Real Linux syscall: `open(2)` / `openat(2)`
    ///
    /// Returns a simulated file-descriptor number (always 42 in this mock).
    pub fn sys_open(&self, path: &str, read_only: bool) -> Result<u32, ApiError> {
        let mode = if read_only { "O_RDONLY" } else { "O_RDWR" };
        println!(
            "[kernel] syscall open(\"{path}\", {mode}) → fd=42"
        );
        // In a real kernel this would look up the path in the VFS
        // (Virtual File System), check permissions in the inode, and
        // return a file-descriptor index into the process's fd table.
        Ok(42)
    }

    /// `sys_read` — ask the kernel to read bytes from an open file.
    ///
    /// Real Linux syscall: `read(2)`
    pub fn sys_read(&self, fd: u32, bytes: usize) -> Result<Vec<u8>, ApiError> {
        println!("[kernel] syscall read(fd={fd}, count={bytes}) → {bytes} bytes");
        // Return mock data (just repeated 0xAB bytes).
        Ok(vec![0xAB; bytes])
    }

    /// `sys_write` — ask the kernel to write bytes to an open file.
    ///
    /// Real Linux syscall: `write(2)`
    pub fn sys_write(&self, fd: u32, data: &[u8]) -> Result<usize, ApiError> {
        println!(
            "[kernel] syscall write(fd={fd}, count={}) → ok",
            data.len()
        );
        Ok(data.len())
    }

    /// `sys_close` — tell the kernel we are done with a file descriptor.
    ///
    /// Real Linux syscall: `close(2)`
    pub fn sys_close(&self, fd: u32) -> Result<(), ApiError> {
        println!("[kernel] syscall close(fd={fd}) → ok");
        Ok(())
    }

    /// `sys_fork` + `sys_execve` — create a new process running a program.
    ///
    /// Real Linux syscalls: `fork(2)` then `execve(2)` in the child.
    /// Modern code often uses `posix_spawn` or `clone` instead of `fork`.
    ///
    /// Returns a simulated process ID (PID).
    pub fn sys_exec(&self, program: &str, args: &[&str]) -> Result<u32, ApiError> {
        println!(
            "[kernel] syscall fork() + execve(\"{program}\", {:?}) → pid=1234",
            args
        );
        // In the real kernel: fork() copies the calling process into a new
        // process, then execve() loads the program binary, sets up the stack,
        // and jumps to its entry point.
        Ok(1234)
    }

    /// `sys_kill` — send a signal to a process.
    ///
    /// Real Linux syscall: `kill(2)`
    ///
    /// Common signals:
    /// * `SIGTERM` (15) — please terminate gracefully
    /// * `SIGKILL` (9)  — terminate immediately, cannot be caught
    pub fn sys_kill(&self, pid: u32, signal: u8) -> Result<(), ApiError> {
        println!("[kernel] syscall kill(pid={pid}, sig={signal}) → ok");
        Ok(())
    }

    /// `sys_mkdir` — create a directory.
    ///
    /// Real Linux syscall: `mkdir(2)` / `mkdirat(2)`
    pub fn sys_mkdir(&self, path: &str) -> Result<(), ApiError> {
        println!("[kernel] syscall mkdir(\"{path}\") → ok");
        Ok(())
    }

    /// Simulate mounting a filesystem (e.g. an ext4 partition).
    ///
    /// Real Linux syscall: `mount(2)`
    pub fn sys_mount(
        &self,
        device: &str,
        mount_point: &str,
        fs_type: &str,
    ) -> Result<(), ApiError> {
        println!(
            "[kernel] syscall mount(device=\"{device}\", mountpoint=\"{mount_point}\", \
             type=\"{fs_type}\") → ok"
        );
        Ok(())
    }
}

impl Default for MockKernel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_returns_fd() {
        let k = MockKernel::new();
        let fd = k.sys_open("/etc/os-release", true).unwrap();
        assert_eq!(fd, 42);
    }

    #[test]
    fn read_returns_bytes() {
        let k = MockKernel::new();
        let data = k.sys_read(42, 16).unwrap();
        assert_eq!(data.len(), 16);
    }

    #[test]
    fn exec_returns_pid() {
        let k = MockKernel::new();
        let pid = k.sys_exec("/bin/bash", &["-c", "echo hi"]).unwrap();
        assert_eq!(pid, 1234);
    }
}
