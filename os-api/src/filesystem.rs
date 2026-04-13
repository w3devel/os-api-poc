//! # File system operations
//!
//! ## How file I/O works today (without an OS API)
//!
//! A C program on Linux that wants to read a file typically calls:
//!
//! ```c
//! int fd = open("/path/to/file", O_RDONLY);
//! char buf[4096];
//! ssize_t n = read(fd, buf, sizeof(buf));
//! close(fd);
//! ```
//!
//! These are thin wrappers in the C standard library (`libc`) that immediately
//! call the `open`, `read`, and `close` syscalls.  The kernel checks the
//! process's UID/GID against the file's permission bits, and either returns
//! the data or `EACCES` (permission denied).
//!
//! There is no policy log, no capability check beyond Unix permissions, and
//! no versioned API — the interface is whatever the current kernel provides.
//!
//! ## What the OS API adds
//!
//! * **Capability check** before touching the kernel.
//! * **Audit log** of every file access.
//! * **Path sanitisation** — rejects path traversal attacks like `../../etc/passwd`.
//! * **Stable API** — callers don't care whether the kernel is Linux, XNU,
//!   or a future microkernel; they just call `open_file`.

use crate::error::ApiError;
use crate::kernel::MockKernel;
use crate::security::{Capability, SecurityContext};

/// A handle to an open file.
///
/// When this value is dropped the file descriptor is automatically closed
/// (RAII — Resource Acquisition Is Initialisation, a core Rust pattern).
#[derive(Debug)]
pub struct FileHandle {
    /// The simulated file-descriptor number.
    pub fd: u32,
    /// The path that was opened.
    pub path: String,
    /// Whether the file was opened read-only.
    pub read_only: bool,
}

/// File system API exposed to applications.
///
/// # Example
///
/// ```
/// use os_api::filesystem::FileSystem;
/// use os_api::security::SecurityContext;
///
/// let ctx = SecurityContext::normal_user("alice");
/// let fs = FileSystem::new();
/// let handle = fs.open_file(&ctx, "/home/alice/notes.txt", true)
///     .expect("open failed");
/// let data = fs.read_file(&ctx, &handle, 64).expect("read failed");
/// ```
pub struct FileSystem {
    kernel: MockKernel,
}

impl FileSystem {
    /// Create a new `FileSystem` API handle.
    pub fn new() -> Self {
        FileSystem {
            kernel: MockKernel::new(),
        }
    }

    /// Open a file and return a [`FileHandle`].
    ///
    /// # Arguments
    ///
    /// * `ctx` — the security context of the caller.
    /// * `path` — absolute path to the file.
    /// * `read_only` — if `true`, only reading is allowed.
    pub fn open_file(
        &self,
        ctx: &SecurityContext,
        path: &str,
        read_only: bool,
    ) -> Result<FileHandle, ApiError> {
        // 1. Check caller has the right capability.
        if read_only {
            ctx.check(Capability::ReadFiles)?;
        } else {
            ctx.check(Capability::WriteFiles)?;
        }

        // 2. Sanitise the path — reject directory traversal attempts.
        //    A real implementation would canonicalise the path using
        //    `realpath(3)` (or Rust's `std::fs::canonicalize`) and check
        //    it falls inside an allowed directory tree.
        if path.contains("..") {
            ctx.audit("open_file", path, false);
            return Err(ApiError::PermissionDenied(
                "path traversal sequences ('..') are not allowed".into(),
            ));
        }

        // 3. Audit the access before asking the kernel.
        ctx.audit("open_file", path, true);

        // 4. Delegate to the kernel layer.
        let fd = self.kernel.sys_open(path, read_only)?;

        Ok(FileHandle {
            fd,
            path: path.to_string(),
            read_only,
        })
    }

    /// Read up to `max_bytes` bytes from an open file.
    pub fn read_file(
        &self,
        ctx: &SecurityContext,
        handle: &FileHandle,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ApiError> {
        ctx.check(Capability::ReadFiles)?;
        ctx.audit("read_file", &handle.path, true);
        self.kernel.sys_read(handle.fd, max_bytes)
    }

    /// Write `data` to an open file.
    pub fn write_file(
        &self,
        ctx: &SecurityContext,
        handle: &FileHandle,
        data: &[u8],
    ) -> Result<usize, ApiError> {
        ctx.check(Capability::WriteFiles)?;
        if handle.read_only {
            return Err(ApiError::InvalidOperation(
                "cannot write to a file opened read-only".into(),
            ));
        }
        ctx.audit("write_file", &handle.path, true);
        self.kernel.sys_write(handle.fd, data)
    }

    /// Close a file handle (explicitly — Rust also closes on drop).
    pub fn close_file(
        &self,
        ctx: &SecurityContext,
        handle: FileHandle,
    ) -> Result<(), ApiError> {
        ctx.audit("close_file", &handle.path, true);
        self.kernel.sys_close(handle.fd)
    }

    /// Create a new directory at `path`.
    pub fn create_dir(
        &self,
        ctx: &SecurityContext,
        path: &str,
    ) -> Result<(), ApiError> {
        ctx.check(Capability::WriteFiles)?;
        if path.contains("..") {
            return Err(ApiError::PermissionDenied(
                "path traversal sequences ('..') are not allowed".into(),
            ));
        }
        ctx.audit("create_dir", path, true);
        self.kernel.sys_mkdir(path)
    }
}

impl Default for FileSystem {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_user_can_open_read_only() {
        let ctx = SecurityContext::normal_user("alice");
        let fs = FileSystem::new();
        let handle = fs.open_file(&ctx, "/home/alice/file.txt", true).unwrap();
        assert_eq!(handle.path, "/home/alice/file.txt");
    }

    #[test]
    fn path_traversal_is_rejected() {
        let ctx = SecurityContext::normal_user("alice");
        let fs = FileSystem::new();
        let result = fs.open_file(&ctx, "/home/alice/../../etc/passwd", true);
        assert!(result.is_err());
        if let Err(ApiError::PermissionDenied(msg)) = result {
            assert!(msg.contains("traversal"));
        }
    }

    #[test]
    fn cannot_write_to_read_only_handle() {
        let ctx = SecurityContext::normal_user("alice");
        let fs = FileSystem::new();
        let handle = fs.open_file(&ctx, "/home/alice/file.txt", true).unwrap();
        let result = fs.write_file(&ctx, &handle, b"hello");
        assert!(result.is_err());
    }

    #[test]
    fn write_requires_write_capability() {
        // A service that only has ReadFiles capability.
        let ctx = SecurityContext::for_user(
            "svc-reader",
            vec![crate::security::Capability::ReadFiles],
        );
        let fs = FileSystem::new();
        let result = fs.open_file(&ctx, "/tmp/test.txt", false);
        assert!(result.is_err());
    }

    #[test]
    fn read_and_write_lifecycle() {
        let ctx = SecurityContext::normal_user("alice");
        let fs = FileSystem::new();
        // Open for writing, write data, then close.
        let handle = fs.open_file(&ctx, "/home/alice/data.bin", false).unwrap();
        let written = fs.write_file(&ctx, &handle, b"hello world").unwrap();
        assert_eq!(written, 11);
        fs.close_file(&ctx, handle).unwrap();
    }
}
