//! # Error types
//!
//! Every module in this crate returns `Result<T, ApiError>`.  Centralising
//! errors in one place means callers only need to handle one error type no
//! matter which part of the API they call.

use std::fmt;

/// The single error type for the entire OS API.
///
/// Each variant represents a different class of failure.  In a real
/// implementation these would carry more detail (e.g. the path that failed,
/// the capability that was denied).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// The requesting process does not have the required permission.
    PermissionDenied(String),

    /// A file or directory was not found.
    NotFound(String),

    /// The operation would leave the system in an inconsistent state.
    InvalidOperation(String),

    /// The requested package could not be found in any configured repository.
    PackageNotFound(String),

    /// A dependency of a package could not be satisfied.
    DependencyError(String),

    /// An error was returned by the (mock) kernel layer.
    KernelError(String),

    /// The system has not been fully initialised yet.
    NotInitialised(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::PermissionDenied(msg) => write!(f, "Permission denied: {msg}"),
            ApiError::NotFound(msg) => write!(f, "Not found: {msg}"),
            ApiError::InvalidOperation(msg) => write!(f, "Invalid operation: {msg}"),
            ApiError::PackageNotFound(msg) => write!(f, "Package not found: {msg}"),
            ApiError::DependencyError(msg) => write!(f, "Dependency error: {msg}"),
            ApiError::KernelError(msg) => write!(f, "Kernel error: {msg}"),
            ApiError::NotInitialised(msg) => write!(f, "Not initialised: {msg}"),
        }
    }
}

// Implement the standard Error trait so ApiError plays nicely with the broader
// Rust ecosystem (e.g. the `?` operator and libraries like `anyhow`).
impl std::error::Error for ApiError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_permission_denied() {
        let e = ApiError::PermissionDenied("write /etc/passwd".into());
        assert_eq!(e.to_string(), "Permission denied: write /etc/passwd");
    }

    #[test]
    fn display_not_found() {
        let e = ApiError::NotFound("/missing/file".into());
        assert_eq!(e.to_string(), "Not found: /missing/file");
    }
}
