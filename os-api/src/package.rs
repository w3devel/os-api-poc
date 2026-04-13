//! # Package management (Debian/APT style)
//!
//! ## How Debian package management works today
//!
//! Debian and Ubuntu use the **APT** (Advanced Package Tool) ecosystem:
//!
//! ```text
//! /etc/apt/sources.list          — list of repository URLs
//! /var/lib/apt/lists/            — cached repository index files
//! /var/lib/dpkg/status           — database of installed packages
//! /var/cache/apt/archives/       — downloaded .deb files
//! ```
//!
//! A typical install flow (`apt install firefox`):
//!
//! 1. APT reads `sources.list` and fetches the package index from each
//!    repository (over HTTPS).
//! 2. APT resolves dependencies — Firefox needs `libgtk-3`, `libdbus`, etc.
//! 3. APT downloads the `.deb` files.
//! 4. `dpkg` unpacks each `.deb` and runs the `preinst`, `postinst` scripts
//!    with **root** privileges.
//! 5. The new binaries appear under `/usr/bin`, `/usr/lib`, etc.
//!
//! The big security concern is step 4: the `postinst` shell script runs as
//! root and can do *anything* on the system.  APT verifies package signatures
//! (GPG) but the scripts themselves are trusted implicitly.
//!
//! ## What the OS API adds
//!
//! * **`ManagePackages` capability** required — ordinary user processes
//!   cannot install software.
//! * **Dependency resolution** surfaced through the API so tools can query
//!   what *would* be installed before confirming.
//! * **Audit trail** — every install/remove is logged.
//! * **Policy hooks** — an organisation could add a policy check that
//!   prevents installation of unapproved packages.

use std::collections::HashMap;

use crate::error::ApiError;
use crate::security::{Capability, SecurityContext};

/// A package available in a repository.
#[derive(Debug, Clone)]
pub struct Package {
    /// Package name (e.g. `"firefox"`).
    pub name: String,
    /// Version string (e.g. `"120.0.1-1"`).
    pub version: String,
    /// Short description.
    pub description: String,
    /// Names of packages that must be installed first.
    pub dependencies: Vec<String>,
    /// Approximate installed size in kibibytes.
    pub installed_size_kb: u64,
}

/// A simulated package repository (like a Debian mirror).
///
/// In a real system this would be populated by fetching and parsing the
/// `Packages.gz` file from each entry in `/etc/apt/sources.list`.
pub struct Repository {
    packages: HashMap<String, Package>,
}

impl Repository {
    /// Create a repository pre-populated with a small set of demo packages.
    pub fn demo() -> Self {
        let mut packages = HashMap::new();

        let pkg = |name: &str, version: &str, desc: &str, deps: Vec<&str>, size: u64| Package {
            name: name.to_string(),
            version: version.to_string(),
            description: desc.to_string(),
            dependencies: deps.iter().map(|s| s.to_string()).collect(),
            installed_size_kb: size,
        };

        packages.insert(
            "libc6".into(),
            pkg("libc6", "2.38-1", "GNU C Library", vec![], 13_000),
        );
        packages.insert(
            "libssl3".into(),
            pkg("libssl3", "3.0.11-1", "OpenSSL shared library", vec!["libc6"], 5_000),
        );
        packages.insert(
            "openssh-client".into(),
            pkg(
                "openssh-client",
                "9.5p1-1",
                "Secure Shell client",
                vec!["libc6", "libssl3"],
                2_500,
            ),
        );
        packages.insert(
            "curl".into(),
            pkg(
                "curl",
                "8.4.0-1",
                "Command-line tool for transferring data",
                vec!["libc6", "libssl3"],
                700,
            ),
        );
        packages.insert(
            "firefox".into(),
            pkg(
                "firefox",
                "120.0.1-1",
                "Mozilla Firefox web browser",
                vec!["libc6", "libssl3"],
                260_000,
            ),
        );
        packages.insert(
            "vim".into(),
            pkg("vim", "9.0.2079-1", "Vi IMproved text editor", vec!["libc6"], 3_800),
        );

        Repository { packages }
    }

    /// Look up a package by name.
    pub fn find(&self, name: &str) -> Option<&Package> {
        self.packages.get(name)
    }
}

/// Tracks which packages are installed and drives install/remove operations.
///
/// # Example
///
/// ```
/// use os_api::package::{PackageManager, Repository};
/// use os_api::security::SecurityContext;
///
/// let ctx = SecurityContext::superuser();
/// let repo = Repository::demo();
/// let mut pm = PackageManager::new(repo);
///
/// pm.install(&ctx, "curl").expect("install failed");
/// assert!(pm.is_installed("curl"));
/// ```
pub struct PackageManager {
    repo: Repository,
    /// Names of currently installed packages.
    installed: HashMap<String, Package>,
}

impl PackageManager {
    /// Create a new `PackageManager` backed by the given `Repository`.
    pub fn new(repo: Repository) -> Self {
        PackageManager {
            repo,
            installed: HashMap::new(),
        }
    }

    /// Resolve the full list of packages that need to be installed
    /// (including dependencies) in install order.
    ///
    /// This is a simplified resolver: it does a depth-first traversal of the
    /// dependency graph.  A real APT resolver handles version constraints,
    /// conflicts, and virtual packages (e.g. `www-browser`).
    /// Returns the names of packages that must be installed, in install order
    /// (dependencies before the package that needs them).
    fn resolve_deps(
        &self,
        name: &str,
        order: &mut Vec<String>,
        visited: &mut Vec<String>,
    ) -> Result<(), ApiError> {
        if visited.contains(&name.to_string()) {
            return Ok(()); // already queued
        }
        let pkg = self.repo.find(name).ok_or_else(|| {
            ApiError::PackageNotFound(format!("'{name}' not found in repository"))
        })?;
        visited.push(name.to_string());
        // Clone the dependency list to avoid holding a borrow across the
        // recursive call (which needs `&self` again).
        let deps: Vec<String> = pkg.dependencies.clone();
        for dep in &deps {
            self.resolve_deps(dep, order, visited)?;
        }
        order.push(name.to_string());
        Ok(())
    }

    /// Install a package and all its dependencies.
    pub fn install(&mut self, ctx: &SecurityContext, name: &str) -> Result<(), ApiError> {
        ctx.check(Capability::ManagePackages)?;

        if self.is_installed(name) {
            println!("[package] '{name}' is already installed — skipping.");
            return Ok(());
        }

        // Resolve install order (dependencies first).
        let mut order: Vec<String> = Vec::new();
        let mut visited: Vec<String> = Vec::new();
        self.resolve_deps(name, &mut order, &mut visited)?;

        // Collect full package info now (separate from the borrow used in
        // the loop below that mutates `self.installed`).
        let to_install: Vec<Package> = order
            .iter()
            .filter_map(|n| self.repo.find(n).cloned())
            .collect();

        println!("[package] The following packages will be installed:");
        for pkg in &to_install {
            println!(
                "[package]   {} {} ({} KiB)",
                pkg.name, pkg.version, pkg.installed_size_kb
            );
        }

        for pkg in to_install {
            if self.is_installed(&pkg.name) {
                continue;
            }
            println!(
                "[package] Downloading {} {} …",
                pkg.name, pkg.version
            );
            println!(
                "[package] Verifying GPG signature for {} …",
                pkg.name
            );
            println!(
                "[package] Unpacking {} …",
                pkg.name
            );
            println!(
                "[package] Running postinst script for {} (sandboxed) …",
                pkg.name
            );
            println!("[package] {} installed ✓", pkg.name);
            self.installed.insert(pkg.name.clone(), pkg);
        }

        ctx.audit("install", name, true);
        Ok(())
    }

    /// Remove an installed package.
    ///
    /// This does **not** remove configuration files (equivalent to
    /// `apt remove`, not `apt purge`).
    pub fn remove(&mut self, ctx: &SecurityContext, name: &str) -> Result<(), ApiError> {
        ctx.check(Capability::ManagePackages)?;

        if !self.is_installed(name) {
            return Err(ApiError::NotFound(format!(
                "'{name}' is not installed"
            )));
        }

        println!("[package] Removing {name} …");
        println!("[package] Running prerm script for {name} (sandboxed) …");
        self.installed.remove(name);
        ctx.audit("remove", name, true);
        println!("[package] {name} removed ✓ (config files retained)");
        Ok(())
    }

    /// Check whether a package is currently installed.
    pub fn is_installed(&self, name: &str) -> bool {
        self.installed.contains_key(name)
    }

    /// Return a list of installed package names.
    pub fn list_installed(&self) -> Vec<&str> {
        self.installed.keys().map(String::as_str).collect()
    }

    /// Search for packages whose name or description contains `query`.
    pub fn search<'a>(&'a self, query: &str) -> Vec<&'a Package> {
        self.repo
            .packages
            .values()
            .filter(|p| {
                p.name.contains(query) || p.description.to_lowercase().contains(query)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn su() -> SecurityContext {
        SecurityContext::superuser()
    }

    #[test]
    fn install_resolves_dependencies() {
        let ctx = su();
        let mut pm = PackageManager::new(Repository::demo());
        pm.install(&ctx, "curl").unwrap();
        // curl depends on libc6 and libssl3 — all three should be installed.
        assert!(pm.is_installed("curl"));
        assert!(pm.is_installed("libc6"));
        assert!(pm.is_installed("libssl3"));
    }

    #[test]
    fn install_is_idempotent() {
        let ctx = su();
        let mut pm = PackageManager::new(Repository::demo());
        pm.install(&ctx, "vim").unwrap();
        // Installing again should succeed without error.
        pm.install(&ctx, "vim").unwrap();
        assert_eq!(pm.list_installed().len(), 2); // vim + libc6
    }

    #[test]
    fn remove_installed_package() {
        let ctx = su();
        let mut pm = PackageManager::new(Repository::demo());
        pm.install(&ctx, "vim").unwrap();
        pm.remove(&ctx, "vim").unwrap();
        assert!(!pm.is_installed("vim"));
    }

    #[test]
    fn remove_not_installed_returns_error() {
        let ctx = su();
        let mut pm = PackageManager::new(Repository::demo());
        let result = pm.remove(&ctx, "vim");
        assert!(result.is_err());
    }

    #[test]
    fn install_missing_package_returns_error() {
        let ctx = su();
        let mut pm = PackageManager::new(Repository::demo());
        let result = pm.install(&ctx, "nonexistent-package");
        assert!(result.is_err());
        if let Err(ApiError::PackageNotFound(msg)) = result {
            assert!(msg.contains("nonexistent-package"));
        }
    }

    #[test]
    fn normal_user_cannot_install() {
        let ctx = SecurityContext::normal_user("alice");
        let mut pm = PackageManager::new(Repository::demo());
        let result = pm.install(&ctx, "vim");
        assert!(result.is_err());
    }

    #[test]
    fn search_returns_matches() {
        let pm = PackageManager::new(Repository::demo());
        let results = pm.search("ssh");
        assert!(!results.is_empty());
        assert!(results.iter().any(|p| p.name == "openssh-client"));
    }
}
