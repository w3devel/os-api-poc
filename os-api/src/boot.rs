//! # Boot and first-run setup
//!
//! ## How Linux boots today (without an OS API)
//!
//! ```text
//!  1. BIOS / UEFI firmware runs power-on self-test (POST)
//!  2. UEFI loads the GRUB bootloader from the EFI System Partition
//!  3. GRUB loads the kernel image (vmlinuz) and initial RAM disk (initrd)
//!  4. Kernel decompresses itself, initialises CPU, memory, devices
//!  5. Kernel mounts the root filesystem (/)
//!  6. Kernel executes /sbin/init (systemd on most modern Debian/Ubuntu systems)
//!  7. systemd reads unit files and starts services in dependency order:
//!       udev (devices), networking, dbus, login manager, desktop, …
//! ```
//!
//! Each step is a hard-coded pipeline.  If you want to change the order or
//! add a step you must modify kernel parameters, initrd scripts, or systemd
//! unit files spread across many directories.
//!
//! ## How an OS API changes this
//!
//! With an OS API the boot sequence becomes a series of well-defined API
//! calls.  Each call checks security context, validates state, calls the
//! mock kernel, and emits an audit log.  Any component of the system can
//! be replaced without breaking the boot sequence — it just needs to
//! implement the same API interface.

use crate::error::ApiError;
use crate::kernel::MockKernel;
use crate::security::{Capability, SecurityContext};

/// The stages the system moves through during boot.
///
/// The OS API enforces that these stages are visited in order — you cannot
/// jump from `Firmware` to `ServicesStarted` without going through the
/// intermediate stages.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum BootStage {
    /// BIOS/UEFI has handed control to the bootloader.
    Firmware,
    /// Kernel has been loaded into memory.
    KernelLoaded,
    /// Root filesystem is mounted and accessible.
    RootFsMounted,
    /// Core services (udev, dbus, networking …) are running.
    ServicesStarted,
    /// The login prompt or display manager is active — system is ready.
    UserSpaceReady,
}

/// Drives the system through its boot sequence.
///
/// # Example
///
/// ```
/// use os_api::boot::BootManager;
/// use os_api::security::SecurityContext;
///
/// let ctx = SecurityContext::superuser();
/// let mut bm = BootManager::new();
/// bm.run_full_boot(&ctx).expect("boot failed");
/// ```
pub struct BootManager {
    /// The current boot stage.
    pub stage: BootStage,
    kernel: MockKernel,
}

impl BootManager {
    /// Create a new `BootManager` starting at the firmware stage.
    pub fn new() -> Self {
        BootManager {
            stage: BootStage::Firmware,
            kernel: MockKernel::new(),
        }
    }

    /// Advance from `Firmware` → `KernelLoaded`.
    ///
    /// In reality the bootloader (GRUB) reads the kernel ELF binary from disk
    /// and places it in RAM, then jumps to the kernel entry point.  Here we
    /// simulate that with a single function call.
    pub fn load_kernel(&mut self, ctx: &SecurityContext) -> Result<(), ApiError> {
        ctx.check(Capability::BootControl)?;
        if self.stage != BootStage::Firmware {
            return Err(ApiError::InvalidOperation(
                "load_kernel called out of sequence".into(),
            ));
        }
        println!("[boot] Loading kernel image (vmlinuz) into memory …");
        println!("[boot] Loading initial RAM disk (initrd) …");
        self.stage = BootStage::KernelLoaded;
        ctx.audit("load_kernel", "vmlinuz", true);
        Ok(())
    }

    /// Advance from `KernelLoaded` → `RootFsMounted`.
    ///
    /// The kernel probes hardware, initialises device drivers, then mounts
    /// the root filesystem.  On Debian the root fs is usually ext4 on an
    /// LVM volume or a plain partition like `/dev/sda1`.
    pub fn mount_root_fs(
        &mut self,
        ctx: &SecurityContext,
        device: &str,
    ) -> Result<(), ApiError> {
        ctx.check(Capability::BootControl)?;
        if self.stage != BootStage::KernelLoaded {
            return Err(ApiError::InvalidOperation(
                "mount_root_fs called out of sequence".into(),
            ));
        }
        println!("[boot] Kernel initialising CPU and memory subsystems …");
        println!("[boot] Probing PCI bus and loading device drivers …");
        self.kernel.sys_mount(device, "/", "ext4")?;
        self.stage = BootStage::RootFsMounted;
        ctx.audit("mount_root_fs", device, true);
        Ok(())
    }

    /// Advance from `RootFsMounted` → `ServicesStarted`.
    ///
    /// This is what systemd (or the older SysV init) does: starts daemons
    /// in the correct order based on their dependency declarations.
    pub fn start_services(&mut self, ctx: &SecurityContext) -> Result<(), ApiError> {
        ctx.check(Capability::BootControl)?;
        if self.stage != BootStage::RootFsMounted {
            return Err(ApiError::InvalidOperation(
                "start_services called out of sequence".into(),
            ));
        }
        let services = [
            ("udev", "device manager — detects and configures hardware"),
            ("dbus", "inter-process message bus"),
            ("networking", "brings up network interfaces"),
            ("sshd", "SSH daemon — remote login"),
            ("cron", "scheduled task runner"),
        ];
        for (name, description) in &services {
            println!("[boot] Starting service '{name}' ({description}) …");
            // In a real system we would call execve to launch each daemon.
            self.kernel
                .sys_exec(&format!("/lib/systemd/systemd-{name}"), &["--start"])
                .ok(); // ignore errors in this mock
        }
        self.stage = BootStage::ServicesStarted;
        ctx.audit("start_services", "all", true);
        Ok(())
    }

    /// Advance from `ServicesStarted` → `UserSpaceReady`.
    ///
    /// Starts the login manager.  On a server this would be `getty` (text
    /// login).  On a desktop Debian system this would be GDM or LightDM.
    pub fn start_user_space(&mut self, ctx: &SecurityContext) -> Result<(), ApiError> {
        ctx.check(Capability::BootControl)?;
        if self.stage != BootStage::ServicesStarted {
            return Err(ApiError::InvalidOperation(
                "start_user_space called out of sequence".into(),
            ));
        }
        println!("[boot] Starting login manager (getty / display manager) …");
        println!("[boot] System is ready. Presenting login prompt.");
        self.stage = BootStage::UserSpaceReady;
        ctx.audit("start_user_space", "login-manager", true);
        Ok(())
    }

    /// Run all four boot stages in sequence.
    ///
    /// This is the high-level convenience function that most callers will use.
    pub fn run_full_boot(&mut self, ctx: &SecurityContext) -> Result<(), ApiError> {
        self.load_kernel(ctx)?;
        self.mount_root_fs(ctx, "/dev/sda1")?;
        self.start_services(ctx)?;
        self.start_user_space(ctx)?;
        println!("[boot] Boot complete ✓");
        Ok(())
    }

    /// Perform first-run setup for a freshly installed Debian system.
    ///
    /// On a real Debian install, `debian-installer` or `calamares` takes
    /// care of this.  This mock shows the kinds of operations that happen:
    /// creating users, setting timezone/locale, configuring networking.
    pub fn first_run_setup(
        &self,
        ctx: &SecurityContext,
        hostname: &str,
        username: &str,
    ) -> Result<(), ApiError> {
        ctx.check(Capability::BootControl)?;
        if self.stage != BootStage::UserSpaceReady {
            return Err(ApiError::NotInitialised(
                "first_run_setup requires the system to be fully booted".into(),
            ));
        }
        println!("[firstrun] Setting hostname to '{hostname}' …");
        // /etc/hostname — stores the system's hostname
        self.kernel.sys_open("/etc/hostname", false)?;

        println!("[firstrun] Creating user '{username}' with home directory …");
        self.kernel
            .sys_mkdir(&format!("/home/{username}"))?;

        println!("[firstrun] Setting default locale (en_US.UTF-8) …");
        println!("[firstrun] Setting default timezone (UTC) …");
        println!("[firstrun] Writing /etc/fstab (filesystem mount table) …");
        println!("[firstrun] First-run setup complete ✓");
        ctx.audit("first_run_setup", hostname, true);
        Ok(())
    }
}

impl Default for BootManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn superuser() -> SecurityContext {
        SecurityContext::superuser()
    }

    #[test]
    fn full_boot_succeeds() {
        let ctx = superuser();
        let mut bm = BootManager::new();
        bm.run_full_boot(&ctx).expect("boot should succeed");
        assert_eq!(bm.stage, BootStage::UserSpaceReady);
    }

    #[test]
    fn stages_must_be_in_order() {
        let ctx = superuser();
        let mut bm = BootManager::new();
        // Skip load_kernel and jump straight to mount_root_fs — should fail.
        let result = bm.mount_root_fs(&ctx, "/dev/sda1");
        assert!(result.is_err());
    }

    #[test]
    fn non_superuser_cannot_boot() {
        let ctx = crate::security::SecurityContext::normal_user("alice");
        let mut bm = BootManager::new();
        let result = bm.load_kernel(&ctx);
        assert!(result.is_err());
    }

    #[test]
    fn first_run_requires_booted_system() {
        let ctx = superuser();
        let bm = BootManager::new(); // still at Firmware stage
        let result = bm.first_run_setup(&ctx, "myhost", "alice");
        assert!(result.is_err());
    }
}
