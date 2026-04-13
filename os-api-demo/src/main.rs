//! # OS API Proof-of-Concept — Interactive Demo
//!
//! This binary walks through all the major API scenarios in sequence:
//!
//!   1. System boot (full four-stage sequence)
//!   2. First-run setup
//!   3. File system operations (open, read, write, path-traversal rejection)
//!   4. Process management (launch, list, terminate)
//!   5. Package management (search, install with dependency resolution, remove)
//!   6. Security demonstration (showing that a normal user cannot install packages)
//!
//! Run with:
//!
//! ```shell
//! cargo run --bin os-api-demo
//! ```

use os_api::boot::BootManager;
use os_api::filesystem::FileSystem;
use os_api::package::{PackageManager, Repository};
use os_api::process::ProcessManager;
use os_api::security::SecurityContext;

fn separator(title: &str) {
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  {title}");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

fn main() {
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│              OS API — Proof of Concept Demo                     │");
    println!("│                                                                  │");
    println!("│  This demo shows how an API layer sitting between applications  │");
    println!("│  and the kernel can improve security, auditability and          │");
    println!("│  portability compared to direct syscall access.                 │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    // ── 1. BOOT ──────────────────────────────────────────────────────────────
    separator("1 · System Boot Sequence");

    // The boot process requires root (superuser) privileges.
    let root_ctx = SecurityContext::superuser();

    let mut boot_manager = BootManager::new();
    boot_manager
        .run_full_boot(&root_ctx)
        .expect("Boot sequence failed");

    // ── 2. FIRST-RUN SETUP ───────────────────────────────────────────────────
    separator("2 · First-Run Setup");

    boot_manager
        .first_run_setup(&root_ctx, "debian-poc", "alice")
        .expect("First-run setup failed");

    // ── 3. FILE SYSTEM OPERATIONS ────────────────────────────────────────────
    separator("3 · File System Operations");

    // Normal users get ReadFiles + WriteFiles capabilities.
    let alice_ctx = SecurityContext::normal_user("alice");
    let fs = FileSystem::new();

    println!("\n[demo] Alice opens her notes file for reading …");
    let handle = fs
        .open_file(&alice_ctx, "/home/alice/notes.txt", true)
        .expect("open failed");

    println!("[demo] Alice reads 64 bytes …");
    let _data = fs
        .read_file(&alice_ctx, &handle, 64)
        .expect("read failed");

    println!("[demo] Alice closes the file …");
    fs.close_file(&alice_ctx, handle).expect("close failed");

    println!("\n[demo] Alice opens a file for writing …");
    let write_handle = fs
        .open_file(&alice_ctx, "/home/alice/output.txt", false)
        .expect("open for write failed");
    let bytes = fs
        .write_file(&alice_ctx, &write_handle, b"Hello from the OS API!")
        .expect("write failed");
    println!("[demo] Wrote {bytes} bytes.");
    fs.close_file(&alice_ctx, write_handle).expect("close failed");

    println!("\n[demo] Demonstrating path-traversal protection …");
    match fs.open_file(&alice_ctx, "/home/alice/../../etc/shadow", true) {
        Ok(_) => println!("[demo] ERROR: path traversal was allowed (this is a bug!)"),
        Err(e) => println!("[demo] Correctly rejected: {e}"),
    }

    // ── 4. PROCESS MANAGEMENT ────────────────────────────────────────────────
    separator("4 · Process Management");

    let mut pm = ProcessManager::new();

    println!("\n[demo] Launching Firefox …");
    let firefox_pid = pm
        .launch(&alice_ctx, "/usr/bin/firefox", &["--new-window"])
        .expect("launch failed");

    println!("\n[demo] Launching a text editor …");
    let _editor_pid = pm
        .launch(&alice_ctx, "/usr/bin/gedit", &["/home/alice/notes.txt"])
        .expect("launch failed");

    let running = pm.list_running();
    println!("\n[demo] Running processes ({} total):", running.len());
    for p in &running {
        println!("  pid={} exe='{}' owner='{}'", p.pid, p.executable, p.owner);
    }

    println!("\n[demo] Terminating Firefox (pid={firefox_pid}) …");
    pm.terminate(&alice_ctx, firefox_pid)
        .expect("terminate failed");

    println!(
        "[demo] Running processes after terminate: {}",
        pm.list_running().len()
    );

    // ── 5. PACKAGE MANAGEMENT ────────────────────────────────────────────────
    separator("5 · Package Management");

    let repo = Repository::demo();
    let mut pkg_mgr = PackageManager::new(repo);

    println!("\n[demo] Searching for packages matching 'ssh' …");
    let results = pkg_mgr.search("ssh");
    for p in &results {
        println!("  {} {} — {}", p.name, p.version, p.description);
    }

    println!("\n[demo] Installing 'curl' (as root, with dependency resolution) …");
    pkg_mgr
        .install(&root_ctx, "curl")
        .expect("install failed");

    println!("\n[demo] Installed packages:");
    let mut installed = pkg_mgr.list_installed();
    installed.sort();
    for name in &installed {
        println!("  {name}");
    }

    println!("\n[demo] Removing 'curl' …");
    pkg_mgr.remove(&root_ctx, "curl").expect("remove failed");

    // ── 6. SECURITY DEMONSTRATION ────────────────────────────────────────────
    separator("6 · Security — Normal User Cannot Install Packages");

    println!(
        "\n[demo] Alice (normal user) tries to install 'firefox' without ManagePackages capability …"
    );
    match pkg_mgr.install(&alice_ctx, "firefox") {
        Ok(_) => println!("[demo] ERROR: install succeeded (this is a bug!)"),
        Err(e) => println!("[demo] Correctly blocked: {e}"),
    }

    // ── DONE ─────────────────────────────────────────────────────────────────
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Demo complete ✓");
    println!();
    println!("  Key takeaways:");
    println!("  • Every operation is checked against a capability set");
    println!("    BEFORE the kernel is called.");
    println!("  • Every operation is logged to an audit trail.");
    println!("  • The API provides a stable, versioned surface — the");
    println!("    kernel implementation can be swapped without changing");
    println!("    application code.");
    println!("  • Path traversal and other simple attacks are blocked");
    println!("    at the API layer.");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}
