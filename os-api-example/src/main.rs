use std::path::PathBuf;

use os_api_client::{FsCapability, OsApiClient};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/os-api-broker.sock"));
    let manifest_path = std::env::args()
        .nth(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("os-api-example/manifest.toml"));

    let manifest = OsApiClient::load_manifest(&manifest_path)?;
    let client = OsApiClient::from_manifest_file(&socket_path, &manifest_path)?;

    println!("example app id: {}", manifest.app_id);
    println!(
        "requested capabilities: fs.read scopes={}, fs.write scopes={}, net.connect={}, proc.spawn={}",
        manifest.requested.fs_read_scopes.len(),
        manifest.requested.fs_write_scopes.len(),
        manifest.requested.net_connect,
        manifest.requested.proc_spawn
    );

    let demo_root = PathBuf::from("/tmp/os-api-poc-demo");
    let allowed_read_path = demo_root.join("read/allowed.txt");
    let denied_write_path = demo_root.join("blocked/denied.txt");

    if let Some(parent) = allowed_read_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&allowed_read_path, b"hello from scoped read")?;

    println!("\n[1] reading file within allowed fs.read scope...");
    match client.read_scoped(allowed_read_path.to_string_lossy().as_ref()) {
        Ok(bytes) => println!("allowed: {}", String::from_utf8_lossy(&bytes)),
        Err(err) => println!("unexpected denial: {err}"),
    }

    println!("\n[2] writing file outside fs.write scope (should fail-closed)...");
    match client.write_scoped(
        denied_write_path.to_string_lossy().as_ref(),
        b"this should be denied",
    ) {
        Ok(()) => println!("BUG: write unexpectedly allowed"),
        Err(err) => println!("correctly denied: {err}"),
    }

    Ok(())
}
