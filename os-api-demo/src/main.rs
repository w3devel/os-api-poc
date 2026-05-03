use os_api_client::BrokerClient;
use os_api_core::{load_manifest, CapabilitySpec, InvokeOperation, InvokeResult};
use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: {} <socket_path> <manifest_path> [allowed_relative_path]",
            args[0]
        );
        std::process::exit(2);
    }

    let socket_path = PathBuf::from(&args[1]);
    let manifest_path = PathBuf::from(&args[2]);
    let allowed_relative_path = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "hello.txt".to_string());

    let manifest = load_manifest(&manifest_path)?;
    println!("loaded manifest for app_id={}", manifest.app_id);

    let mut client = BrokerClient::connect(&socket_path, &manifest.app_id)?;
    println!("connected to broker");

    println!("\n1) invoke fs.read without any granted capability (expected: denied)");
    match client.invoke(
        "not-a-grant-token",
        InvokeOperation::FsRead {
            relative_path: allowed_relative_path.clone(),
        },
    ) {
        Ok(_) => println!("unexpected success (BUG)"),
        Err(e) => println!("denied as expected: {e}"),
    }

    println!("\n2) request capabilities from manifest");
    let capability_response = client.request_capabilities(manifest.capabilities.clone())?;

    for grant in &capability_response.grants {
        println!(
            "granted token={} capability={:?}",
            grant.token, grant.capability
        );
    }
    for denied in &capability_response.denied {
        println!(
            "denied capability={:?} reason={}",
            denied.capability, denied.reason
        );
    }

    println!("\n3) invoke fs.read with granted token within scope (expected: success)");
    let fs_read_grant = capability_response
        .grants
        .iter()
        .find(|grant| matches!(grant.capability, CapabilitySpec::FsRead { .. }));

    if let Some(grant) = fs_read_grant {
        match client.invoke(
            &grant.token,
            InvokeOperation::FsRead {
                relative_path: allowed_relative_path,
            },
        )? {
            InvokeResult::FsRead { content } => {
                println!("fs.read success: {}", String::from_utf8_lossy(&content));
            }
            other => println!("unexpected invoke result: {other:?}"),
        }

        println!("\n4) invoke fs.read with '../' escape (expected: denied)");
        match client.invoke(
            &grant.token,
            InvokeOperation::FsRead {
                relative_path: "../secret.txt".to_string(),
            },
        ) {
            Ok(_) => println!("unexpected success (BUG)"),
            Err(e) => println!("denied as expected: {e}"),
        }
    } else {
        println!("no fs.read capability granted; skipping read tests");
    }

    println!("\n5) net.connect should be denied by default in v0");
    let net_denied = capability_response
        .denied
        .iter()
        .any(|d| matches!(d.capability, CapabilitySpec::NetConnect));
    if net_denied {
        println!("net.connect denied by broker policy (expected)");
    } else {
        println!("net.connect was not requested in manifest");
    }

    Ok(())
}
