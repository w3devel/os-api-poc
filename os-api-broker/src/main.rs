use os_api_core::{
    load_manifest, read_json_line, write_json_line, CapabilityGrant, CapabilitySpec, ClientMessage,
    DeniedCapability, InvokeOperation, InvokeResult, Manifest, ServerMessage, PROTOCOL_VERSION,
};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::BufReader;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TOKEN_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
enum GrantedCapability {
    FsRead { scope_dir: PathBuf },
}

struct Session {
    app_id: Option<String>,
    grants: HashMap<String, GrantedCapability>,
}

impl Session {
    fn new() -> Self {
        Self {
            app_id: None,
            grants: HashMap::new(),
        }
    }
}

fn next_token() -> String {
    format!("cap-{}", TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed))
}

fn capability_allowed_by_manifest(manifest: &Manifest, requested: &CapabilitySpec) -> bool {
    manifest
        .capabilities
        .iter()
        .any(|declared| declared == requested)
}

fn resolve_scoped_path(scope_dir: &Path, relative_path: &str) -> Result<PathBuf, String> {
    let rel = Path::new(relative_path);

    if rel.is_absolute() {
        return Err("absolute paths are not allowed".to_string());
    }

    if rel.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err("path traversal is not allowed".to_string());
    }

    let target = scope_dir.join(rel);
    let target_canon = target
        .canonicalize()
        .map_err(|_| "target file does not exist".to_string())?;
    if !target_canon.starts_with(scope_dir) {
        return Err("path escapes capability scope".to_string());
    }

    if !target_canon.is_file() {
        return Err("target must be a regular file".to_string());
    }

    Ok(target_canon)
}

fn send_error(stream: &mut UnixStream, message: impl Into<String>) {
    let _ = write_json_line(
        stream,
        &ServerMessage::Error {
            message: message.into(),
        },
    );
}

fn handle_connection(mut stream: UnixStream, manifest: &Manifest) {
    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            send_error(&mut stream, format!("stream clone failed: {e}"));
            return;
        }
    };

    let mut reader = BufReader::new(reader_stream);
    let mut session = Session::new();

    while let Ok(message) = read_json_line::<_, ClientMessage>(&mut reader) {
        match message {
            ClientMessage::Hello { version, app_id } => {
                if version != PROTOCOL_VERSION {
                    send_error(
                        &mut stream,
                        format!(
                            "unsupported protocol version {version}, expected {PROTOCOL_VERSION}"
                        ),
                    );
                    continue;
                }
                if app_id != manifest.app_id {
                    send_error(
                        &mut stream,
                        format!("unknown app id '{app_id}' for this broker instance"),
                    );
                    continue;
                }
                session.app_id = Some(app_id);
                let _ = write_json_line(
                    &mut stream,
                    &ServerMessage::HelloAck {
                        version: PROTOCOL_VERSION,
                    },
                );
            }
            ClientMessage::RequestCapabilities { capabilities } => {
                if session.app_id.is_none() {
                    send_error(&mut stream, "hello required before requesting capabilities");
                    continue;
                }

                let mut grants = Vec::new();
                let mut denied = Vec::new();

                for capability in capabilities {
                    if !capability_allowed_by_manifest(manifest, &capability) {
                        denied.push(DeniedCapability {
                            capability,
                            reason: "not declared in manifest".to_string(),
                        });
                        continue;
                    }

                    match &capability {
                        CapabilitySpec::FsRead { scope_dir } => match fs::canonicalize(scope_dir) {
                            Ok(scope) if scope.is_dir() => {
                                let token = next_token();
                                session.grants.insert(
                                    token.clone(),
                                    GrantedCapability::FsRead {
                                        scope_dir: scope.clone(),
                                    },
                                );
                                grants.push(CapabilityGrant {
                                    token,
                                    capability: CapabilitySpec::FsRead {
                                        scope_dir: scope.to_string_lossy().to_string(),
                                    },
                                });
                            }
                            _ => denied.push(DeniedCapability {
                                capability: capability.clone(),
                                reason: "invalid fs.read scope_dir".to_string(),
                            }),
                        },
                        CapabilitySpec::NetConnect => denied.push(DeniedCapability {
                            capability,
                            reason: "net.connect denied by default in v0".to_string(),
                        }),
                    }
                }

                let _ = write_json_line(
                    &mut stream,
                    &ServerMessage::CapabilitiesResult { grants, denied },
                );
            }
            ClientMessage::Invoke { token, operation } => {
                if session.app_id.is_none() {
                    send_error(&mut stream, "hello required before invoke");
                    continue;
                }

                let Some(granted) = session.grants.get(&token).cloned() else {
                    send_error(&mut stream, "unknown or unauthorized capability token");
                    continue;
                };

                match (granted, operation) {
                    (
                        GrantedCapability::FsRead { scope_dir },
                        InvokeOperation::FsRead { relative_path },
                    ) => {
                        let scoped = match resolve_scoped_path(&scope_dir, &relative_path) {
                            Ok(path) => path,
                            Err(message) => {
                                send_error(&mut stream, message);
                                continue;
                            }
                        };

                        match fs::read(scoped) {
                            Ok(content) => {
                                let _ = write_json_line(
                                    &mut stream,
                                    &ServerMessage::InvokeResult {
                                        result: InvokeResult::FsRead { content },
                                    },
                                );
                            }
                            Err(e) => send_error(&mut stream, format!("fs.read failed: {e}")),
                        }
                    }
                    (_, InvokeOperation::NetConnect { .. }) => {
                        send_error(&mut stream, "net.connect is denied in v0");
                    }
                }
            }
        }
    }
}

fn remove_stale_socket(path: &Path) -> std::io::Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_socket() {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <socket_path> <manifest_path>", args[0]);
        std::process::exit(2);
    }

    let socket_path = PathBuf::from(&args[1]);
    let manifest_path = PathBuf::from(&args[2]);
    let manifest = load_manifest(&manifest_path)?;

    remove_stale_socket(&socket_path)?;
    let listener = UnixListener::bind(&socket_path)?;
    println!(
        "broker listening on {} for app_id={}",
        socket_path.display(),
        manifest.app_id
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => handle_connection(stream, &manifest),
            Err(e) => eprintln!("accept error: {e}"),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::resolve_scoped_path;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        dir.push(format!("os-api-broker-test-{name}-{ts}"));
        dir
    }

    #[test]
    fn resolve_scoped_path_rejects_parent_traversal() {
        let root = unique_dir("traversal");
        fs::create_dir_all(&root).unwrap();
        let allowed = root.join("allowed");
        fs::create_dir_all(&allowed).unwrap();
        fs::write(allowed.join("ok.txt"), b"ok").unwrap();

        let scope = fs::canonicalize(&allowed).unwrap();
        let err = resolve_scoped_path(&scope, "../secret.txt").unwrap_err();
        assert!(err.contains("traversal"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resolve_scoped_path_allows_file_inside_scope() {
        let root = unique_dir("allow");
        fs::create_dir_all(&root).unwrap();
        let allowed = root.join("allowed");
        fs::create_dir_all(&allowed).unwrap();
        let file = allowed.join("ok.txt");
        fs::write(&file, b"ok").unwrap();

        let scope = fs::canonicalize(&allowed).unwrap();
        let resolved = resolve_scoped_path(&scope, "ok.txt").unwrap();
        assert_eq!(resolved, fs::canonicalize(file).unwrap());

        fs::remove_dir_all(root).unwrap();
    }
}
