use std::collections::HashMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use os_api_client::{Request, RequestEnvelope, Response, ResponseEnvelope};
use serde::Deserialize;

#[derive(Debug)]
pub enum BrokerError {
    Io(std::io::Error),
    ParseToml(toml::de::Error),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BrokerError::Io(e) => write!(f, "io error: {e}"),
            BrokerError::ParseToml(e) => write!(f, "policy parse error: {e}"),
        }
    }
}

impl std::error::Error for BrokerError {}

impl From<std::io::Error> for BrokerError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<toml::de::Error> for BrokerError {
    fn from(value: toml::de::Error) -> Self {
        Self::ParseToml(value)
    }
}

#[derive(Debug, Clone)]
pub struct AppPolicy {
    pub fs_read_scopes: Vec<PathBuf>,
    pub fs_write_scopes: Vec<PathBuf>,
    pub allow_net_connect: bool,
    pub allow_proc_spawn: bool,
}

#[derive(Debug, Clone, Default)]
pub struct BrokerPolicy {
    apps: HashMap<String, AppPolicy>,
}

#[derive(Debug, Deserialize)]
struct PolicyFile {
    #[serde(default)]
    apps: Vec<AppPolicyRecord>,
}

#[derive(Debug, Deserialize)]
struct AppPolicyRecord {
    app_id: String,
    #[serde(default)]
    fs_read_scopes: Vec<String>,
    #[serde(default)]
    fs_write_scopes: Vec<String>,
    #[serde(default)]
    allow_net_connect: bool,
    #[serde(default)]
    allow_proc_spawn: bool,
}

impl BrokerPolicy {
    pub fn from_toml_file(path: &Path) -> Result<Self, BrokerError> {
        let raw = std::fs::read_to_string(path)?;
        let parsed: PolicyFile = toml::from_str(&raw)?;
        let mut apps = HashMap::new();

        for app in parsed.apps {
            apps.insert(
                app.app_id,
                AppPolicy {
                    fs_read_scopes: app
                        .fs_read_scopes
                        .into_iter()
                        .filter_map(|scope| sanitize_path(&scope))
                        .collect(),
                    fs_write_scopes: app
                        .fs_write_scopes
                        .into_iter()
                        .filter_map(|scope| sanitize_path(&scope))
                        .collect(),
                    allow_net_connect: app.allow_net_connect,
                    allow_proc_spawn: app.allow_proc_spawn,
                },
            );
        }

        Ok(Self { apps })
    }

    fn app(&self, app_id: &str) -> Option<&AppPolicy> {
        self.apps.get(app_id)
    }
}

fn sanitize_path(path: &str) -> Option<PathBuf> {
    let pb = PathBuf::from(path);
    if !pb.is_absolute() {
        return None;
    }

    if pb
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return None;
    }

    Some(pb)
}

fn is_path_allowed(path: &Path, scopes: &[PathBuf]) -> bool {
    scopes.iter().any(|scope| path.starts_with(scope))
}

fn deny(message: &str) -> ResponseEnvelope {
    ResponseEnvelope {
        response: Response::Error {
            message: message.to_string(),
        },
    }
}

pub fn handle_request(policy: &BrokerPolicy, envelope: RequestEnvelope) -> ResponseEnvelope {
    let Some(app_policy) = policy.app(&envelope.app_id) else {
        return deny("default deny: app has no policy entry");
    };

    match envelope.request {
        Request::FsRead { path } => {
            let Some(path_buf) = sanitize_path(&path) else {
                return deny("invalid path");
            };
            if !is_path_allowed(&path_buf, &app_policy.fs_read_scopes) {
                return deny("fs.read denied by policy scope");
            }

            match std::fs::read(path_buf) {
                Ok(data) => ResponseEnvelope {
                    response: Response::Data { data },
                },
                Err(err) => deny(&format!("fs.read failed: {err}")),
            }
        }
        Request::FsWrite { path, data } => {
            let Some(path_buf) = sanitize_path(&path) else {
                return deny("invalid path");
            };
            if !is_path_allowed(&path_buf, &app_policy.fs_write_scopes) {
                return deny("fs.write denied by policy scope");
            }

            if let Some(parent) = path_buf.parent()
                && let Err(err) = std::fs::create_dir_all(parent)
            {
                return deny(&format!("fs.write failed to create parent dirs: {err}"));
            }

            match std::fs::write(path_buf, data) {
                Ok(()) => ResponseEnvelope {
                    response: Response::Ok,
                },
                Err(err) => deny(&format!("fs.write failed: {err}")),
            }
        }
        Request::NetConnect { .. } => {
            if !app_policy.allow_net_connect {
                return deny("net.connect denied by policy");
            }
            deny("net.connect stubbed in v0")
        }
        Request::ProcSpawn { .. } => {
            if !app_policy.allow_proc_spawn {
                return deny("proc.spawn denied by policy");
            }
            deny("proc.spawn stubbed in v0")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use os_api_client::RequestEnvelope;

    fn policy_with_single_app(read_scope: &str, write_scope: &str) -> BrokerPolicy {
        let mut apps = HashMap::new();
        apps.insert(
            "example-app".to_string(),
            AppPolicy {
                fs_read_scopes: vec![PathBuf::from(read_scope)],
                fs_write_scopes: vec![PathBuf::from(write_scope)],
                allow_net_connect: false,
                allow_proc_spawn: false,
            },
        );
        BrokerPolicy { apps }
    }

    #[test]
    fn unknown_app_is_default_denied() {
        let policy = BrokerPolicy::default();
        let response = handle_request(
            &policy,
            RequestEnvelope {
                app_id: "missing-app".to_string(),
                request: Request::FsRead {
                    path: "/tmp/whatever".into(),
                },
            },
        );

        match response.response {
            Response::Error { message } => assert!(message.contains("default deny")),
            _ => panic!("expected error"),
        }
    }

    #[test]
    fn write_denied_outside_scope() {
        let policy = policy_with_single_app("/tmp/os-api-test/read", "/tmp/os-api-test/write");
        let response = handle_request(
            &policy,
            RequestEnvelope {
                app_id: "example-app".to_string(),
                request: Request::FsWrite {
                    path: "/tmp/other/file.txt".into(),
                    data: b"nope".to_vec(),
                },
            },
        );

        match response.response {
            Response::Error { message } => assert!(message.contains("fs.write denied")),
            _ => panic!("expected error"),
        }
    }

    #[test]
    fn read_allowed_in_scope() {
        let root = std::env::temp_dir().join(format!(
            "os-api-broker-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let read_dir = root.join("read");
        std::fs::create_dir_all(&read_dir).expect("create read dir");
        let target = read_dir.join("allowed.txt");
        std::fs::write(&target, b"hello").expect("write fixture");

        let policy = policy_with_single_app(
            read_dir.to_str().expect("utf8 path"),
            root.join("write").to_str().expect("utf8 path"),
        );

        let response = handle_request(
            &policy,
            RequestEnvelope {
                app_id: "example-app".to_string(),
                request: Request::FsRead {
                    path: target.to_str().expect("utf8 path").to_string(),
                },
            },
        );

        match response.response {
            Response::Data { data } => assert_eq!(data, b"hello"),
            _ => panic!("expected data"),
        }

        let _ = std::fs::remove_dir_all(root);
    }
}
