use std::fmt;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub trait FsCapability {
    fn read_scoped(&self, path: &str) -> Result<Vec<u8>, ClientError>;
    fn write_scoped(&self, path: &str, data: &[u8]) -> Result<(), ClientError>;
}

pub trait NetCapability {
    fn connect(&self, host: &str, port: u16) -> Result<(), ClientError>;
}

pub trait ProcCapability {
    fn spawn(&self, command: &str, args: &[String]) -> Result<u32, ClientError>;
}

#[derive(Debug)]
pub enum ClientError {
    Io(io::Error),
    SerdeJson(serde_json::Error),
    Toml(toml::de::Error),
    InvalidResponse,
    BrokerDenied(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "io error: {e}"),
            ClientError::SerdeJson(e) => write!(f, "protocol decode/encode error: {e}"),
            ClientError::Toml(e) => write!(f, "manifest parse error: {e}"),
            ClientError::InvalidResponse => write!(f, "invalid broker response"),
            ClientError::BrokerDenied(msg) => write!(f, "request denied: {msg}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for ClientError {
    fn from(value: serde_json::Error) -> Self {
        Self::SerdeJson(value)
    }
}

impl From<toml::de::Error> for ClientError {
    fn from(value: toml::de::Error) -> Self {
        Self::Toml(value)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppManifest {
    pub app_id: String,
    #[serde(default)]
    pub requested: RequestedCapabilities,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RequestedCapabilities {
    #[serde(default)]
    pub fs_read_scopes: Vec<String>,
    #[serde(default)]
    pub fs_write_scopes: Vec<String>,
    #[serde(default)]
    pub net_connect: bool,
    #[serde(default)]
    pub proc_spawn: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub app_id: String,
    pub request: Request,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub response: Response,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Request {
    FsRead { path: String },
    FsWrite { path: String, data: Vec<u8> },
    NetConnect { host: String, port: u16 },
    ProcSpawn { command: String, args: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Data { data: Vec<u8> },
    Spawned { pid: u32 },
    Error { message: String },
}

#[derive(Debug, Clone)]
pub struct OsApiClient {
    socket_path: PathBuf,
    app_id: String,
}

impl OsApiClient {
    pub fn new<P: Into<PathBuf>, S: Into<String>>(socket_path: P, app_id: S) -> Self {
        Self {
            socket_path: socket_path.into(),
            app_id: app_id.into(),
        }
    }

    pub fn from_manifest_file<P: AsRef<Path>, Q: AsRef<Path>>(
        socket_path: P,
        manifest_path: Q,
    ) -> Result<Self, ClientError> {
        let manifest_raw = std::fs::read_to_string(manifest_path)?;
        let manifest: AppManifest = toml::from_str(&manifest_raw)?;
        Ok(Self::new(
            socket_path.as_ref().to_path_buf(),
            manifest.app_id,
        ))
    }

    pub fn load_manifest<P: AsRef<Path>>(manifest_path: P) -> Result<AppManifest, ClientError> {
        let manifest_raw = std::fs::read_to_string(manifest_path)?;
        Ok(toml::from_str(&manifest_raw)?)
    }

    fn send_request(&self, request: Request) -> Result<Response, ClientError> {
        let mut stream = UnixStream::connect(&self.socket_path)?;
        let envelope = RequestEnvelope {
            app_id: self.app_id.clone(),
            request,
        };

        let payload = serde_json::to_vec(&envelope)?;
        stream.write_all(&payload)?;
        stream.write_all(b"\n")?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            return Err(ClientError::InvalidResponse);
        }

        let response: ResponseEnvelope = serde_json::from_str(line.trim_end())?;
        Ok(response.response)
    }

    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, ClientError> {
        match self.send_request(Request::FsRead {
            path: path.to_string(),
        })? {
            Response::Data { data } => Ok(data),
            Response::Error { message } => Err(ClientError::BrokerDenied(message)),
            _ => Err(ClientError::InvalidResponse),
        }
    }

    pub fn write_file(&self, path: &str, data: &[u8]) -> Result<(), ClientError> {
        match self.send_request(Request::FsWrite {
            path: path.to_string(),
            data: data.to_vec(),
        })? {
            Response::Ok => Ok(()),
            Response::Error { message } => Err(ClientError::BrokerDenied(message)),
            _ => Err(ClientError::InvalidResponse),
        }
    }

    pub fn net_connect(&self, host: &str, port: u16) -> Result<(), ClientError> {
        match self.send_request(Request::NetConnect {
            host: host.to_string(),
            port,
        })? {
            Response::Ok => Ok(()),
            Response::Error { message } => Err(ClientError::BrokerDenied(message)),
            _ => Err(ClientError::InvalidResponse),
        }
    }

    pub fn proc_spawn(&self, command: &str, args: &[String]) -> Result<u32, ClientError> {
        match self.send_request(Request::ProcSpawn {
            command: command.to_string(),
            args: args.to_vec(),
        })? {
            Response::Spawned { pid } => Ok(pid),
            Response::Error { message } => Err(ClientError::BrokerDenied(message)),
            _ => Err(ClientError::InvalidResponse),
        }
    }
}

impl FsCapability for OsApiClient {
    fn read_scoped(&self, path: &str) -> Result<Vec<u8>, ClientError> {
        self.read_file(path)
    }

    fn write_scoped(&self, path: &str, data: &[u8]) -> Result<(), ClientError> {
        self.write_file(path, data)
    }
}

impl NetCapability for OsApiClient {
    fn connect(&self, host: &str, port: u16) -> Result<(), ClientError> {
        self.net_connect(host, port)
    }
}

impl ProcCapability for OsApiClient {
    fn spawn(&self, command: &str, args: &[String]) -> Result<u32, ClientError> {
        self.proc_spawn(command, args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parses_with_defaults() {
        let parsed: AppManifest = toml::from_str(
            r#"
app_id = "demo"

[requested]
fs_read_scopes = ["/tmp/demo"]
"#,
        )
        .expect("manifest parses");

        assert_eq!(parsed.app_id, "demo");
        assert_eq!(parsed.requested.fs_read_scopes, vec!["/tmp/demo"]);
        assert!(!parsed.requested.net_connect);
        assert!(!parsed.requested.proc_spawn);
    }

    #[test]
    fn protocol_round_trip() {
        let req = RequestEnvelope {
            app_id: "example-app".into(),
            request: Request::FsRead {
                path: "/tmp/file.txt".into(),
            },
        };

        let as_json = serde_json::to_string(&req).expect("serialize request");
        let parsed: RequestEnvelope = serde_json::from_str(&as_json).expect("deserialize request");

        match parsed.request {
            Request::FsRead { path } => assert_eq!(path, "/tmp/file.txt"),
            _ => panic!("wrong request variant"),
        }
    }
}
