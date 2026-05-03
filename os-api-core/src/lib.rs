use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs;
use std::io::{BufRead, Write};
use std::path::Path;

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "name")]
pub enum CapabilitySpec {
    #[serde(rename = "fs.read")]
    FsRead { scope_dir: String },
    #[serde(rename = "net.connect")]
    NetConnect,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub app_id: String,
    #[serde(default)]
    pub capabilities: Vec<CapabilitySpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityGrant {
    pub token: String,
    pub capability: CapabilitySpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeniedCapability {
    pub capability: CapabilitySpec,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum InvokeOperation {
    FsRead { relative_path: String },
    NetConnect { host: String, port: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InvokeResult {
    FsRead { content: Vec<u8> },
    Ack,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Hello {
        version: u16,
        app_id: String,
    },
    RequestCapabilities {
        capabilities: Vec<CapabilitySpec>,
    },
    Invoke {
        token: String,
        operation: InvokeOperation,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    HelloAck {
        version: u16,
    },
    CapabilitiesResult {
        grants: Vec<CapabilityGrant>,
        denied: Vec<DeniedCapability>,
    },
    InvokeResult {
        result: InvokeResult,
    },
    Error {
        message: String,
    },
}

pub fn load_manifest(path: &Path) -> Result<Manifest, CoreError> {
    parse_manifest_str(&fs::read_to_string(path)?)
}

pub fn parse_manifest_str(content: &str) -> Result<Manifest, CoreError> {
    Ok(toml::from_str(content)?)
}

pub fn write_json_line<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<(), CoreError> {
    let serialized = serde_json::to_string(value)?;
    writer.write_all(serialized.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

pub fn read_json_line<R: BufRead, T: DeserializeOwned>(reader: &mut R) -> Result<T, CoreError> {
    let mut line = String::new();
    let read = reader.read_line(&mut line)?;
    if read == 0 {
        return Err(CoreError::Protocol("unexpected EOF".into()));
    }
    Ok(serde_json::from_str(line.trim_end())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_manifest_with_capabilities() {
        let manifest = parse_manifest_str(
            r#"
app_id = "demo-app"

[[capabilities]]
name = "fs.read"
scope_dir = "/tmp/demo"

[[capabilities]]
name = "net.connect"
"#,
        )
        .unwrap();

        assert_eq!(manifest.app_id, "demo-app");
        assert_eq!(manifest.capabilities.len(), 2);
        assert_eq!(
            manifest.capabilities[0],
            CapabilitySpec::FsRead {
                scope_dir: "/tmp/demo".to_string()
            }
        );
        assert_eq!(manifest.capabilities[1], CapabilitySpec::NetConnect);
    }
}
