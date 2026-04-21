use os_api_core::{
    read_json_line, write_json_line, CapabilityGrant, CapabilitySpec, ClientMessage, CoreError,
    DeniedCapability, InvokeOperation, InvokeResult, ServerMessage, PROTOCOL_VERSION,
};
use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::Path;

pub struct BrokerClient {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

pub struct CapabilityResponse {
    pub grants: Vec<CapabilityGrant>,
    pub denied: Vec<DeniedCapability>,
}

impl BrokerClient {
    pub fn connect(socket_path: &Path, app_id: &str) -> Result<Self, CoreError> {
        let stream = UnixStream::connect(socket_path)?;
        let writer = stream.try_clone()?;
        let mut client = Self {
            reader: BufReader::new(stream),
            writer,
        };

        client.send(&ClientMessage::Hello {
            version: PROTOCOL_VERSION,
            app_id: app_id.to_string(),
        })?;

        match client.recv()? {
            ServerMessage::HelloAck { version } if version == PROTOCOL_VERSION => Ok(client),
            ServerMessage::HelloAck { version } => Err(CoreError::Protocol(format!(
                "protocol version mismatch: broker={version} client={PROTOCOL_VERSION}"
            ))),
            ServerMessage::Error { message } => Err(CoreError::Protocol(message)),
            _ => Err(CoreError::Protocol("unexpected hello response".into())),
        }
    }

    pub fn request_capabilities(
        &mut self,
        capabilities: Vec<CapabilitySpec>,
    ) -> Result<CapabilityResponse, CoreError> {
        self.send(&ClientMessage::RequestCapabilities { capabilities })?;
        match self.recv()? {
            ServerMessage::CapabilitiesResult { grants, denied } => {
                Ok(CapabilityResponse { grants, denied })
            }
            ServerMessage::Error { message } => Err(CoreError::Protocol(message)),
            _ => Err(CoreError::Protocol(
                "unexpected request_capabilities response".into(),
            )),
        }
    }

    pub fn invoke(
        &mut self,
        token: &str,
        operation: InvokeOperation,
    ) -> Result<InvokeResult, CoreError> {
        self.send(&ClientMessage::Invoke {
            token: token.to_string(),
            operation,
        })?;

        match self.recv()? {
            ServerMessage::InvokeResult { result } => Ok(result),
            ServerMessage::Error { message } => Err(CoreError::PermissionDenied(message)),
            _ => Err(CoreError::Protocol("unexpected invoke response".into())),
        }
    }

    fn send(&mut self, message: &ClientMessage) -> Result<(), CoreError> {
        write_json_line(&mut self.writer, message)
    }

    fn recv(&mut self) -> Result<ServerMessage, CoreError> {
        read_json_line(&mut self.reader)
    }
}
