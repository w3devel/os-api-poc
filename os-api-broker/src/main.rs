use std::env;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

use os_api_broker::{BrokerPolicy, handle_request};
use os_api_client::{RequestEnvelope, Response, ResponseEnvelope};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket_path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/os-api-broker.sock"));
    let policy_path = env::args()
        .nth(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("policy.example.toml"));

    let policy = BrokerPolicy::from_toml_file(&policy_path)?;

    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    println!(
        "os-api-broker listening on {} with policy {}",
        socket_path.display(),
        policy_path.display()
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(err) = handle_stream(stream, &policy) {
                    eprintln!("connection handling error: {err}");
                }
            }
            Err(err) => {
                eprintln!("accept error: {err}");
            }
        }
    }

    Ok(())
}

fn handle_stream(
    mut stream: UnixStream,
    policy: &BrokerPolicy,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut line = String::new();
    {
        let mut reader = BufReader::new(&stream);
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            return Ok(());
        }
    }

    let response = match serde_json::from_str::<RequestEnvelope>(line.trim_end()) {
        Ok(request) => handle_request(policy, request),
        Err(err) => ResponseEnvelope {
            response: Response::Error {
                message: format!("invalid request: {err}"),
            },
        },
    };

    let payload = serde_json::to_vec(&response)?;
    stream.write_all(&payload)?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    Ok(())
}
