//! Local control socket: one JSON request line, one JSON response line.
//!
//! The socket sits in the 0700 state directory, so only this user can reach it.
//! Nothing here can approve a request: pairing and credential release still
//! require Touch ID.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};

use crate::storage::Device;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "lowercase")]
pub enum Request {
    Pair { name: Option<String> },
    Status,
    Lock,
    Revoke { name: String },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    pub at: u64,
    pub device: String,
    pub query: String,
    pub outcome: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Status {
    pub unlocked: bool,
    pub relay: String,
    pub devices: Vec<Device>,
    pub recent: Vec<Decision>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
}

impl Response {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: Some(message.into()),
            ..Default::default()
        }
    }
    pub fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: Some(message.into()),
            ..Default::default()
        }
    }
}

pub type Envelope = (Request, oneshot::Sender<Response>);

pub fn socket_path(dir: &Path) -> PathBuf {
    dir.join("control.sock")
}

/// Accept connections and forward each request to the service loop.
pub async fn serve(path: PathBuf, tx: mpsc::Sender<Envelope>) -> std::io::Result<()> {
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    loop {
        let (stream, _) = listener.accept().await?;
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = handle(stream, tx).await;
        });
    }
}

async fn handle(stream: UnixStream, tx: mpsc::Sender<Envelope>) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    BufReader::new(read).read_line(&mut line).await?;
    let response = match serde_json::from_str::<Request>(&line) {
        Ok(req) => {
            let (rtx, rrx) = oneshot::channel();
            if tx.send((req, rtx)).await.is_err() {
                Response::err("service is shutting down")
            } else {
                rrx.await.unwrap_or_else(|_| Response::err("no reply"))
            }
        }
        Err(e) => Response::err(format!("bad request: {e}")),
    };
    let mut out = serde_json::to_vec(&response).map_err(std::io::Error::other)?;
    out.push(b'\n');
    write.write_all(&out).await
}

/// Send one request to a running service.
pub async fn call(path: &Path, req: &Request) -> std::io::Result<Response> {
    let stream = UnixStream::connect(path).await.map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "cannot reach the aac-touchid service at {}: {e}",
                path.display()
            ),
        )
    })?;
    let (read, mut write) = stream.into_split();
    let mut out = serde_json::to_vec(req).map_err(std::io::Error::other)?;
    out.push(b'\n');
    write.write_all(&out).await?;
    let mut line = String::new();
    BufReader::new(read).read_line(&mut line).await?;
    serde_json::from_str(&line).map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format() {
        let r: Request = serde_json::from_str(r#"{"cmd":"pair","name":"nuc"}"#).expect("parse");
        assert_eq!(
            r,
            Request::Pair {
                name: Some("nuc".into())
            }
        );
        let r: Request = serde_json::from_str(r#"{"cmd":"status"}"#).expect("parse");
        assert_eq!(r, Request::Status);
        assert!(serde_json::from_str::<Request>(r#"{"cmd":"approve"}"#).is_err());
    }

    #[tokio::test]
    async fn round_trip_over_socket() {
        let dir = std::env::temp_dir().join(format!("aac-touchid-ctl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = socket_path(&dir);
        let (tx, mut rx) = mpsc::channel::<Envelope>(4);
        let server = tokio::spawn(serve(path.clone(), tx));
        tokio::spawn(async move {
            while let Some((req, reply)) = rx.recv().await {
                let _ = reply.send(match req {
                    Request::Lock => Response::ok("locked"),
                    _ => Response::err("unexpected"),
                });
            }
        });
        let mut resp = None;
        for _ in 0..50 {
            if let Ok(r) = call(&path, &Request::Lock).await {
                resp = Some(r);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(resp, Some(Response::ok("locked")));
        server.abort();
    }
}
