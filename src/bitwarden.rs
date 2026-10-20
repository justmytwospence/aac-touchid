//! Vault access through the official Bitwarden CLI, privately.
//!
//! One long-lived `bw serve` child serves Bitwarden's REST API over an
//! inherited socket pair (`--hostname fd+connected://3`, a supported `bw
//! serve` mode). Only this process holds the other end: nothing listens on a
//! port or a path. The master password travels once, in the body of
//! `POST /unlock`, and the vault key stays inside that child. No secret is
//! ever put in an environment variable or a command line, where any process
//! of the same user could read it (`ps -E`).
//!
//! Item parsing follows Bitwarden Agent Access `ap-cli`
//! (`providers/bitwarden.rs`, v0.11.0, Apache-2.0).

use std::os::fd::{AsRawFd, OwnedFd};
use std::process::Stdio;
use std::time::Duration;

use ap_client::{CredentialData, CredentialQuery};
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use zeroize::{Zeroize, Zeroizing};

const BW_FALLBACK_PATHS: &[&str] = &["/opt/homebrew/bin/bw", "/usr/local/bin/bw"];
const CHILD_FD: i32 = 3;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub enum Lookup {
    /// The credential, the vault item's name, and the fields being released.
    Found(Box<CredentialData>, Option<String>, Fields),
    NotFound,
    /// Several logins match; the requester must ask by item id.
    Ambiguous(usize),
    Locked,
    Error(String),
}

/// Which secret fields a release contains, for the approval sheet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fields {
    pub password: bool,
    pub totp: bool,
}

impl Fields {
    pub fn describe(&self) -> &'static str {
        match (self.password, self.totp) {
            (true, true) => "password + 2FA code",
            (true, false) => "password",
            (false, true) => "2FA code",
            (false, false) => "username only",
        }
    }
}

#[derive(Deserialize)]
struct BwItem {
    id: Option<String>,
    name: Option<String>,
    login: Option<BwLogin>,
}

#[derive(Deserialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Option<Vec<BwUri>>,
}

#[derive(Deserialize)]
struct BwUri {
    uri: Option<String>,
}

/// A running `bw serve` on a private socket.
struct Serve {
    child: Child,
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
}

pub struct Vault {
    bw: Option<String>,
    serve: Option<Serve>,
    unlocked: bool,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            bw: resolve_bw(),
            serve: None,
            unlocked: false,
        }
    }

    pub fn installed(&self) -> bool {
        self.bw.is_some()
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked
    }

    fn spawn(&mut self) -> Result<(), String> {
        let bw = self.bw.as_deref().ok_or("Bitwarden CLI (bw) not found")?;
        let (ours, theirs) =
            std::os::unix::net::UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
        let theirs: OwnedFd = theirs.into();
        let theirs_raw = theirs.as_raw_fd();
        let mut cmd = Command::new(bw);
        cmd.args(["serve", "--hostname", &format!("fd+connected://{CHILD_FD}")])
            .env("BW_NOINTERACTION", "true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        // SAFETY: only async-signal-safe libc calls between fork and exec.
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(theirs_raw, CHILD_FD) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // dup2 clears close-on-exec on the new descriptor.
                Ok(())
            });
        }
        let child = cmd.spawn().map_err(|e| format!("start bw serve: {e}"))?;
        drop(theirs);
        ours.set_nonblocking(true)
            .map_err(|e| format!("socket: {e}"))?;
        let stream = UnixStream::from_std(ours).map_err(|e| format!("socket: {e}"))?;
        let (r, w) = stream.into_split();
        self.serve = Some(Serve {
            child,
            reader: BufReader::new(r),
            writer: w,
        });
        Ok(())
    }

    /// One HTTP request to the private `bw serve`. Returns `(ok, json)`.
    async fn call(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<Value, String> {
        if self
            .serve
            .as_mut()
            .is_some_and(|s| s.child.try_wait().ok().flatten().is_some())
        {
            self.serve = None;
            self.unlocked = false;
        }
        if self.serve.is_none() {
            self.spawn()?;
        }
        let result = match self.serve.as_mut() {
            Some(s) => tokio::time::timeout(REQUEST_TIMEOUT, roundtrip(s, method, path, body))
                .await
                .unwrap_or_else(|_| Err("bw serve timed out".to_string())),
            None => Err("bw serve not running".to_string()),
        };
        if result.is_err() {
            // A broken channel means an unknown state: start over, locked.
            self.serve = None;
            self.unlocked = false;
        }
        result
    }

    /// Unlock with the master password, then sync.
    pub async fn unlock(&mut self, password: &str) -> Result<(), String> {
        let mut body = serde_json::to_vec(&serde_json::json!({ "password": password }))
            .map_err(|e| e.to_string())?;
        let reply = self.call("POST", "/unlock", Some(&body)).await;
        body.zeroize();
        let mut reply = reply?;
        let ok = reply["success"].as_bool() == Some(true);
        let message = reply["message"]
            .as_str()
            .unwrap_or("bw unlock failed")
            .to_string();
        // The reply carries the raw session key; drop it at once.
        if let Some(data) = reply.get_mut("data") {
            *data = Value::Null;
        }
        if !ok {
            return Err(message);
        }
        self.unlocked = true;
        let _ = self.call("POST", "/sync", None).await;
        Ok(())
    }

    /// Lock the vault and stop `bw serve`, so the key leaves memory too.
    pub async fn lock(&mut self) {
        if self.serve.is_some() {
            let _ = self.call("POST", "/lock", None).await;
        }
        if let Some(mut s) = self.serve.take() {
            let _ = s.child.kill().await;
        }
        self.unlocked = false;
    }

    pub async fn lookup(&mut self, query: &CredentialQuery) -> Lookup {
        if self.bw.is_none() {
            return Lookup::Error("Bitwarden CLI (bw) not found".to_string());
        }
        if !self.unlocked {
            return Lookup::Locked;
        }
        let search = query.search_string().to_string();
        let reply = match self
            .call("GET", &format!("/object/item/{}", pct(&search)), None)
            .await
        {
            Ok(v) => v,
            Err(e) => return Lookup::Error(e),
        };
        if reply["success"].as_bool() == Some(true) {
            return match serde_json::from_value::<BwItem>(reply["data"].clone()) {
                Ok(item) => self.credential_from(item).await,
                Err(e) => Lookup::Error(format!("parse item: {e}")),
            };
        }
        let message = reply["message"].as_str().unwrap_or_default();
        if message.contains("More than one result") {
            return self.lookup_by_url(&search).await;
        }
        if message.contains("Not found") {
            return Lookup::NotFound;
        }
        if message.contains("locked") {
            self.unlocked = false;
            return Lookup::Locked;
        }
        Lookup::Error(message.to_string())
    }

    /// Disambiguate a domain by exact login URI host.
    async fn lookup_by_url(&mut self, domain: &str) -> Lookup {
        let reply = match self
            .call(
                "GET",
                &format!("/list/object/items?search={}", pct(domain)),
                None,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => return Lookup::Error(e),
        };
        let items: Vec<BwItem> =
            serde_json::from_value(reply["data"]["data"].clone()).unwrap_or_default();
        let mut matches: Vec<BwItem> = items
            .into_iter()
            .filter(|i| {
                i.login.as_ref().is_some_and(|l| {
                    l.uris
                        .iter()
                        .flatten()
                        .any(|u| u.uri.as_deref().and_then(host_of).as_deref() == Some(domain))
                })
            })
            .collect();
        match matches.len() {
            0 => Lookup::NotFound,
            1 => match matches.pop() {
                Some(item) => self.credential_from(item).await,
                None => Lookup::NotFound,
            },
            n => Lookup::Ambiguous(n),
        }
    }

    async fn credential_from(&mut self, item: BwItem) -> Lookup {
        let Some(login) = item.login else {
            return Lookup::NotFound;
        };
        let uri = login.uris.iter().flatten().find_map(|u| u.uri.clone());
        let domain = uri
            .as_deref()
            .and_then(host_of)
            .or_else(|| item.name.clone());
        // The vault stores the TOTP seed; release only the current code.
        let totp = match (&login.totp, &item.id) {
            (Some(_), Some(id)) => self
                .call("GET", &format!("/object/totp/{}", pct(id)), None)
                .await
                .ok()
                .and_then(|v| v["data"]["data"].as_str().map(String::from)),
            _ => None,
        };
        let fields = Fields {
            password: login.password.is_some(),
            totp: totp.is_some(),
        };
        // Notes are deliberately not released: they can hold recovery codes.
        Lookup::Found(
            Box::new(CredentialData {
                username: login.username,
                password: login.password.map(Zeroizing::new),
                totp,
                uri,
                notes: None,
                credential_id: item.id,
                domain,
            }),
            item.name,
            fields,
        )
    }
}

async fn roundtrip(
    s: &mut Serve,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Result<Value, String> {
    let body = body.unwrap_or_default();
    let mut req = Zeroizing::new(
        format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost:8087\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes(),
    );
    req.extend_from_slice(body);
    s.writer
        .write_all(&req)
        .await
        .map_err(|e| format!("write: {e}"))?;

    let mut status = String::new();
    s.reader
        .read_line(&mut status)
        .await
        .map_err(|e| format!("read: {e}"))?;
    if status.is_empty() {
        return Err("bw serve closed the connection".to_string());
    }
    let mut length: Option<usize> = None;
    let mut chunked = false;
    loop {
        let mut line = String::new();
        s.reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("read: {e}"))?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            length = v.trim().parse().ok();
        } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        }
    }
    let mut data = Zeroizing::new(Vec::new());
    if chunked {
        loop {
            let mut size = String::new();
            s.reader
                .read_line(&mut size)
                .await
                .map_err(|e| format!("read: {e}"))?;
            let n = usize::from_str_radix(size.trim().split(';').next().unwrap_or("0"), 16)
                .map_err(|e| format!("chunk: {e}"))?;
            let mut chunk = vec![0; n + 2];
            s.reader
                .read_exact(&mut chunk)
                .await
                .map_err(|e| format!("read: {e}"))?;
            chunk.truncate(n);
            data.extend_from_slice(&chunk);
            chunk.zeroize();
            if n == 0 {
                break;
            }
        }
    } else {
        let n = length.ok_or("bw serve reply without length")?;
        data.resize(n, 0);
        s.reader
            .read_exact(&mut data)
            .await
            .map_err(|e| format!("read: {e}"))?;
    }
    serde_json::from_slice(&data).map_err(|e| format!("parse reply: {e}"))
}

/// Percent-encode a path segment or query value.
fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn resolve_bw() -> Option<String> {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let p = dir.join("bw");
            if p.is_file() {
                return Some(p.to_string_lossy().into_owned());
            }
        }
    }
    BW_FALLBACK_PATHS
        .iter()
        .find(|p| std::path::Path::new(p).is_file())
        .map(|p| p.to_string())
}

/// Host of a URI: `https://user@example.com:8443/x` -> `example.com`.
pub fn host_of(uri: &str) -> Option<String> {
    let rest = uri.split_once("://").map_or(uri, |(_, r)| r);
    let rest = rest.split_once('@').map_or(rest, |(_, r)| r);
    let host = rest.split(['/', ':', '?', '#']).next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(
            host_of("https://GitHub.com/login").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            host_of("https://u:p@example.com:8443/x").as_deref(),
            Some("example.com")
        );
        assert_eq!(host_of("example.com").as_deref(), Some("example.com"));
        assert_eq!(host_of("https://"), None);
    }

    #[test]
    fn percent_encoding() {
        assert_eq!(pct("github.com"), "github.com");
        assert_eq!(pct("a b/c?d"), "a%20b%2Fc%3Fd");
    }

    #[test]
    fn field_descriptions() {
        assert_eq!(
            Fields {
                password: true,
                totp: true
            }
            .describe(),
            "password + 2FA code"
        );
        assert_eq!(
            Fields {
                password: true,
                totp: false
            }
            .describe(),
            "password"
        );
    }

    #[tokio::test]
    async fn locked_vault_never_starts_bw() {
        let mut v = Vault {
            bw: Some("/nonexistent/bw".to_string()),
            serve: None,
            unlocked: false,
        };
        assert!(matches!(
            v.lookup(&CredentialQuery::Domain("github.com".into()))
                .await,
            Lookup::Locked
        ));
        assert!(v.serve.is_none());
    }

    /// A fake `bw serve` that speaks HTTP on fd 3, to test the private channel
    /// end to end without a vault: it must answer on the inherited socket and
    /// never see a secret in its environment or arguments.
    #[tokio::test]
    async fn private_channel_round_trip() {
        let dir = std::env::temp_dir().join(format!("aac-touchid-fakebw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let fake = dir.join("bw");
        std::fs::write(
            &fake,
            concat!("#!/usr/bin/env python3\n", r#"import os, socket, json, sys
s = socket.socket(fileno=3)
leak = any("hunter2" in v for v in os.environ.values()) or any("hunter2" in a for a in sys.argv)
f = s.makefile("rb")
while True:
    line = f.readline()
    if not line:
        break
    method, path, _ = line.decode().split(" ", 2)
    n = 0
    while True:
        h = f.readline().decode().strip()
        if not h:
            break
        if h.lower().startswith("content-length:"):
            n = int(h.split(":")[1])
    body = f.read(n) if n else b""
    if path == "/unlock":
        ok = json.loads(body)["password"] == "hunter2" and not leak
        out = {"success": True, "data": {"raw": "SESSIONKEY"}} if ok else {"success": False, "message": "Invalid master password."}
    elif path.startswith("/object/item/"):
        out = {"success": True, "data": {"id": "i1", "name": "GitHub", "notes": "RECOVERY", "login": {"username": "me", "password": "pw", "totp": "SEED", "uris": [{"uri": "https://github.com/login"}]}}}
    elif path.startswith("/object/totp/"):
        out = {"success": True, "data": {"object": "string", "data": "123456"}}
    else:
        out = {"success": True}
    b = json.dumps(out).encode()
    s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(b)).encode() + b"\r\n\r\n" + b)
"#),
        )
        .expect("write fake");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let mut v = Vault {
            bw: Some(fake.to_string_lossy().into_owned()),
            serve: None,
            unlocked: false,
        };
        assert!(v.unlock("wrong").await.is_err());
        assert!(!v.is_unlocked());
        v.unlock("hunter2").await.expect("unlock");
        assert!(v.is_unlocked());
        match v
            .lookup(&CredentialQuery::Domain("github.com".into()))
            .await
        {
            Lookup::Found(c, name, fields) => {
                assert_eq!(name.as_deref(), Some("GitHub"));
                assert_eq!(c.username.as_deref(), Some("me"));
                assert_eq!(c.totp.as_deref(), Some("123456"));
                assert!(c.notes.is_none(), "notes must not be released");
                assert_eq!(c.domain.as_deref(), Some("github.com"));
                assert_eq!(
                    fields,
                    Fields {
                        password: true,
                        totp: true
                    }
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        v.lock().await;
        assert!(!v.is_unlocked());
        assert!(v.serve.is_none());
    }
}
