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

use crate::intent::Generator;

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

/// One vault item named by a search, as bw serve returns it.
#[derive(Debug)]
pub enum Resolved {
    Item(Value),
    NotFound,
    /// Several logins match; the requester must ask by item id.
    Ambiguous(usize),
    Locked,
    Error(String),
}

/// The folder every agent-created login goes in. Only its logins may get a
/// 2FA seed from an agent.
pub const AGENT_FOLDER: &str = "Agent-created";

/// A login to create.
pub struct NewLogin<'a> {
    pub name: &'a str,
    pub username: Option<&'a str>,
    pub password: &'a str,
    pub uri: Option<&'a str>,
    pub folder_id: &'a str,
    pub notes: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TotpWrite {
    Stored,
    /// The login has a seed already; it is never overwritten.
    AlreadySet,
    NotLogin,
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

    /// Whether the CLI has no account logged in. Asks the private `bw serve`.
    pub async fn needs_login(&mut self) -> bool {
        if self.bw.is_none() {
            return false;
        }
        match self.call("GET", "/status", None).await {
            Ok(v) => v["data"]["template"]["status"].as_str() == Some("unauthenticated"),
            Err(_) => false,
        }
    }

    /// Log in with a personal API key. `bw login --apikey` reads the key only
    /// from its environment, so it is passed to that one short-lived child;
    /// an API key alone cannot decrypt the vault. `bw serve` is restarted
    /// afterwards so it sees the new account.
    pub async fn log_in(&mut self, client_id: &str, client_secret: &str) -> Result<(), String> {
        let bw = self.bw.clone().ok_or("Bitwarden CLI (bw) not found")?;
        self.lock().await;
        let out = Command::new(bw)
            .args(["login", "--apikey", "--raw"])
            .env("BW_CLIENTID", client_id)
            .env("BW_CLIENTSECRET", client_secret)
            .env("BW_NOINTERACTION", "true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|e| format!("bw login: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
            Err(if msg.is_empty() {
                "bw login failed".to_string()
            } else {
                msg
            })
        }
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

    /// Pull the vault from the server. Writes go to the server directly;
    /// syncing before a write's checks sees items made elsewhere, and after
    /// it keeps the local copy current.
    pub async fn sync(&mut self) -> Result<(), String> {
        let reply = self.call("POST", "/sync", None).await?;
        self.check(&reply)
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

    /// Mark the vault locked when bw says so, and turn a failed reply into
    /// its message.
    fn check(&mut self, reply: &Value) -> Result<(), String> {
        if reply["success"].as_bool() == Some(true) {
            return Ok(());
        }
        let message = reply["message"].as_str().unwrap_or("bw request failed");
        if message.contains("locked") {
            self.unlocked = false;
        }
        Err(message.to_string())
    }

    /// Find the one vault item a search names. A host or URL is matched on
    /// login URI hosts alone (see [`pick_by_host`]); anything else goes to
    /// bw's own lookup by id or name, then by exact name when several match.
    pub async fn resolve(&mut self, search: &str) -> Resolved {
        if self.bw.is_none() {
            return Resolved::Error("Bitwarden CLI (bw) not found".to_string());
        }
        if !self.unlocked {
            return Resolved::Locked;
        }
        if let Some(host) = host_query(search) {
            return self.resolve_by_host(&host).await;
        }
        let mut reply = match self
            .call("GET", &format!("/object/item/{}", pct(search)), None)
            .await
        {
            Ok(v) => v,
            Err(e) => return Resolved::Error(e),
        };
        if reply["success"].as_bool() == Some(true) {
            return Resolved::Item(reply["data"].take());
        }
        let message = reply["message"].as_str().unwrap_or_default().to_string();
        if message.contains("More than one result") {
            return self
                .resolve_among(search, |items| pick_by_name(items, search))
                .await;
        }
        if message.contains("Not found") {
            return Resolved::NotFound;
        }
        if message.contains("locked") {
            self.unlocked = false;
            return Resolved::Locked;
        }
        Resolved::Error(message)
    }

    /// Match a host on login URI hosts. bw's search is a substring match on
    /// names and URIs, so it returns every candidate; the choice is ours.
    async fn resolve_by_host(&mut self, host: &str) -> Resolved {
        let search = bare(host).to_string();
        self.resolve_among(&search, |items| pick_by_host(items, host))
            .await
    }

    /// List the items bw finds for `search` and keep the one `pick` chooses.
    async fn resolve_among(
        &mut self,
        search: &str,
        pick: impl FnOnce(&[Value]) -> Pick,
    ) -> Resolved {
        let mut reply = match self
            .call(
                "GET",
                &format!("/list/object/items?search={}", pct(search)),
                None,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => return Resolved::Error(e),
        };
        if let Err(e) = self.check(&reply) {
            wipe(&mut reply);
            return if self.unlocked {
                Resolved::Error(e)
            } else {
                Resolved::Locked
            };
        }
        let mut items = match reply["data"]["data"].take() {
            Value::Array(items) => items,
            _ => Vec::new(),
        };
        wipe(&mut reply);
        let found = match pick(&items) {
            Pick::None => Resolved::NotFound,
            Pick::One(i) => Resolved::Item(items.swap_remove(i)),
            Pick::Several(n) => Resolved::Ambiguous(n),
        };
        items.iter_mut().for_each(wipe);
        found
    }

    pub async fn lookup(&mut self, query: &CredentialQuery) -> Lookup {
        match self.resolve(query.search_string()).await {
            Resolved::Item(v) => match serde_json::from_value::<BwItem>(v) {
                Ok(item) => self.credential_from(item).await,
                Err(e) => Lookup::Error(format!("parse item: {e}")),
            },
            Resolved::NotFound => Lookup::NotFound,
            Resolved::Ambiguous(n) => Lookup::Ambiguous(n),
            Resolved::Locked => Lookup::Locked,
            Resolved::Error(e) => Lookup::Error(e),
        }
    }

    /// A password from bw's generator. Older bw reads any present boolean
    /// option as true, so options that are off are left out, never false.
    pub async fn generate(&mut self, how: Generator) -> Result<Zeroizing<String>, String> {
        let path = match how {
            Generator::Passphrase { words } => format!(
                "/generate?passphrase=true&words={words}&separator=-&capitalize=true&includeNumber=true"
            ),
            Generator::Password { length, symbols } => format!(
                "/generate?length={length}&uppercase=true&lowercase=true&number=true{}",
                if symbols { "&special=true" } else { "" }
            ),
        };
        let mut reply = self.call("GET", &path, None).await?;
        self.check(&reply)?;
        let password = match reply["data"]["data"].take() {
            Value::String(s) => Zeroizing::new(s),
            _ => return Err("bw generate returned no password".to_string()),
        };
        // Organization policies may lengthen it, never shorten it.
        let short = match how {
            Generator::Passphrase { words } => password.split('-').count() < words as usize,
            Generator::Password { length, .. } => password.chars().count() < length as usize,
        };
        if short {
            return Err("bw generated a shorter password than asked".to_string());
        }
        Ok(password)
    }

    /// Ids of the folders named [`AGENT_FOLDER`].
    async fn agent_folder_ids(&mut self) -> Result<Vec<String>, String> {
        let reply = self
            .call(
                "GET",
                &format!("/list/object/folders?search={}", pct(AGENT_FOLDER)),
                None,
            )
            .await?;
        self.check(&reply)?;
        Ok(reply["data"]["data"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|f| f["name"].as_str() == Some(AGENT_FOLDER))
            .filter_map(|f| f["id"].as_str().map(String::from))
            .collect())
    }

    /// The folder agent-created logins go in; created on first use when
    /// `create` is set.
    pub async fn agent_folder(&mut self, create: bool) -> Result<Option<String>, String> {
        if let Some(id) = self.agent_folder_ids().await?.into_iter().next() {
            return Ok(Some(id));
        }
        if !create {
            return Ok(None);
        }
        let body = serde_json::to_vec(&serde_json::json!({ "name": AGENT_FOLDER }))
            .map_err(|e| e.to_string())?;
        let reply = self.call("POST", "/object/folder", Some(&body)).await?;
        self.check(&reply)?;
        reply["data"]["id"]
            .as_str()
            .map(|id| Some(id.to_string()))
            .ok_or_else(|| "bw created a folder without an id".to_string())
    }

    /// Whether an item is in a folder named [`AGENT_FOLDER`].
    pub async fn in_agent_folder(&mut self, item: &Value) -> Result<bool, String> {
        let Some(folder) = item["folderId"].as_str() else {
            return Ok(false);
        };
        Ok(self.agent_folder_ids().await?.iter().any(|id| id == folder))
    }

    /// Whether the vault already has an item with this name (exact, any
    /// case) or a login for this host.
    pub async fn exists(&mut self, name: &str, host: Option<&str>) -> Result<bool, String> {
        let mut searches = vec![name];
        if let Some(h) = host.filter(|h| !h.eq_ignore_ascii_case(name)) {
            searches.push(h);
        }
        for search in searches {
            let mut reply = self
                .call(
                    "GET",
                    &format!("/list/object/items?search={}", pct(search)),
                    None,
                )
                .await?;
            let checked = self.check(&reply);
            let hit = reply["data"]["data"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|i| {
                    i["name"]
                        .as_str()
                        .is_some_and(|n| n.trim().eq_ignore_ascii_case(name))
                        || host.is_some_and(|h| login_hosts(i).any(|x| x == h))
                });
            wipe(&mut reply);
            checked?;
            if hit {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Create a login in `folder_id`. Returns the new item's id.
    pub async fn create_login(&mut self, new: &NewLogin<'_>) -> Result<String, String> {
        let uris: Vec<Value> = new
            .uri
            .map(|u| serde_json::json!({ "match": null, "uri": u }))
            .into_iter()
            .collect();
        let mut item = serde_json::json!({
            "organizationId": null,
            "collectionIds": null,
            "folderId": new.folder_id,
            "type": 1,
            "name": new.name,
            "notes": new.notes,
            "favorite": false,
            "fields": [],
            "reprompt": 0,
            "login": {
                "uris": uris,
                "username": new.username,
                "password": new.password,
                "totp": null,
            },
        });
        let body = serde_json::to_vec(&item).map_err(|e| e.to_string());
        wipe(&mut item);
        let mut body = Zeroizing::new(body?);
        let reply = self.call("POST", "/object/item", Some(&body)).await;
        body.zeroize();
        let mut reply = reply?;
        let checked = self.check(&reply);
        let id = reply["data"]["id"].as_str().map(String::from);
        wipe(&mut reply);
        checked?;
        id.ok_or_else(|| "bw created an item without an id".to_string())
    }

    /// Store a TOTP seed on a login that has none. Reads the item again
    /// first, so a seed set since the approval is never overwritten.
    pub async fn set_totp(&mut self, id: &str, seed: &str) -> Result<TotpWrite, String> {
        let path = format!("/object/item/{}", pct(id));
        let mut reply = self.call("GET", &path, None).await?;
        let checked = self.check(&reply);
        let mut item = reply["data"].take();
        wipe(&mut reply);
        if let Err(e) = checked {
            wipe(&mut item);
            return Err(e);
        }
        if item["type"].as_i64() != Some(1) || !item["login"].is_object() {
            wipe(&mut item);
            return Ok(TotpWrite::NotLogin);
        }
        if item["login"]["totp"]
            .as_str()
            .is_some_and(|t| !t.is_empty())
        {
            wipe(&mut item);
            return Ok(TotpWrite::AlreadySet);
        }
        item["login"]["totp"] = Value::String(seed.to_string());
        let body = serde_json::to_vec(&item).map_err(|e| e.to_string());
        wipe(&mut item);
        let mut body = Zeroizing::new(body?);
        let reply = self.call("PUT", &path, Some(&body)).await;
        body.zeroize();
        let mut reply = reply?;
        let checked = self.check(&reply);
        let stored = reply["data"]["login"]["totp"]
            .as_str()
            .is_some_and(|t| !t.is_empty());
        wipe(&mut reply);
        checked?;
        if stored {
            Ok(TotpWrite::Stored)
        } else {
            Err("bw did not store the 2FA seed".to_string())
        }
    }

    /// The current TOTP code of an item, never its seed.
    pub async fn totp_code(&mut self, id: &str) -> Option<String> {
        self.call("GET", &format!("/object/totp/{}", pct(id)), None)
            .await
            .ok()
            .and_then(|v| v["data"]["data"].as_str().map(String::from))
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
            (Some(_), Some(id)) => self.totp_code(id).await,
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

/// Hosts of a vault item's login URIs.
pub fn login_hosts(item: &Value) -> impl Iterator<Item = String> + '_ {
    item["login"]["uris"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|u| u["uri"].as_str().and_then(host_of))
}

/// Bitwarden URI match detection values whose URI is not a plain address:
/// regular expression (4) and never (5).
const NOT_A_HOST_MATCH: &[u64] = &[4, 5];

/// Hosts a login may be matched on: its URIs' hosts, except URIs set to
/// never match or to a regular expression.
fn matching_hosts(item: &Value) -> impl Iterator<Item = String> + '_ {
    item["login"]["uris"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|u| {
            u["match"]
                .as_u64()
                .is_none_or(|m| !NOT_A_HOST_MATCH.contains(&m))
        })
        .filter_map(|u| u["uri"].as_str().and_then(host_of))
}

/// Which of a search's results to release.
#[derive(Debug, PartialEq, Eq)]
pub enum Pick {
    None,
    One(usize),
    Several(usize),
}

fn pick_where(items: &[Value], f: impl Fn(&Value) -> bool) -> Pick {
    let mut hits = items
        .iter()
        .enumerate()
        .filter(|(_, i)| f(i))
        .map(|(n, _)| n);
    match (hits.next(), hits.count()) {
        (None, _) => Pick::None,
        (Some(n), 0) => Pick::One(n),
        (Some(_), more) => Pick::Several(more + 1),
    }
}

/// `www.example.com` -> `example.com`.
fn bare(host: &str) -> &str {
    host.strip_prefix("www.").unwrap_or(host)
}

/// The host a lookup names, when it names one: a URL's host (scheme,
/// user, port, path, query and fragment dropped) or a bare
/// dotted name of letters, digits and `-` (`github.com`). Item ids and
/// names with spaces or other characters are not hosts.
pub fn host_query(search: &str) -> Option<String> {
    let s = search.trim();
    let host = host_of(s)?;
    let labels_ok = host
        .split('.')
        .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    (host.contains('.') && labels_ok).then_some(host)
}

/// Choose a login for a host, deterministically, among bw's search results:
///
/// 1. Logins with a URI on exactly that host, or named exactly that host
///    (`www.` is ignored on both sides).
/// 2. Only if there are none: logins with a URI on a subdomain of it
///    (`github.com` finds `gist.github.com`).
///
/// More than one login in the first tier that has any is ambiguous. Partial
/// matches of names, URIs or usernames never count, and URIs set to never
/// match or to a regular expression are skipped.
pub fn pick_by_host(items: &[Value], host: &str) -> Pick {
    let q = bare(host);
    let dot_q = format!(".{q}");
    let logins = |i: &Value| i["login"].is_object();
    let exact = pick_where(items, |i| {
        logins(i)
            && (matching_hosts(i).any(|h| bare(&h) == q)
                || i["name"]
                    .as_str()
                    .is_some_and(|n| bare(&n.trim().to_ascii_lowercase()) == q))
    });
    if exact != Pick::None {
        return exact;
    }
    pick_where(items, |i| {
        logins(i) && matching_hosts(i).any(|h| h.ends_with(&dot_q))
    })
}

/// Choose among several search results the one named exactly `name` (any
/// case); otherwise every result counts toward the ambiguity.
pub fn pick_by_name(items: &[Value], name: &str) -> Pick {
    let name = name.trim();
    match pick_where(items, |i| {
        i["name"]
            .as_str()
            .is_some_and(|n| n.trim().eq_ignore_ascii_case(name))
    }) {
        Pick::None => match items.len() {
            0 => Pick::None,
            1 => Pick::One(0),
            n => Pick::Several(n),
        },
        p => p,
    }
}

/// Overwrite every string in a JSON value before it is dropped: bw replies
/// and request templates carry passwords and seeds.
pub fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(o) => o.values_mut().for_each(wipe),
        _ => {}
    }
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
    fn host_queries() {
        assert_eq!(host_query("GitHub.com").as_deref(), Some("github.com"));
        assert_eq!(
            host_query("https://github.com/login").as_deref(),
            Some("github.com")
        );
        assert_eq!(host_query("10.0.0.5").as_deref(), Some("10.0.0.5"));
        assert_eq!(
            host_query("GitHub.com/login?next=/x").as_deref(),
            Some("github.com")
        );
        assert_eq!(host_query("github.com:443").as_deref(), Some("github.com"));
        assert_eq!(host_query("GitHub"), None);
        assert_eq!(host_query("My Bank.com"), None);
        assert_eq!(host_query("a..b"), None);
        assert_eq!(host_query("github.com."), None);
        assert_eq!(host_query("2b5c1f4e-0a2d-4b7e-9f3a-1c2d3e4f5a6b"), None);
    }

    fn login(name: &str, uris: &[(&str, Option<u64>)]) -> Value {
        let uris: Vec<Value> = uris
            .iter()
            .map(|(u, m)| serde_json::json!({ "uri": u, "match": m }))
            .collect();
        serde_json::json!({ "type": 1, "name": name, "login": { "uris": uris } })
    }

    #[test]
    fn host_picks() {
        let gh = login("GitHub", &[("https://github.com/login", None)]);
        let gist = login("Gist", &[("https://gist.github.com", None)]);
        let named = login("github.com", &[]);
        let www = login("Amazon", &[("https://www.amazon.com/ap/signin", Some(0))]);
        let lookalike = login("Evil", &[("https://github.com.evil.io", None)]);
        let never = login("Old", &[("https://github.com", Some(5))]);
        let regex = login("Re", &[("^https://github\\.com/.*", Some(4))]);
        let note = serde_json::json!({ "type": 2, "name": "github.com" });

        let items = [
            lookalike.clone(),
            gist.clone(),
            gh.clone(),
            never,
            regex,
            note,
        ];
        // An exact host wins over a subdomain; look-alikes and skipped URIs never count.
        assert_eq!(pick_by_host(&items, "github.com"), Pick::One(2));
        assert_eq!(pick_by_host(&items, "www.github.com"), Pick::One(2));
        assert_eq!(pick_by_host(&items, "gist.github.com"), Pick::One(1));
        assert_eq!(pick_by_host(&items, "hub.com"), Pick::None);
        assert_eq!(pick_by_host(&items, "api.github.com"), Pick::None);
        // Several exact matches, or several subdomains, are ambiguous.
        assert_eq!(
            pick_by_host(&[gh.clone(), named.clone()], "github.com"),
            Pick::Several(2)
        );
        assert_eq!(pick_by_host(&[named], "github.com"), Pick::One(0));
        let api = login("API", &[("https://api.github.com", None)]);
        assert_eq!(
            pick_by_host(&[gist.clone(), api], "github.com"),
            Pick::Several(2)
        );
        assert_eq!(pick_by_host(&[gist], "github.com"), Pick::One(0));
        assert_eq!(pick_by_host(&[www], "amazon.com"), Pick::One(0));
    }

    #[test]
    fn name_picks() {
        let items = [login("GitHub Enterprise", &[]), login("github", &[])];
        assert_eq!(pick_by_name(&items, "GitHub"), Pick::One(1));
        assert_eq!(pick_by_name(&items, "Git"), Pick::Several(2));
        assert_eq!(pick_by_name(&[], "Git"), Pick::None);
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
            concat!("#!/usr/bin/env python3\n", r#"import os, socket, json, sys, urllib.parse
s = socket.socket(fileno=3)
folders = []
items = {"i1": {"id": "i1", "type": 1, "folderId": None, "name": "GitHub", "notes": "RECOVERY", "login": {"username": "me", "password": "pw", "totp": "SEED", "uris": [{"uri": "https://github.com/login"}]}}}
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
    route, _, query = path.partition("?")
    q = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
    def hit(i, term):
        term = urllib.parse.unquote(term).lower()
        return term in i["name"].lower() or any(term in u["uri"] for u in i["login"]["uris"])
    if route == "/unlock":
        ok = json.loads(body)["password"] == "hunter2" and not leak
        out = {"success": True, "data": {"raw": "SESSIONKEY"}} if ok else {"success": False, "message": "Invalid master password."}
    elif route == "/generate":
        if q.get("special") != "true" and "special" in q:
            out = {"success": False, "message": "special must be left out, not false"}
        else:
            if "passphrase" in q:
                ok = q == {"passphrase": "true", "words": q["words"], "separator": "-", "capitalize": "true", "includeNumber": "true"}
                pw = "-".join(["Word"] * int(q["words"])) if ok else "bad"
            else:
                pw = "A" * int(q["length"]) + ("!" if "special" in q else "")
            out = {"success": True, "data": {"object": "string", "data": pw}}
    elif route == "/list/object/folders":
        out = {"success": True, "data": {"object": "list", "data": folders}}
    elif route == "/object/folder" and method == "POST":
        folders.append({"object": "folder", "id": "f1", "name": json.loads(body)["name"]})
        out = {"success": True, "data": folders[-1]}
    elif route == "/list/object/items":
        out = {"success": True, "data": {"object": "list", "data": [i for i in items.values() if hit(i, q["search"])]}}
    elif route == "/object/item" and method == "POST":
        item = json.loads(body)
        item["id"] = "n%d" % len(items)
        items[item["id"]] = item
        out = {"success": True, "data": item}
    elif route.startswith("/object/item/") and method == "PUT":
        item = json.loads(body)
        items[route.rsplit("/", 1)[1]] = item
        out = {"success": True, "data": item}
    elif route.startswith("/object/item/"):
        key = urllib.parse.unquote(route.rsplit("/", 1)[1])
        found = items.get(key) or [i for i in items.values() if hit(i, key)]
        if isinstance(found, list):
            found = found[0] if len(found) == 1 else None
        out = {"success": True, "data": found} if found else {"success": False, "message": "Not found."}
    elif route.startswith("/object/totp/"):
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

        assert_eq!(v.sync().await, Ok(()));
        // Writes: generator, agent folder, new login, 2FA seed.
        let pw = v
            .generate(Generator::Password {
                length: 20,
                symbols: false,
            })
            .await
            .expect("generate");
        assert_eq!(pw.as_str(), "A".repeat(20));
        let with_symbols = Generator::Password {
            length: 16,
            symbols: true,
        };
        assert!(
            v.generate(with_symbols)
                .await
                .expect("generate")
                .ends_with('!')
        );
        assert_eq!(
            v.generate(Generator::Passphrase { words: 3 })
                .await
                .expect("passphrase")
                .as_str(),
            "Word-Word-Word"
        );
        assert_eq!(v.agent_folder(false).await, Ok(None));
        assert_eq!(v.agent_folder(true).await, Ok(Some("f1".to_string())));
        assert_eq!(v.agent_folder(false).await, Ok(Some("f1".to_string())));
        assert_eq!(v.exists("Acme", Some("acme.io")).await, Ok(false));
        assert_eq!(v.exists("github", None).await, Ok(true));
        assert_eq!(v.exists("Other", Some("github.com")).await, Ok(true));
        let id = v
            .create_login(&NewLogin {
                name: "Acme",
                username: Some("bot@x.com"),
                password: &pw,
                uri: Some("https://acme.io"),
                folder_id: "f1",
                notes: "Created by aac-touchid",
            })
            .await
            .expect("create");
        assert_eq!(id, "n1");
        assert_eq!(v.exists("acme", None).await, Ok(true));
        let Resolved::Item(item) = v.resolve(&id).await else {
            panic!("new item not found")
        };
        assert_eq!(item["login"]["password"], "A".repeat(20));
        assert_eq!(item["folderId"], "f1");
        assert_eq!(v.in_agent_folder(&item).await, Ok(true));
        let Resolved::Item(github) = v.resolve("i1").await else {
            panic!("github not found")
        };
        assert_eq!(v.in_agent_folder(&github).await, Ok(false));
        assert_eq!(
            v.set_totp(&id, "JBSWY3DPEHPK3PXP").await,
            Ok(TotpWrite::Stored)
        );
        let Resolved::Item(item) = v.resolve(&id).await else {
            panic!("item gone")
        };
        assert_eq!(item["login"]["totp"], "JBSWY3DPEHPK3PXP");
        assert_eq!(
            item["login"]["password"],
            "A".repeat(20),
            "PUT keeps the item"
        );
        assert_eq!(
            v.set_totp(&id, "KRSXG5CTMVRXEZLU").await,
            Ok(TotpWrite::AlreadySet)
        );
        assert_eq!(
            v.set_totp("i1", "KRSXG5CTMVRXEZLU").await,
            Ok(TotpWrite::AlreadySet)
        );
        assert_eq!(v.totp_code(&id).await.as_deref(), Some("123456"));
        assert!(matches!(v.resolve("nothing").await, Resolved::NotFound));
        // Hosts match on URI hosts only, never on part of one.
        assert!(matches!(
            v.resolve("https://github.com/settings").await,
            Resolved::Item(_)
        ));
        assert!(matches!(v.resolve("hub.com").await, Resolved::NotFound));

        v.lock().await;
        assert!(!v.is_unlocked());
        assert!(v.serve.is_none());
    }

    #[test]
    fn wipe_clears_every_string() {
        let mut v = serde_json::json!({"a": "pw", "b": [{"c": "seed"}], "d": 1});
        wipe(&mut v);
        assert_eq!(v, serde_json::json!({"a": "", "b": [{"c": ""}], "d": 1}));
    }
}
