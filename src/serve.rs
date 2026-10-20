//! The background listener: Agent Access user client + Touch ID approvals.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ap_client::{
    AuditEvent, AuditLog, CredentialQuery, CredentialRequestReply, DefaultProxyClient,
    FingerprintVerificationReply, IdentityFingerprint, UserClient, UserClientHandle,
    UserClientNotification, UserClientRequest,
};
use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::bitwarden::{Lookup, Vault};
use crate::control::{self, Decision, Envelope, Request, Response, Status};
use crate::dialog;
use crate::storage::{FileConnections, FileIdentity, short_hex};
use crate::touchid::{self, Outcome};

pub struct Config {
    pub proxy_url: String,
    pub lock_after: Duration,
    pub approval_timeout: Duration,
}

/// After a denial, the same device asking for the same thing is denied
/// silently for this long, so an agent cannot spam prompts.
const DENY_QUIET: Duration = Duration::from_secs(60);
/// After a cancelled unlock dialog, further unlock dialogs wait this long.
const UNLOCK_QUIET: Duration = Duration::from_secs(120);
const UNLOCK_DIALOG_TIMEOUT: Duration = Duration::from_secs(90);
const RECENT: usize = 10;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// State shared with the control-socket handler.
#[derive(Default)]
struct Shared {
    unlocked: bool,
    relay: String,
    recent: VecDeque<Decision>,
    /// Name given to the most recent `pair` request, used for the next new device.
    pending_name: Option<String>,
    client: Option<UserClient>,
}

type SharedRef = Arc<Mutex<Shared>>;

fn shared(s: &SharedRef) -> std::sync::MutexGuard<'_, Shared> {
    s.lock().unwrap_or_else(|p| p.into_inner())
}

/// What `serve` tells the control handler to do in the service loop.
enum LoopCmd {
    Lock(tokio::sync::oneshot::Sender<Response>),
    Revoke(String, tokio::sync::oneshot::Sender<Response>),
}

struct Audit;

#[async_trait]
impl AuditLog for Audit {
    async fn write(&self, event: AuditEvent<'_>) {
        match event {
            AuditEvent::ConnectionEstablished {
                remote_identity,
                remote_name,
                ..
            } => info!(
                "audit: device connected {} ({})",
                remote_name.unwrap_or("unnamed"),
                short_hex(remote_identity)
            ),
            AuditEvent::ConnectionRejected { remote_identity } => {
                info!("audit: device rejected {}", short_hex(remote_identity))
            }
            AuditEvent::CredentialRequested {
                query,
                remote_identity,
                ..
            } => {
                info!("audit: request {query} from {}", short_hex(remote_identity))
            }
            AuditEvent::CredentialApproved {
                query,
                remote_identity,
                fields,
                ..
            } => info!(
                "audit: released {query} to {} (username={} password={} totp={})",
                short_hex(remote_identity),
                fields.has_username,
                fields.has_password,
                fields.has_totp
            ),
            AuditEvent::CredentialDenied {
                query,
                remote_identity,
                ..
            } => {
                info!("audit: denied {query} to {}", short_hex(remote_identity))
            }
            _ => {}
        }
    }
}

/// Split an agent's `--domain "github.com | why"` (or `--id`) into the
/// lookup string and its stated purpose.
pub fn split_purpose(raw: &str) -> (String, Option<String>) {
    match raw.split_once('|') {
        Some((what, why)) => {
            let why: String = why
                .trim()
                .chars()
                .filter(|c| !c.is_control())
                .take(80)
                .collect();
            (what.trim().to_string(), (!why.is_empty()).then_some(why))
        }
        None => (raw.trim().to_string(), None),
    }
}

/// Mathematical sans-serif bold letters and digits: the system sheet has no
/// rich text, but these render bold in the system font.
pub fn bold(s: &str) -> String {
    s.chars()
        .map(|c| {
            let base = match c {
                'A'..='Z' => Some(0x1D5D4 + (c as u32 - 'A' as u32)),
                'a'..='z' => Some(0x1D5EE + (c as u32 - 'a' as u32)),
                '0'..='9' => Some(0x1D7EC + (c as u32 - '0' as u32)),
                _ => None,
            };
            base.and_then(char::from_u32).unwrap_or(c)
        })
        .collect()
}

/// The touch prompt text: completes `"aac-touchid" is trying to <reason>.`
pub fn credential_reason(
    item: &str,
    username: Option<&str>,
    device: &str,
    purpose: Option<&str>,
) -> String {
    let who = match username {
        Some(u) if !u.is_empty() => format!(" ({u})"),
        _ => String::new(),
    };
    let why = purpose.unwrap_or("no reason given");
    format!("share {}{who} with \"{device}\" \u{2014} {why}", bold(item))
}

pub fn pairing_reason(device: &str, code: &str) -> String {
    format!("pair new device {} (check code {code})", bold(device))
}

/// Per-device denial memory.
#[derive(Default)]
pub struct Quiet {
    denied: HashMap<(IdentityFingerprint, String), Instant>,
}

impl Quiet {
    pub fn is_quiet(&mut self, who: &IdentityFingerprint, what: &str) -> bool {
        self.denied.retain(|_, at| at.elapsed() < DENY_QUIET);
        self.denied.contains_key(&(*who, what.to_string()))
    }
    pub fn note_denied(&mut self, who: IdentityFingerprint, what: &str) {
        self.denied.insert((who, what.to_string()), Instant::now());
    }
}

struct Service {
    dir: PathBuf,
    cfg: Config,
    vault: Vault,
    shared: SharedRef,
    quiet: Quiet,
    unlock_quiet_until: Option<Instant>,
    last_activity: Instant,
}

impl Service {
    fn device_label(&self, who: &IdentityFingerprint) -> String {
        FileConnections::load(&self.dir)
            .ok()
            .and_then(|c| c.label(who))
            .unwrap_or_else(|| short_hex(who))
    }

    fn record(&self, device: &str, query: &str, outcome: &str) {
        info!("decision: {outcome} {query} for {device}");
        let mut s = shared(&self.shared);
        s.recent.push_front(Decision {
            at: now_secs(),
            device: device.to_string(),
            query: query.to_string(),
            outcome: outcome.to_string(),
        });
        s.recent.truncate(RECENT);
    }

    fn set_unlocked(&self) {
        shared(&self.shared).unlocked = self.vault.is_unlocked();
    }

    fn lock(&mut self, why: &str) {
        if self.vault.is_unlocked() {
            info!("locking vault: {why}");
        }
        self.vault.lock();
        self.set_unlocked();
    }

    /// Unlock through the native dialog. Returns whether the vault is unlocked.
    async fn ensure_unlocked(&mut self, device: &str, what: &str) -> bool {
        if self.vault.is_unlocked() {
            return true;
        }
        if self.unlock_quiet_until.is_some_and(|t| Instant::now() < t) {
            return false;
        }
        let mut message = format!(
            "\"{device}\" asked for {what}.\n\nEnter your Bitwarden master password to unlock agent access. You will approve each credential with Touch ID."
        );
        for _ in 0..3 {
            let Some(password) =
                dialog::ask_master_password(message.clone(), UNLOCK_DIALOG_TIMEOUT).await
            else {
                self.unlock_quiet_until = Some(Instant::now() + UNLOCK_QUIET);
                return false;
            };
            match self.vault.unlock(&password) {
                Ok(()) => {
                    info!("vault unlocked");
                    self.unlock_quiet_until = None;
                    self.last_activity = Instant::now();
                    self.set_unlocked();
                    return true;
                }
                Err(e) => {
                    warn!("unlock failed: {e}");
                    message =
                        format!("Unlock failed: {e}\n\n\"{device}\" asked for {what}. Try again.");
                }
            }
        }
        self.unlock_quiet_until = Some(Instant::now() + UNLOCK_QUIET);
        false
    }

    async fn on_request(&mut self, req: UserClientRequest) {
        match req {
            UserClientRequest::VerifyFingerprint {
                fingerprint, reply, ..
            } => {
                let name = shared(&self.shared)
                    .pending_name
                    .take()
                    .unwrap_or_else(|| "new device".to_string());
                let outcome = touchid::confirm(
                    pairing_reason(&name, &fingerprint),
                    self.cfg.approval_timeout,
                )
                .await;
                let approved = outcome == Outcome::Approved;
                self.record(&name, "pairing", &format!("{outcome:?}").to_lowercase());
                let _ = reply.send(FingerprintVerificationReply {
                    approved,
                    name: approved.then_some(name),
                });
            }
            UserClientRequest::CredentialRequest {
                query,
                identity,
                reply,
            } => {
                let (query, purpose) = match &query {
                    CredentialQuery::Domain(d) => {
                        let (d, why) = split_purpose(d);
                        (CredentialQuery::Domain(d), why)
                    }
                    CredentialQuery::Id(id) => {
                        let (id, why) = split_purpose(id);
                        (CredentialQuery::Id(id), why)
                    }
                    CredentialQuery::Search(q) => {
                        let (q, why) = split_purpose(q);
                        (CredentialQuery::Search(q), why)
                    }
                };
                let device = self.device_label(&identity);
                let what = query_label(&query);
                let deny = |reply: tokio::sync::oneshot::Sender<CredentialRequestReply>| {
                    let _ = reply.send(CredentialRequestReply {
                        approved: false,
                        credential: None,
                        credential_id: None,
                    });
                };
                if self.quiet.is_quiet(&identity, &what) {
                    self.record(&device, &what, "denied (repeat within 60 s)");
                    return deny(reply);
                }
                if !self.ensure_unlocked(&device, &what).await {
                    self.record(&device, &what, "denied (vault locked)");
                    self.quiet.note_denied(identity, &what);
                    return deny(reply);
                }
                let (credential, item_name) = match self.vault.lookup(&query) {
                    Lookup::Found(c, name) => (c, name),
                    Lookup::Locked => {
                        self.lock("bw reported the session invalid");
                        self.record(&device, &what, "denied (vault locked)");
                        return deny(reply);
                    }
                    Lookup::NotFound => {
                        self.record(&device, &what, "not found");
                        return deny(reply);
                    }
                    Lookup::Ambiguous(n) => {
                        self.record(
                            &device,
                            &what,
                            &format!("ambiguous ({n} logins match; request by item id)"),
                        );
                        return deny(reply);
                    }
                    Lookup::Error(e) => {
                        warn!("lookup error: {e}");
                        self.record(&device, &what, "error");
                        return deny(reply);
                    }
                };
                let domain = credential
                    .domain
                    .clone()
                    .unwrap_or_else(|| query.search_string().to_string());
                let item = item_name.unwrap_or(domain);
                let reason = credential_reason(
                    &item,
                    credential.username.as_deref(),
                    &device,
                    purpose.as_deref(),
                );
                let outcome = touchid::confirm(reason, self.cfg.approval_timeout).await;
                self.last_activity = Instant::now();
                if outcome == Outcome::Approved {
                    self.record(&device, &what, "approved");
                    let credential_id = credential.credential_id.clone();
                    let _ = reply.send(CredentialRequestReply {
                        approved: true,
                        credential: Some(*credential),
                        credential_id,
                    });
                } else {
                    self.record(&device, &what, &format!("{outcome:?}").to_lowercase());
                    self.quiet.note_denied(identity, &what);
                    deny(reply);
                }
            }
        }
    }

    fn maybe_idle_lock(&mut self) {
        if self.vault.is_unlocked() && self.last_activity.elapsed() >= self.cfg.lock_after {
            self.lock("idle timeout");
        }
    }
}

fn query_label(q: &CredentialQuery) -> String {
    match q {
        CredentialQuery::Domain(d) => d.clone(),
        CredentialQuery::Id(id) => format!("item {id}"),
        CredentialQuery::Search(s) => format!("search \"{s}\""),
    }
}

async fn connect(dir: &Path, cfg: &Config) -> Result<UserClientHandle, ap_client::ClientError> {
    let identity = Box::new(FileIdentity::load_or_generate(dir)?);
    let connections = Box::new(FileConnections::load(dir)?);
    let proxy = Box::new(DefaultProxyClient::from_url(cfg.proxy_url.clone()));
    UserClient::connect(identity, connections, proxy, Some(Box::new(Audit)), None).await
}

/// Handle control requests that need no service-loop state; forward the rest.
async fn control_handler(
    mut rx: mpsc::Receiver<Envelope>,
    shared_state: SharedRef,
    dir: PathBuf,
    loop_tx: mpsc::Sender<LoopCmd>,
) {
    while let Some((req, reply)) = rx.recv().await {
        let response = match req {
            Request::Status => {
                let s = shared(&shared_state);
                Response {
                    ok: true,
                    status: Some(Status {
                        unlocked: s.unlocked,
                        relay: s.relay.clone(),
                        devices: FileConnections::load(&dir)
                            .map(|c| c.devices())
                            .unwrap_or_default(),
                        recent: s.recent.iter().cloned().collect(),
                    }),
                    ..Default::default()
                }
            }
            Request::Pair { name } => {
                let client = shared(&shared_state).client.clone();
                match client {
                    None => Response::err("not connected to the relay yet; try again shortly"),
                    Some(client) => {
                        let name = name.unwrap_or_else(|| "new device".to_string());
                        match client.get_rendezvous_token(Some(name.clone())).await {
                            Ok(code) => {
                                shared(&shared_state).pending_name = Some(name);
                                Response {
                                    ok: true,
                                    code: Some(code.as_str().to_string()),
                                    ..Default::default()
                                }
                            }
                            Err(e) => Response::err(format!("could not get a pairing code: {e}")),
                        }
                    }
                }
            }
            Request::Lock => {
                let (tx, rx2) = tokio::sync::oneshot::channel();
                let _ = loop_tx.send(LoopCmd::Lock(tx)).await;
                rx2.await.unwrap_or_else(|_| Response::err("no reply"))
            }
            Request::Revoke { name } => {
                let (tx, rx2) = tokio::sync::oneshot::channel();
                let _ = loop_tx.send(LoopCmd::Revoke(name, tx)).await;
                rx2.await.unwrap_or_else(|_| Response::err("no reply"))
            }
        };
        let _ = reply.send(response);
    }
}

pub async fn run(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    let dir = crate::storage::state_dir()?;
    let shared_state: SharedRef = Arc::new(Mutex::new(Shared {
        relay: "connecting".to_string(),
        ..Default::default()
    }));
    let (ctl_tx, ctl_rx) = mpsc::channel::<Envelope>(16);
    let (loop_tx, mut loop_rx) = mpsc::channel::<LoopCmd>(16);
    let sock = control::socket_path(&dir);
    tokio::spawn(async move {
        if let Err(e) = control::serve(sock, ctl_tx).await {
            warn!("control socket stopped: {e}");
        }
    });
    tokio::spawn(control_handler(
        ctl_rx,
        shared_state.clone(),
        dir.clone(),
        loop_tx,
    ));

    let mut svc = Service {
        dir: dir.clone(),
        cfg,
        vault: Vault::new(),
        shared: shared_state.clone(),
        quiet: Quiet::default(),
        unlock_quiet_until: None,
        last_activity: Instant::now(),
    };
    if !svc.vault.installed() {
        warn!("Bitwarden CLI (bw) not found on PATH; every request will be denied");
    }
    info!("aac-touchid listening via {}", svc.cfg.proxy_url);

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut backoff = Duration::from_secs(2);
    loop {
        let handle = match connect(&dir, &svc.cfg).await {
            Ok(h) => h,
            Err(e) => {
                warn!(
                    "relay connect failed: {e}; retrying in {}s",
                    backoff.as_secs()
                );
                shared(&shared_state).relay = format!("connect failed: {e}");
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = term.recv() => { svc.lock("shutdown"); return Ok(()); }
                }
                backoff = (backoff * 2).min(Duration::from_secs(120));
                continue;
            }
        };
        backoff = Duration::from_secs(2);
        let UserClientHandle {
            client,
            mut notifications,
            mut requests,
        } = handle;
        {
            let mut s = shared(&shared_state);
            s.client = Some(client.clone());
            s.relay = "connected".to_string();
        }
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        let revoke = loop {
            tokio::select! {
                n = notifications.recv() => match n {
                    Some(UserClientNotification::Reconnecting { attempt }) => {
                        shared(&shared_state).relay = format!("reconnecting (attempt {attempt})");
                    }
                    Some(UserClientNotification::Reconnected {}) => {
                        shared(&shared_state).relay = "connected".to_string();
                    }
                    Some(UserClientNotification::ClientDisconnected {}) => {
                        shared(&shared_state).relay = "disconnected".to_string();
                    }
                    Some(UserClientNotification::Error { message, context }) => {
                        warn!("client error: {message} ({})", context.unwrap_or_default());
                    }
                    Some(_) => {}
                    None => break None,
                },
                r = requests.recv() => match r {
                    Some(r) => svc.on_request(r).await,
                    None => break None,
                },
                c = loop_rx.recv() => match c {
                    Some(LoopCmd::Lock(reply)) => {
                        svc.lock("requested");
                        let _ = reply.send(Response::ok("locked"));
                    }
                    Some(LoopCmd::Revoke(name, reply)) => break Some((name, reply)),
                    None => {}
                },
                _ = tick.tick() => svc.maybe_idle_lock(),
                _ = term.recv() => {
                    svc.lock("shutdown");
                    return Ok(());
                }
            }
        };
        // Stop the client before touching its connection file, so it cannot
        // write its in-memory copy back over a revocation.
        drop(requests);
        drop(notifications);
        drop(client);
        {
            let mut s = shared(&shared_state);
            s.client = None;
            s.relay = "reconnecting".to_string();
        }
        if let Some((name, reply)) = revoke {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let result = FileConnections::load(&dir).and_then(|mut c| c.remove(&name));
            let _ = reply.send(match result {
                Ok(0) => Response::err(format!("no paired device named {name}")),
                Ok(n) => Response::ok(format!("revoked {n} device(s) named {name}")),
                Err(e) => Response::err(format!("revoke failed: {e}")),
            });
        } else {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ap_proxy_protocol::IdentityKeyPair;

    #[test]
    fn reasons_name_device_domain_and_user() {
        assert_eq!(
            credential_reason("GitHub", Some("me@x.com"), "nuc", Some("log in with gh")),
            format!(
                "share {} (me@x.com) with \"nuc\" \u{2014} log in with gh",
                bold("GitHub")
            )
        );
        assert_eq!(
            credential_reason("x", None, "nuc", None),
            "share \u{1D605} with \"nuc\" \u{2014} no reason given"
        );
        assert_eq!(
            pairing_reason("nuc", "ab12cd"),
            format!("pair new device {} (check code ab12cd)", bold("nuc"))
        );
    }

    #[test]
    fn denials_are_remembered_per_device_and_query() {
        let a = IdentityKeyPair::generate().identity().fingerprint();
        let b = IdentityKeyPair::generate().identity().fingerprint();
        let mut q = Quiet::default();
        assert!(!q.is_quiet(&a, "github.com"));
        q.note_denied(a, "github.com");
        assert!(q.is_quiet(&a, "github.com"));
        assert!(!q.is_quiet(&a, "gitlab.com"));
        assert!(!q.is_quiet(&b, "github.com"));
    }

    #[test]
    fn purposes_are_split_off_and_cleaned() {
        assert_eq!(split_purpose("github.com"), ("github.com".into(), None));
        assert_eq!(
            split_purpose("github.com | log in with gh"),
            ("github.com".into(), Some("log in with gh".into()))
        );
        assert_eq!(split_purpose("x.com |  "), ("x.com".into(), None));
        assert_eq!(split_purpose("x.com|a\nb").1.as_deref(), Some("ab"));
        assert_eq!(
            split_purpose(&format!("x|{}", "y".repeat(200)))
                .1
                .map(|s| s.len()),
            Some(80)
        );
    }

    #[test]
    fn bold_maps_letters_and_digits_only() {
        assert_eq!(bold("Ab9-"), "\u{1D5D4}\u{1D5EF}\u{1D7F5}-");
    }

    #[test]
    fn query_labels() {
        assert_eq!(
            query_label(&CredentialQuery::Domain("x.com".into())),
            "x.com"
        );
        assert_eq!(query_label(&CredentialQuery::Id("abc".into())), "item abc");
    }
}
