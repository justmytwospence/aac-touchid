//! The background listener: Agent Access user client + Touch ID approvals.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ap_client::{
    AuditEvent, AuditLog, CredentialData, CredentialQuery, CredentialRequestReply,
    DefaultProxyClient, FingerprintVerificationReply, IdentityFingerprint, UserClient,
    UserClientHandle, UserClientNotification, UserClientRequest,
};
use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::bitwarden::{self, Lookup, Resolved, TotpWrite, Vault, host_of, wipe};
use crate::control::{self, Decision, Envelope, Request, Response, Status};
use crate::dialog;
use crate::intent::{self, AddTotp, Intent, NewLogin};
use crate::storage::{FileConnections, FileIdentity, short_hex};
use crate::touchid::{self, Outcome};

pub struct Config {
    pub proxy_url: String,
    pub lock_after: Duration,
    pub approval_timeout: Duration,
    /// Machines whose `aac` this listener keeps paired.
    pub targets: Vec<crate::provision::Target>,
}

const PROVISION_EVERY: Duration = Duration::from_secs(30 * 60);

/// After a denial, the same device asking for the same thing is denied
/// silently for this long, so an agent cannot spam prompts.
const DENY_QUIET: Duration = Duration::from_secs(60);
/// After a cancelled unlock dialog, further unlock dialogs wait this long.
const UNLOCK_QUIET: Duration = Duration::from_secs(120);
const UNLOCK_DIALOG_TIMEOUT: Duration = Duration::from_secs(90);
const RECENT: usize = 10;
/// How long a code from `aac-touchid pair` can complete a pairing.
const PAIR_WINDOW: Duration = Duration::from_secs(300);

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
    pending_name: Option<(String, Instant)>,
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

/// A query as the audit log prints it, with any 2FA seed removed.
fn audit_query(q: &CredentialQuery) -> String {
    match q {
        CredentialQuery::Domain(d) => format!("domain: {}", intent::redact(d)),
        CredentialQuery::Id(id) => format!("id: {}", intent::redact(id)),
        CredentialQuery::Search(s) => format!("search: {}", intent::redact(s)),
    }
}

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
                info!(
                    "audit: request {} from {}",
                    audit_query(query),
                    short_hex(remote_identity)
                )
            }
            AuditEvent::CredentialApproved {
                query,
                remote_identity,
                fields,
                ..
            } => info!(
                "audit: released {} to {} (username={} password={} totp={})",
                audit_query(query),
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
                info!(
                    "audit: denied {} to {}",
                    audit_query(query),
                    short_hex(remote_identity)
                )
            }
            _ => {}
        }
    }
}

/// What an agent put in `--domain` (or `--id`): `item | agent | reason`,
/// or `item | reason`, or just `item`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Ask {
    pub what: String,
    pub agent: Option<String>,
    pub why: Option<String>,
}

/// An agent's self-reported name: letters, digits, spaces and `· . - _ / @`
/// only, so it cannot fake a device suffix, line breaks or other sheet text.
fn clean_agent(s: &str) -> Option<String> {
    let s: String = s
        .chars()
        .filter(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ' ' | '\u{b7}' | '.' | '-' | '_' | '/' | '@')
        })
        .take(40)
        .collect();
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    (!s.is_empty()).then_some(s)
}

fn clean(s: &str, max: usize) -> Option<String> {
    let s: String = s
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect();
    (!s.is_empty()).then_some(s)
}

pub fn parse_ask(raw: &str) -> Ask {
    let mut parts = raw.splitn(3, '|');
    let what = parts.next().unwrap_or_default().trim().to_string();
    match (parts.next(), parts.next()) {
        (Some(agent), Some(why)) => Ask {
            what,
            agent: clean_agent(agent),
            why: clean(why, 80),
        },
        (Some(why), None) => Ask {
            what,
            agent: None,
            why: clean(why, 80),
        },
        _ => Ask {
            what,
            ..Default::default()
        },
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

/// Who is asking: `agent (device)` with the agent in bold, or the device in bold.
pub fn requester(agent: Option<&str>, device: &str) -> String {
    match agent {
        Some(a) => format!("{} ({device})", bold(a)),
        None => bold(device),
    }
}

/// The sheet reads `Bitwarden is trying to share a password`, then one line
/// each: who (bold), which item (bold), and why.
pub fn credential_reason(
    who: &str,
    item: &str,
    username: Option<&str>,
    fields: &str,
    why: Option<&str>,
) -> String {
    sheet(&format!("share a {fields}"), who, item, username, why)
}

/// `Bitwarden is trying to create a login with a 6-word passphrase and share it`.
pub fn create_reason(
    who: &str,
    name: &str,
    username: Option<&str>,
    secret: &str,
    why: Option<&str>,
) -> String {
    sheet(
        &format!("create a login with a {secret} and share it"),
        who,
        name,
        username,
        why,
    )
}

/// `Bitwarden is trying to add 2FA and share a 2FA code`.
pub fn totp_reason(who: &str, item: &str, username: Option<&str>, why: Option<&str>) -> String {
    sheet("add 2FA and share a 2FA code", who, item, username, why)
}

fn sheet(action: &str, who: &str, item: &str, username: Option<&str>, why: Option<&str>) -> String {
    let user = match username {
        Some(u) if !u.is_empty() => format!(" ({u})"),
        _ => String::new(),
    };
    format!(
        "{action}\n\n{who}\n{}{user}\n{}",
        bold(item),
        why.unwrap_or("no reason given")
    )
}

pub fn pairing_reason(device: &str, issued_secs_ago: u64) -> String {
    format!(
        "pair a new device\n\n{}\nfrom the pairing code issued {} ago",
        bold(device),
        ago(issued_secs_ago)
    )
}

fn ago(secs: u64) -> String {
    if secs < 60 {
        format!("{secs} s")
    } else {
        format!("{} min", secs / 60)
    }
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

type ReplyTx = tokio::sync::oneshot::Sender<CredentialRequestReply>;

fn deny(reply: ReplyTx) {
    let _ = reply.send(CredentialRequestReply {
        approved: false,
        credential: None,
        credential_id: None,
    });
}

fn release(reply: ReplyTx, credential: CredentialData) {
    let credential_id = credential.credential_id.clone();
    let _ = reply.send(CredentialRequestReply {
        approved: true,
        credential: Some(credential),
        credential_id,
    });
}

/// A credential request from a paired device, after its `| agent | reason`
/// fields are split off.
struct Pending {
    identity: IdentityFingerprint,
    device: String,
    /// Who the sheet names: agent (device), or the device.
    who: String,
    agent: Option<String>,
    why: Option<String>,
}

impl Pending {
    /// Who a release is recorded for.
    fn recipient(&self) -> String {
        self.agent
            .as_ref()
            .map_or(self.device.clone(), |a| format!("{a} ({})", self.device))
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

    async fn lock(&mut self, why: &str) {
        if self.vault.is_unlocked() {
            info!("locking vault: {why}");
        }
        self.vault.lock().await;
        self.set_unlocked();
    }

    /// Unlock through the native dialog. Returns whether the vault is unlocked.
    async fn ensure_unlocked(&mut self, who: &str, what: &str, why: Option<&str>) -> bool {
        if self.vault.is_unlocked() {
            return true;
        }
        if self.unlock_quiet_until.is_some_and(|t| Instant::now() < t) {
            return false;
        }
        let ask = format!(
            "{who}\n{}\n{}",
            bold(what),
            why.unwrap_or("no reason given")
        );
        if self.vault.needs_login().await && !self.log_in(&ask).await {
            self.unlock_quiet_until = Some(Instant::now() + UNLOCK_QUIET);
            return false;
        }
        let mut message =
            format!("{ask}\n\nEnter your Bitwarden master password to unlock agent requests.");
        for _ in 0..3 {
            let Some(password) =
                dialog::ask_master_password(message.clone(), UNLOCK_DIALOG_TIMEOUT).await
            else {
                self.unlock_quiet_until = Some(Instant::now() + UNLOCK_QUIET);
                return false;
            };
            match self.vault.unlock(&password).await {
                Ok(()) => {
                    info!("vault unlocked");
                    self.unlock_quiet_until = None;
                    self.last_activity = Instant::now();
                    self.set_unlocked();
                    return true;
                }
                Err(e) => {
                    warn!("unlock failed: {e}");
                    message = format!("Unlock failed: {e}\n\n{ask}\n\nTry again.");
                }
            }
        }
        self.unlock_quiet_until = Some(Instant::now() + UNLOCK_QUIET);
        false
    }

    /// Log the Bitwarden CLI in with an API key (it cannot decrypt the vault).
    async fn log_in(&mut self, ask: &str) -> bool {
        let mut note = String::new();
        for _ in 0..3 {
            let Some(id) = dialog::ask(
                format!("{ask}\n\n{note}The Bitwarden CLI on this Mac is not logged in. Enter your personal API key's client_id (web vault: Settings > Security > Keys > View API key)."),
                false,
                "Next",
                UNLOCK_DIALOG_TIMEOUT,
            )
            .await
            else {
                return false;
            };
            let Some(secret) = dialog::ask(
                "Enter the API key's client_secret.".to_string(),
                true,
                "Log in",
                UNLOCK_DIALOG_TIMEOUT,
            )
            .await
            else {
                return false;
            };
            match self.vault.log_in(id.trim(), secret.trim()).await {
                Ok(()) => {
                    info!("bw logged in");
                    return true;
                }
                Err(e) => {
                    warn!("bw login failed: {e}");
                    note = format!("Login failed: {e}\n\n");
                }
            }
        }
        false
    }

    async fn on_request(&mut self, req: UserClientRequest) {
        match req {
            UserClientRequest::VerifyFingerprint {
                fingerprint, reply, ..
            } => {
                let _ = fingerprint;
                let pending = shared(&self.shared).pending_name.take();
                let Some((name, issued)) = pending.filter(|(_, at)| at.elapsed() < PAIR_WINDOW)
                else {
                    // No `aac-touchid pair` in the last 5 minutes: nothing to approve.
                    self.record(
                        "unknown device",
                        "pairing",
                        "refused (no pairing code issued)",
                    );
                    let _ = reply.send(FingerprintVerificationReply {
                        approved: false,
                        name: None,
                    });
                    return;
                };
                let outcome = touchid::confirm(
                    pairing_reason(&name, issued.elapsed().as_secs()),
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
                let (query, ask) = match &query {
                    CredentialQuery::Domain(d) => {
                        let a = parse_ask(d);
                        (CredentialQuery::Domain(a.what.clone()), a)
                    }
                    CredentialQuery::Id(id) => {
                        let a = parse_ask(id);
                        (CredentialQuery::Id(a.what.clone()), a)
                    }
                    CredentialQuery::Search(q) => {
                        let a = parse_ask(q);
                        (CredentialQuery::Search(a.what.clone()), a)
                    }
                };
                let device = self.device_label(&identity);
                if ask.what == crate::provision::MARKER {
                    // The pairing check aac-touchid itself sends; nothing to release.
                    self.record(&device, "pairing", "paired");
                    return deny(reply);
                }
                let intent = match intent::parse(&ask.what) {
                    Ok(i) => i,
                    Err(e) => {
                        self.record(
                            &device,
                            &intent::redact(&ask.what),
                            &format!("refused: {e}"),
                        );
                        return deny(reply);
                    }
                };
                let p = Pending {
                    identity,
                    who: requester(ask.agent.as_deref(), &device),
                    device,
                    agent: ask.agent,
                    why: ask.why,
                };
                match intent {
                    Intent::Read => self.read(p, query, reply).await,
                    Intent::Create(n) => self.create(p, n, reply).await,
                    Intent::AddTotp(t) => self.add_totp(p, t, reply).await,
                }
            }
        }
    }

    /// Repeat and lock checks before any lookup. Unlocks the vault if needed.
    async fn admit(&mut self, p: &Pending, what: &str) -> bool {
        if self.quiet.is_quiet(&p.identity, what) {
            self.record(&p.device, what, "denied (repeat within 60 s)");
            return false;
        }
        if !self.ensure_unlocked(&p.who, what, p.why.as_deref()).await {
            self.record(&p.device, what, "denied (vault locked)");
            self.quiet.note_denied(p.identity, what);
            return false;
        }
        true
    }

    /// Show the Touch ID sheet. A refusal is recorded and remembered.
    async fn approve(&mut self, p: &Pending, what: &str, reason: String) -> bool {
        let outcome = touchid::confirm(reason, self.cfg.approval_timeout).await;
        self.last_activity = Instant::now();
        if outcome == Outcome::Approved {
            return true;
        }
        self.record(&p.device, what, &format!("{outcome:?}").to_lowercase());
        self.quiet.note_denied(p.identity, what);
        false
    }

    /// Sync before a write's checks. Records and refuses on failure, since
    /// the checks would run on a stale vault.
    async fn sync(&mut self, p: &Pending, what: &str) -> bool {
        match self.vault.sync().await {
            Ok(()) => true,
            Err(e) => {
                self.vault_error(p, what, &format!("sync: {e}")).await;
                false
            }
        }
    }

    /// Sync after a write; the write itself is already on the server.
    async fn after_write(&mut self) {
        if let Err(e) = self.vault.sync().await {
            warn!("sync after write failed: {e}");
        }
    }

    async fn vault_error(&mut self, p: &Pending, what: &str, e: &str) {
        if self.vault.is_unlocked() {
            warn!("vault error: {e}");
            self.record(&p.device, what, "error");
        } else {
            self.lock("bw reported the vault locked").await;
            self.record(&p.device, what, "denied (vault locked)");
        }
    }

    async fn read(&mut self, p: Pending, query: CredentialQuery, reply: ReplyTx) {
        let what = query_label(&query);
        if !self.admit(&p, &what).await {
            return deny(reply);
        }
        let (credential, item_name, fields) = match self.vault.lookup(&query).await {
            Lookup::Found(c, name, fields) => (c, name, fields),
            Lookup::Locked => {
                self.lock("bw reported the vault locked").await;
                self.record(&p.device, &what, "denied (vault locked)");
                return deny(reply);
            }
            Lookup::NotFound => {
                self.record(&p.device, &what, "not found");
                return deny(reply);
            }
            Lookup::Ambiguous(n) => {
                self.record(
                    &p.device,
                    &what,
                    &format!("ambiguous ({n} logins match; request by item id)"),
                );
                return deny(reply);
            }
            Lookup::Error(e) => {
                warn!("lookup error: {e}");
                self.record(&p.device, &what, "error");
                return deny(reply);
            }
        };
        let domain = credential
            .domain
            .clone()
            .unwrap_or_else(|| query.search_string().to_string());
        let item = item_name.unwrap_or(domain);
        let reason = credential_reason(
            &p.who,
            &item,
            credential.username.as_deref(),
            fields.describe(),
            p.why.as_deref(),
        );
        if !self.approve(&p, &what, reason).await {
            return deny(reply);
        }
        self.record(&p.recipient(), &what, "approved");
        release(reply, *credential);
    }

    /// Whether `new:` may go ahead: nothing by that name or host exists yet.
    /// Records why not.
    async fn may_create(&mut self, p: &Pending, what: &str, n: &NewLogin) -> bool {
        let host = n.uri.as_deref().and_then(host_of);
        match self.vault.exists(&n.name, host.as_deref()).await {
            Ok(false) => true,
            Ok(true) => {
                self.record(&p.device, what, "refused (already exists)");
                false
            }
            Err(e) => {
                self.vault_error(p, what, &e).await;
                false
            }
        }
    }

    async fn create(&mut self, p: Pending, n: NewLogin, reply: ReplyTx) {
        let what = format!("new {}", n.name);
        if !self.admit(&p, &what).await
            || !self.sync(&p, &what).await
            || !self.may_create(&p, &what, &n).await
        {
            return deny(reply);
        }
        let reason = create_reason(
            &p.who,
            &n.name,
            n.username.as_deref(),
            &n.secret.describe(),
            p.why.as_deref(),
        );
        if !self.approve(&p, &what, reason).await || !self.may_create(&p, &what, &n).await {
            return deny(reply);
        }
        let written = async {
            let password = self.vault.generate(n.secret).await?;
            let folder = self
                .vault
                .agent_folder(true)
                .await?
                .ok_or("no Agent-created folder")?;
            let notes = format!(
                "Created by aac-touchid for {} on {}: {}",
                p.agent.as_deref().unwrap_or("an agent"),
                p.device,
                p.why.as_deref().unwrap_or("no reason given")
            );
            let id = self
                .vault
                .create_login(&bitwarden::NewLogin {
                    name: &n.name,
                    username: n.username.as_deref(),
                    password: &password,
                    uri: n.uri.as_deref(),
                    folder_id: &folder,
                    notes: &notes,
                })
                .await?;
            Ok::<_, String>((id, password))
        }
        .await;
        match written {
            Ok((id, password)) => {
                self.after_write().await;
                self.record(&p.recipient(), &what, "created");
                release(
                    reply,
                    CredentialData {
                        username: n.username,
                        password: Some(password),
                        totp: None,
                        uri: n.uri,
                        notes: None,
                        credential_id: Some(id),
                        domain: None,
                    },
                );
            }
            Err(e) => {
                self.vault_error(&p, &what, &e).await;
                deny(reply);
            }
        }
    }

    async fn add_totp(&mut self, p: Pending, t: AddTotp, reply: ReplyTx) {
        let what = format!("2FA {}", t.item);
        if !self.admit(&p, &what).await || !self.sync(&p, &what).await {
            return deny(reply);
        }
        let mut item = match self.vault.resolve(&t.item).await {
            Resolved::Item(v) => v,
            Resolved::Locked => {
                self.lock("bw reported the vault locked").await;
                self.record(&p.device, &what, "denied (vault locked)");
                return deny(reply);
            }
            Resolved::NotFound => {
                self.record(&p.device, &what, "not found");
                return deny(reply);
            }
            Resolved::Ambiguous(n) => {
                self.record(
                    &p.device,
                    &what,
                    &format!("ambiguous ({n} logins match; request by item id)"),
                );
                return deny(reply);
            }
            Resolved::Error(e) => {
                self.vault_error(&p, &what, &e).await;
                return deny(reply);
            }
        };
        let id = item["id"].as_str().map(String::from);
        let name = item["name"].as_str().map(String::from);
        let username = item["login"]["username"].as_str().map(String::from);
        let is_login = item["type"].as_i64() == Some(1) && item["login"].is_object();
        let has_totp = item["login"]["totp"]
            .as_str()
            .is_some_and(|s| !s.is_empty());
        let in_folder = self.vault.in_agent_folder(&item).await;
        wipe(&mut item);
        let refusal = match (&id, in_folder) {
            _ if !is_login => Some("refused (not a login)"),
            (None, _) => Some("refused (item has no id)"),
            (_, Err(e)) => {
                self.vault_error(&p, &what, &e).await;
                return deny(reply);
            }
            (_, Ok(false)) => Some("refused (not in the Agent-created folder)"),
            _ if has_totp => Some("refused (already has 2FA)"),
            _ => None,
        };
        let (Some(id), None) = (id, refusal) else {
            self.record(&p.device, &what, refusal.unwrap_or("refused"));
            return deny(reply);
        };
        let shown = name.unwrap_or_else(|| t.item.clone());
        let reason = totp_reason(&p.who, &shown, username.as_deref(), p.why.as_deref());
        if !self.approve(&p, &what, reason).await {
            return deny(reply);
        }
        match self.vault.set_totp(&id, &t.seed).await {
            Ok(TotpWrite::Stored) => {
                self.after_write().await;
                let code = self.vault.totp_code(&id).await;
                let outcome = if code.is_some() {
                    "2FA added"
                } else {
                    "2FA added (no code)"
                };
                self.record(&p.recipient(), &what, outcome);
                // The username and current code only: never the seed or the password.
                release(
                    reply,
                    CredentialData {
                        username,
                        password: None,
                        totp: code,
                        uri: None,
                        notes: None,
                        credential_id: Some(id),
                        domain: None,
                    },
                );
            }
            Ok(TotpWrite::AlreadySet) => {
                self.record(&p.device, &what, "refused (already has 2FA)");
                deny(reply);
            }
            Ok(TotpWrite::NotLogin) => {
                self.record(&p.device, &what, "refused (not a login)");
                deny(reply);
            }
            Err(e) => {
                self.vault_error(&p, &what, &e).await;
                deny(reply);
            }
        }
    }

    async fn maybe_idle_lock(&mut self) {
        if self.vault.is_unlocked() && self.last_activity.elapsed() >= self.cfg.lock_after {
            self.lock("idle timeout").await;
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
                                shared(&shared_state).pending_name = Some((name, Instant::now()));
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
                    _ = term.recv() => { svc.lock("shutdown").await; return Ok(()); }
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
        let mut provision = tokio::time::interval(PROVISION_EVERY);
        let mut presence = tokio::time::interval(Duration::from_secs(60));
        let provisioning = Arc::new(tokio::sync::Mutex::new(()));
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
                        svc.lock("requested").await;
                        let _ = reply.send(Response::ok("locked"));
                    }
                    Some(LoopCmd::Revoke(name, reply)) => break Some((name, reply)),
                    None => {}
                },
                _ = tick.tick() => svc.maybe_idle_lock().await,
                _ = presence.tick() => {
                    let (targets, dir) = (svc.cfg.targets.clone(), dir.clone());
                    let name = svc.cfg.targets.iter()
                        .find(|t| t.at == crate::provision::Where::Local)
                        .map_or_else(|| "mac".to_string(), |t| t.name.clone());
                    tokio::spawn(async move {
                        if let Some(own) = crate::provision::listener_fingerprint(&dir).await {
                            crate::provision::mark_present(&targets, &own, &name).await;
                        }
                    });
                }
                _ = provision.tick() => {
                    // First tick fires at once: pair right after connecting.
                    let (targets, client, dir, gate) =
                        (svc.cfg.targets.clone(), client.clone(), dir.clone(), provisioning.clone());
                    tokio::spawn(async move {
                        if let Ok(_g) = gate.try_lock() {
                            crate::provision::ensure_all(&targets, &client, &dir).await;
                        }
                    });
                }
                _ = term.recv() => {
                    svc.lock("shutdown").await;
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
    fn sheet_texts() {
        let who = requester(Some("pi \u{b7} homelab"), "nuc");
        assert_eq!(who, format!("{} (nuc)", bold("pi \u{b7} homelab")));
        assert_eq!(requester(None, "nuc"), bold("nuc"));
        assert_eq!(
            credential_reason(
                &who,
                "GitHub",
                Some("me@x.com"),
                "password + 2FA code",
                Some("log in with gh")
            ),
            format!(
                "share a password + 2FA code\n\n{who}\n{} (me@x.com)\nlog in with gh",
                bold("GitHub")
            )
        );
        assert_eq!(
            credential_reason("n", "x", None, "password", None),
            "share a password\n\nn\n\u{1D605}\nno reason given"
        );
        assert_eq!(
            pairing_reason("nuc", 75),
            format!(
                "pair a new device\n\n{}\nfrom the pairing code issued 1 min ago",
                bold("nuc")
            )
        );
    }

    #[test]
    fn write_sheet_texts() {
        let who = requester(Some("pi"), "nuc");
        assert_eq!(
            create_reason(
                &who,
                "acme.io",
                Some("bot@x.com"),
                "6-word passphrase",
                Some("sign up")
            ),
            format!(
                "create a login with a 6-word passphrase and share it\n\n{who}\n{} (bot@x.com)\nsign up",
                bold("acme.io")
            )
        );
        assert_eq!(
            create_reason(&who, "Acme", None, "24-character password", None),
            format!(
                "create a login with a 24-character password and share it\n\n{who}\n{}\nno reason given",
                bold("Acme")
            )
        );
        assert_eq!(
            totp_reason(&who, "Acme", Some("bot"), Some("enroll 2FA")),
            format!(
                "add 2FA and share a 2FA code\n\n{who}\n{} (bot)\nenroll 2FA",
                bold("Acme")
            )
        );
    }

    #[test]
    fn audit_and_labels_never_show_a_seed() {
        let seed = "JBSWY3DPEHPK3PXP";
        for raw in [
            format!("totp:acme.io secret={seed} | pi | enroll"),
            format!("totp:acme.io uri=otpauth://totp/a?secret={seed}"),
            format!("totp:acme.io secret={seed} {seed}"),
        ] {
            for q in [
                CredentialQuery::Domain(raw.clone()),
                CredentialQuery::Id(raw.clone()),
                CredentialQuery::Search(raw.clone()),
            ] {
                assert!(!audit_query(&q).contains(seed), "{raw}");
            }
            let ask = parse_ask(&raw);
            let label = match intent::parse(&ask.what) {
                Ok(Intent::AddTotp(t)) => format!("2FA {}", t.item),
                _ => intent::redact(&ask.what),
            };
            assert!(!label.contains(seed), "{label}");
        }
        assert_eq!(
            audit_query(&CredentialQuery::Domain("github.com | pi | x".into())),
            "domain: github.com | pi | x"
        );
    }

    #[test]
    fn agent_names_cannot_fake_devices_or_lines() {
        assert_eq!(
            clean_agent("pi \u{b7} homelab").as_deref(),
            Some("pi \u{b7} homelab")
        );
        assert_eq!(clean_agent("pi (mac-air)").as_deref(), Some("pi mac-air"));
        assert_eq!(clean_agent("a\nb\u{202e}c\"d").as_deref(), Some("abcd"));
        assert_eq!(
            clean_agent("\u{1D5D4}\u{1D5D5}"),
            None,
            "no lookalike letters"
        );
        assert_eq!(clean_agent("x   y").as_deref(), Some("x y"));
        assert_eq!(clean_agent(&"z".repeat(90)).map(|s| s.len()), Some(40));
        assert_eq!(
            parse_ask("g.com | pi (mac) | why").agent.as_deref(),
            Some("pi mac")
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
    fn asks_are_parsed_and_cleaned() {
        assert_eq!(
            parse_ask("github.com"),
            Ask {
                what: "github.com".into(),
                ..Default::default()
            }
        );
        assert_eq!(
            parse_ask("github.com | log in with gh"),
            Ask {
                what: "github.com".into(),
                agent: None,
                why: Some("log in with gh".into())
            }
        );
        assert_eq!(
            parse_ask("github.com | pi \u{b7} homelab | log in | with gh"),
            Ask {
                what: "github.com".into(),
                agent: Some("pi \u{b7} homelab".into()),
                why: Some("log in | with gh".into())
            }
        );
        assert_eq!(parse_ask("x.com |  ").why, None);
        assert_eq!(parse_ask("x.com|a\nb").why.as_deref(), Some("ab"));
        assert_eq!(
            parse_ask(&format!("x|{}", "y".repeat(200)))
                .why
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
