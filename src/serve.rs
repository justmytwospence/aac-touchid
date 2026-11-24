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
use zeroize::Zeroizing;

use crate::bitwarden::{
    self, Conflict, FieldWrite, Lookup, PasswordWrite, Resolved, TotpWrite, Vault, host_of, wipe,
};
use crate::control::{self, Decision, Envelope, Request, Response, Status};
use crate::dialog;
use crate::grants::{BATCH_WINDOW, Grant, Kind};
use crate::intent::{self, AddTotp, Intent, NewLogin, Rotate, SaveLogin};
use crate::panel::{self, Choice, Decision as PanelDecision, Prompt, Row};
use crate::storage::{FileConnections, FileIdentity, short_hex};
use crate::touchid;

pub struct Config {
    pub proxy_url: String,
    pub lock_after: Duration,
    pub approval_timeout: Duration,
    /// How long a request waits for a locked or closed Mac before it is refused.
    pub wait_for_mac: Duration,
    /// Longest `remember=` window an agent can ask for; zero turns it off.
    pub max_remember: Duration,
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
const RECENT: usize = 50;
/// How long a human has to type a value for `ask:`.
const ASK_TIMEOUT: Duration = Duration::from_secs(180);
/// `why:` reports decisions this recent, at most [`WHY_MAX`] of them.
const WHY_WINDOW_SECS: u64 = 900;
const WHY_MAX: usize = 5;
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
    grants: crate::grants::Grants,
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
        .filter(|c| {
            !c.is_control()
                && !matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
        })
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

/// `1 min`, `1 h`, `1 h 30 min`.
pub fn span(d: Duration) -> String {
    let m = d.as_secs() / 60;
    if m < 60 {
        format!("{m} min")
    } else if m % 60 == 0 {
        format!("{} h", m / 60)
    } else {
        format!("{} h {} min", m / 60, m % 60)
    }
}

pub struct BatchLine {
    pub name: String,
    pub username: Option<String>,
    pub fields: String,
}

fn with_text(q: &CredentialQuery, s: String) -> CredentialQuery {
    match q {
        CredentialQuery::Domain(_) => CredentialQuery::Domain(s),
        CredentialQuery::Id(_) => CredentialQuery::Id(s),
        CredentialQuery::Search(_) => CredentialQuery::Search(s),
    }
}

/// What a `savefield:` is about to do, for its sheet.
#[derive(Debug, PartialEq, Eq)]
pub enum FieldChange {
    /// A new hidden field on an existing item.
    Add,
    /// A new value; the old one stays on the item as `archived`.
    Replace { archived: String },
    /// A new login that holds the field.
    Create,
}

const NOTE: &str = "Agent and reason are the agent's own words. The device is verified by pairing.";

fn row(label: &str, value: impl Into<String>) -> Row {
    Row {
        label: label.to_string(),
        value: value.into(),
    }
}

fn who_rows(p: &Pending) -> Vec<Row> {
    vec![
        row("Agent", p.agent.as_deref().unwrap_or("not given")),
        row("Device", p.device.as_str()),
    ]
}

fn why_row(p: &Pending) -> Row {
    row("Reason", p.why.as_deref().unwrap_or("no reason given"))
}

fn item_rows(item: &str, username: Option<&str>) -> Vec<Row> {
    let mut rows = vec![row("Item", item)];
    if let Some(u) = username.filter(|u| !u.is_empty()) {
        rows.push(row("Username", u));
    }
    rows
}

fn once(label: &str) -> (Vec<Choice>, Option<usize>) {
    (
        vec![Choice {
            label: label.to_string(),
            minutes: None,
        }],
        None,
    )
}

/// Allow buttons for a read: once, 15 min and 1 h (up to the cap), plus the
/// window the agent asked for, which Return presses.
fn read_choices(remember: Option<Duration>, max: Duration) -> (Vec<Choice>, Option<usize>) {
    let max_min = max.as_secs() / 60;
    let mut minutes: Vec<u64> = [15u64, 60].into_iter().filter(|m| *m <= max_min).collect();
    let asked = remember.map(|d| d.as_secs() / 60);
    if let Some(m) = asked.filter(|m| !minutes.contains(m)) {
        minutes.push(m);
        minutes.sort_unstable();
    }
    let mut choices = vec![Choice {
        label: "Allow once".to_string(),
        minutes: None,
    }];
    choices.extend(minutes.iter().map(|m| Choice {
        label: format!("Allow {}", span(Duration::from_secs(m * 60))),
        minutes: Some(*m),
    }));
    let default = match asked {
        Some(m) => choices.iter().position(|c| c.minutes == Some(m)),
        None => Some(0),
    };
    (choices, default)
}

fn prompt(
    title: String,
    rows: Vec<Row>,
    note: bool,
    (choices, default_choice): (Vec<Choice>, Option<usize>),
    touch_reason: String,
    timeout: Duration,
) -> Prompt {
    Prompt {
        title,
        rows,
        note: note.then(|| NOTE.to_string()),
        choices,
        default_choice,
        touch_reason,
        timeout_secs: timeout.as_secs(),
        input: None,
    }
}

fn read_prompt(
    p: &Pending,
    item: &str,
    username: Option<&str>,
    fields: &str,
    remember: Option<Duration>,
    max: Duration,
    timeout: Duration,
) -> Prompt {
    let mut rows = who_rows(p);
    rows.extend(item_rows(item, username));
    rows.push(row("Releases", fields));
    rows.push(why_row(p));
    prompt(
        format!("Share a {fields}"),
        rows,
        true,
        read_choices(remember, max),
        format!("share {item} with {}", p.device),
        timeout,
    )
}

fn batch_prompt(
    p: &Pending,
    lines: &[BatchLine],
    remember: Option<Duration>,
    max: Duration,
    timeout: Duration,
) -> Prompt {
    let n = lines.len();
    let mut rows = who_rows(p);
    for (i, l) in lines.iter().enumerate() {
        let user = match l.username.as_deref() {
            Some(u) if !u.is_empty() => format!(" ({u})"),
            _ => String::new(),
        };
        rows.push(row(
            &format!("Item {}", i + 1),
            format!("{}{user} \u{b7} {}", l.name, l.fields),
        ));
    }
    rows.push(why_row(p));
    let s = if n == 1 { "" } else { "s" };
    prompt(
        format!("Share {n} login{s}"),
        rows,
        true,
        read_choices(remember, max),
        format!("share {n} login{s} with {}", p.device),
        timeout,
    )
}

fn create_prompt(
    p: &Pending,
    name: &str,
    username: Option<&str>,
    secret: &str,
    timeout: Duration,
) -> Prompt {
    let mut rows = who_rows(p);
    rows.extend(item_rows(name, username));
    rows.push(row("Password", format!("new {secret}")));
    rows.push(why_row(p));
    prompt(
        "Create a login".to_string(),
        rows,
        true,
        once("Create"),
        format!("create the login {name}"),
        timeout,
    )
}

fn rotate_prompt(
    p: &Pending,
    item: &str,
    username: Option<&str>,
    new_username: Option<&str>,
    secret: &str,
    timeout: Duration,
) -> Prompt {
    let mut rows = who_rows(p);
    rows.extend(item_rows(item, username));
    rows.push(row("New password", secret));
    if let Some(u) = new_username {
        rows.push(row("New username", u));
    }
    rows.push(why_row(p));
    prompt(
        "Replace a password".to_string(),
        rows,
        true,
        once("Replace"),
        format!("replace the password of {item}"),
        timeout,
    )
}

fn save_prompt(p: &Pending, name: &str, username: Option<&str>, timeout: Duration) -> Prompt {
    let mut rows = who_rows(p);
    rows.extend(item_rows(name, username));
    rows.push(why_row(p));
    prompt(
        "Save a password the agent supplied".to_string(),
        rows,
        true,
        once("Save"),
        format!("save the login {name}"),
        timeout,
    )
}

/// Who supplies a field's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The agent sent it (`savefield:`).
    Agent,
    /// The human types it on the panel (`ask:`).
    Human,
}

fn field_prompt(
    p: &Pending,
    item: &str,
    username: Option<&str>,
    field: &str,
    change: &FieldChange,
    by: Source,
    timeout: Duration,
) -> Prompt {
    let f = field;
    let title = match (change, by) {
        (FieldChange::Add, Source::Agent) => {
            format!("Save the field \u{201c}{f}\u{201d} the agent supplied")
        }
        (FieldChange::Replace { .. }, Source::Agent) => {
            format!("Replace the field \u{201c}{f}\u{201d} with a value the agent supplied")
        }
        (FieldChange::Create, Source::Agent) => {
            format!("Create a login holding the field \u{201c}{f}\u{201d} the agent supplied")
        }
        (FieldChange::Add, Source::Human) => {
            format!("Enter a value for the field \u{201c}{f}\u{201d}")
        }
        (FieldChange::Replace { .. }, Source::Human) => {
            format!("Enter a new value for the field \u{201c}{f}\u{201d}")
        }
        (FieldChange::Create, Source::Human) => {
            format!("Create a login holding the field \u{201c}{f}\u{201d}")
        }
    };
    let mut rows = who_rows(p);
    rows.extend(item_rows(item, username));
    if let FieldChange::Replace { archived } = change {
        rows.push(row(
            "Old value",
            format!("kept as \u{201c}{archived}\u{201d}"),
        ));
    }
    rows.push(why_row(p));
    let mut pr = prompt(
        title,
        rows,
        true,
        once("Save"),
        format!("save the field {field} on {item}"),
        timeout,
    );
    if by == Source::Human {
        pr.input = Some("Paste the value. The agent never sees it.".to_string());
    }
    pr
}

fn totp_prompt(p: &Pending, item: &str, username: Option<&str>, timeout: Duration) -> Prompt {
    let mut rows = who_rows(p);
    rows.extend(item_rows(item, username));
    rows.push(why_row(p));
    prompt(
        "Add 2FA and share a 2FA code".to_string(),
        rows,
        true,
        once("Add 2FA"),
        format!("add 2FA to {item}"),
        timeout,
    )
}

fn pairing_prompt(device: &str, issued_secs_ago: u64, timeout: Duration) -> Prompt {
    prompt(
        "Pair a new device".to_string(),
        vec![
            row("Device", device),
            row(
                "Pairing code",
                format!("issued {} ago", ago(issued_secs_ago)),
            ),
        ],
        false,
        once("Pair"),
        format!("pair the device {device}"),
        timeout,
    )
}

/// What `why:` tells a device: its own recent decisions, newest first. Only
/// request labels and outcomes, never vault contents.
pub fn recent_for(recent: &VecDeque<Decision>, device: &str, now: u64) -> String {
    let suffix = format!(" ({device})");
    let lines: Vec<String> = recent
        .iter()
        .filter(|d| d.device == device || d.device.ends_with(&suffix))
        .filter(|d| now.saturating_sub(d.at) <= WHY_WINDOW_SECS)
        .take(WHY_MAX)
        .map(|d| {
            format!(
                "{}: {}, {} ago",
                d.query,
                d.outcome,
                ago(now.saturating_sub(d.at))
            )
        })
        .collect();
    if lines.is_empty() {
        "no decisions for this device in the last 15 min".to_string()
    } else {
        lines.join("; ")
    }
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

/// What a human chose on the panel.
struct Approval {
    /// The window picked, if any.
    minutes: Option<u64>,
    /// A value typed on the panel (`ask:`).
    value: Option<Zeroizing<String>>,
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
        shared(&self.shared).grants.clear();
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
                let decision = panel::ask(&pairing_prompt(
                    &name,
                    issued.elapsed().as_secs(),
                    self.cfg.approval_timeout,
                ))
                .await;
                let (approved, outcome) = match decision {
                    PanelDecision::Approved { .. } => (true, "approved"),
                    PanelDecision::Denied => (false, "denied"),
                    PanelDecision::TimedOut => (false, "timedout"),
                    PanelDecision::Unavailable => (false, "unavailable"),
                };
                self.record(&name, "pairing", outcome);
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
                    Intent::Read(r) => {
                        let q = with_text(&query, r.item);
                        self.read(p, q, r.field, r.remember, reply).await
                    }
                    Intent::Batch(b) => self.batch(p, b, reply).await,
                    Intent::Create(n) => self.create(p, n, reply).await,
                    Intent::AddTotp(t) => self.add_totp(p, t, reply).await,
                    Intent::Save(n) => self.save(p, n, reply).await,
                    Intent::SaveField(f) => self.save_field(p, f, reply).await,
                    Intent::AskValue(a) => self.ask_value(p, a, reply).await,
                    Intent::Rotate(r) => self.rotate(p, r, reply).await,
                    Intent::Why => self.why(p, reply),
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
        // Never show the master-password dialog to a locked screen.
        if !self.vault.is_unlocked() && !self.wait_for_mac(p, what).await {
            return false;
        }
        if !self.ensure_unlocked(&p.who, what, p.why.as_deref()).await {
            self.record(&p.device, what, "denied (vault locked)");
            self.quiet.note_denied(p.identity, what);
            return false;
        }
        true
    }

    /// Wait (up to `wait_for_mac`) until a panel can be shown: the screen
    /// unlocked and Touch ID usable. Posts one notification while waiting.
    async fn wait_for_mac(&mut self, p: &Pending, what: &str) -> bool {
        let ready = || !touchid::screen_locked() && touchid::available();
        if ready() {
            return true;
        }
        info!("waiting for the Mac: {what} from {}", p.device);
        dialog::notify(format!(
            "An agent request from {} is waiting. Unlock this Mac to answer it.",
            p.device
        ));
        let until = Instant::now() + self.cfg.wait_for_mac;
        while Instant::now() < until {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if ready() {
                return true;
            }
        }
        self.record(
            &p.device,
            what,
            "unavailable (Mac locked, asleep or lid closed)",
        );
        false
    }

    /// Show the approval panel (then Touch ID). A refusal is recorded and
    /// remembered; the Mac being unavailable is only recorded.
    async fn approve(&mut self, p: &Pending, what: &str, prompt: Prompt) -> Option<Approval> {
        if !self.wait_for_mac(p, what).await {
            return None;
        }
        let decision = panel::ask(&prompt).await;
        self.last_activity = Instant::now();
        let outcome = match decision {
            PanelDecision::Approved { choice, value } => {
                return Some(Approval {
                    minutes: prompt.choices.get(choice).and_then(|c| c.minutes),
                    value: value.map(Zeroizing::new),
                });
            }
            PanelDecision::Denied => "denied",
            PanelDecision::TimedOut => "timedout",
            PanelDecision::Unavailable => "unavailable",
        };
        self.record(&p.device, what, outcome);
        // Unavailable showed no panel, so there is no prompt spam to hold off,
        // and a retry should report the real reason again.
        if outcome != "unavailable" {
            self.quiet.note_denied(p.identity, what);
        }
        None
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

    fn cap(&self, d: Duration) -> Option<Duration> {
        (!self.cfg.max_remember.is_zero()).then(|| d.min(self.cfg.max_remember))
    }

    async fn read(
        &mut self,
        p: Pending,
        query: CredentialQuery,
        field: Option<String>,
        remember: Option<Duration>,
        reply: ReplyTx,
    ) {
        let what = match &field {
            Some(f) => format!("{} field={f}", query_label(&query)),
            None => query_label(&query),
        };
        let wanted = field.as_deref().unwrap_or_default().to_string();
        if !self.admit(&p, &what).await {
            return deny(reply);
        }
        let found = match field.as_deref() {
            Some(f) => self.vault.lookup_field(&query, f).await,
            None => self.vault.lookup(&query).await,
        };
        let (credential, item_name, fields) = match found {
            Lookup::Found(c, name, fields) => (c, name, fields),
            Lookup::FieldNotFound => {
                self.record(&p.device, &what, &format!("not found (no field {wanted})"));
                return deny(reply);
            }
            Lookup::FieldAmbiguous(n) => {
                self.record(
                    &p.device,
                    &what,
                    &format!("ambiguous ({n} fields named {wanted})"),
                );
                return deny(reply);
            }
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
        if let Some(id) = credential.credential_id.as_deref() {
            let kind =
                shared(&self.shared)
                    .grants
                    .take(&p.identity, id, field.as_deref(), Instant::now());
            if let Some(kind) = kind {
                self.last_activity = Instant::now();
                self.record(&p.recipient(), &what, kind.outcome());
                return release(reply, *credential);
            }
        }
        let remember = remember.and_then(|d| self.cap(d));
        let domain = credential
            .domain
            .clone()
            .unwrap_or_else(|| query.search_string().to_string());
        let item = item_name.unwrap_or(domain);
        let prompt = read_prompt(
            &p,
            &item,
            credential.username.as_deref(),
            &fields.describe(),
            remember,
            self.cfg.max_remember,
            self.cfg.approval_timeout,
        );
        let Some(approval) = self.approve(&p, &what, prompt).await else {
            return deny(reply);
        };
        let window = approval.minutes.map(|m| Duration::from_secs(m * 60));
        if let (Some(d), Some(id)) = (window, credential.credential_id.clone()) {
            shared(&self.shared).grants.add(Grant {
                device: p.identity,
                device_label: p.device.clone(),
                item_id: id,
                field: field.clone(),
                item: grant_label(&item, field.as_deref()),
                kind: Kind::Remembered,
                expires: Instant::now() + d,
                uses_left: None,
            });
        }
        let outcome = match window {
            Some(d) => format!("approved (remembered {})", span(d)),
            None => "approved".to_string(),
        };
        self.record(&p.recipient(), &what, &outcome);
        release(reply, *credential);
    }

    /// Several items on one sheet; approval leaves grants the client's
    /// following reads use.
    async fn batch(&mut self, p: Pending, b: intent::Batch, reply: ReplyTx) {
        let labels: Vec<String> = b.items.iter().map(intent::Target::label).collect();
        let what = format!("batch {}", labels.join(","));
        if !self.admit(&p, &what).await {
            return deny(reply);
        }
        let mut found: Vec<(String, Option<String>, BatchLine)> = Vec::new();
        for target in &b.items {
            let item = &target.item;
            let label = target.label();
            let query = CredentialQuery::Domain(item.clone());
            let looked = match target.field.as_deref() {
                Some(f) => self.vault.lookup_field(&query, f).await,
                None => self.vault.lookup(&query).await,
            };
            match looked {
                Lookup::FieldNotFound => {
                    self.record(&p.device, &what, &format!("not found: {label}"));
                    return deny(reply);
                }
                Lookup::FieldAmbiguous(n) => {
                    self.record(
                        &p.device,
                        &what,
                        &format!("ambiguous: {label} ({n} fields match)"),
                    );
                    return deny(reply);
                }
                Lookup::Found(c, name, fields) => {
                    let Some(id) = c.credential_id.clone() else {
                        self.record(&p.device, &what, "refused (item has no id)");
                        return deny(reply);
                    };
                    if found.iter().any(|(i, f, _)| {
                        *i == id && crate::grants::same_field(f.as_deref(), target.field.as_deref())
                    }) {
                        continue;
                    }
                    found.push((
                        id,
                        target.field.clone(),
                        BatchLine {
                            name: name
                                .or_else(|| c.domain.clone())
                                .unwrap_or_else(|| item.clone()),
                            username: c.username.clone(),
                            fields: fields.describe(),
                        },
                    ));
                }
                Lookup::Locked => {
                    self.lock("bw reported the vault locked").await;
                    self.record(&p.device, &what, "denied (vault locked)");
                    return deny(reply);
                }
                Lookup::NotFound => {
                    self.record(&p.device, &what, &format!("not found: {label}"));
                    return deny(reply);
                }
                Lookup::Ambiguous(n) => {
                    self.record(
                        &p.device,
                        &what,
                        &format!("ambiguous: {label} ({n} logins match; request by item id)"),
                    );
                    return deny(reply);
                }
                Lookup::Error(e) => {
                    warn!("lookup error: {e}");
                    self.record(&p.device, &what, "error");
                    return deny(reply);
                }
            }
        }
        let covered = {
            let mut s = shared(&self.shared);
            let now = Instant::now();
            found
                .iter()
                .all(|(id, f, _)| s.grants.remembers(&p.identity, id, f.as_deref(), now))
        };
        if covered {
            // Every item is already remembered for this device: the reads
            // that follow are released by those grants, so no new sheet.
            self.last_activity = Instant::now();
            self.record(&p.recipient(), &what, "approved (remembered)");
            return release(
                reply,
                CredentialData {
                    username: None,
                    password: None,
                    totp: None,
                    uri: None,
                    notes: None,
                    credential_id: None,
                    domain: Some(format!("batch of {} remembered", found.len())),
                },
            );
        }
        let remember = b.remember.and_then(|d| self.cap(d));
        let lines: Vec<BatchLine> = found
            .iter()
            .map(|(_, _, l)| BatchLine {
                name: l.name.clone(),
                username: l.username.clone(),
                fields: l.fields.clone(),
            })
            .collect();
        let prompt = batch_prompt(
            &p,
            &lines,
            remember,
            self.cfg.max_remember,
            self.cfg.approval_timeout,
        );
        let Some(approval) = self.approve(&p, &what, prompt).await else {
            return deny(reply);
        };
        let window = approval.minutes.map(|m| Duration::from_secs(m * 60));
        let now = Instant::now();
        let n = found.len();
        {
            let mut s = shared(&self.shared);
            for (id, field, line) in found {
                let (kind, expires, uses_left) = match window {
                    Some(d) => (Kind::Remembered, now + d, None),
                    None => (Kind::Batch, now + BATCH_WINDOW, Some(1)),
                };
                s.grants.add(Grant {
                    device: p.identity,
                    device_label: p.device.clone(),
                    item_id: id,
                    item: grant_label(&line.name, field.as_deref()),
                    field,
                    kind,
                    expires,
                    uses_left,
                });
            }
        }
        let outcome = match window {
            Some(d) => format!("approved (batch, remembered {})", span(d)),
            None => "approved (batch)".to_string(),
        };
        self.record(&p.recipient(), &what, &outcome);
        release(
            reply,
            CredentialData {
                username: None,
                password: None,
                totp: None,
                uri: None,
                notes: None,
                credential_id: None,
                domain: Some(format!("batch of {n} approved")),
            },
        );
    }

    /// Whether `new:` or `save:` may go ahead: nothing by that name, and no
    /// login a read of the host would find. Records why not, naming only
    /// what the request supplied.
    async fn may_create(&mut self, p: &Pending, what: &str, name: &str, uri: Option<&str>) -> bool {
        let host = uri.and_then(host_of);
        match self.vault.exists(name, host.as_deref()).await {
            Ok(None) => true,
            Ok(Some(conflict)) => {
                let why = match conflict {
                    Conflict::Name => "an item with that name".to_string(),
                    Conflict::Host(h) => format!("a login for {h}"),
                };
                self.record(&p.device, what, &format!("refused (already exists: {why})"));
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
            || !self.may_create(&p, &what, &n.name, n.uri.as_deref()).await
        {
            return deny(reply);
        }
        let prompt = create_prompt(
            &p,
            &n.name,
            n.username.as_deref(),
            &n.secret.describe(),
            self.cfg.approval_timeout,
        );
        if self.approve(&p, &what, prompt).await.is_none()
            || !self.may_create(&p, &what, &n.name, n.uri.as_deref()).await
        {
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
                    password: Some(&password),
                    field: None,
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

    /// Tell a device why its recent requests were refused. No sheet and no
    /// unlock: only its own decision records leave, never vault data.
    fn why(&self, p: Pending, reply: ReplyTx) {
        let text = recent_for(&shared(&self.shared).recent, &p.device, now_secs());
        info!("why: {} asked for its recent decisions", p.device);
        release(
            reply,
            CredentialData {
                username: None,
                password: None,
                totp: None,
                uri: None,
                notes: None,
                credential_id: None,
                domain: Some(text),
            },
        );
    }

    /// Store a password the agent already has as a new login. The agent has
    /// the password, so nothing but the username, URI and item id comes back.
    async fn save(&mut self, p: Pending, n: SaveLogin, reply: ReplyTx) {
        let what = format!("save {}", n.name);
        if !self.admit(&p, &what).await
            || !self.sync(&p, &what).await
            || !self.may_create(&p, &what, &n.name, n.uri.as_deref()).await
        {
            return deny(reply);
        }
        let prompt = save_prompt(
            &p,
            &n.name,
            n.username.as_deref(),
            self.cfg.approval_timeout,
        );
        if self.approve(&p, &what, prompt).await.is_none()
            || !self.may_create(&p, &what, &n.name, n.uri.as_deref()).await
        {
            return deny(reply);
        }
        let written = async {
            let folder = self
                .vault
                .agent_folder(true)
                .await?
                .ok_or("no Agent-created folder")?;
            let notes = format!(
                "Saved by aac-touchid for {} on {}: {}",
                p.agent.as_deref().unwrap_or("an agent"),
                p.device,
                p.why.as_deref().unwrap_or("no reason given")
            );
            self.vault
                .create_login(&bitwarden::NewLogin {
                    name: &n.name,
                    username: n.username.as_deref(),
                    password: Some(&n.password),
                    field: None,
                    uri: n.uri.as_deref(),
                    folder_id: &folder,
                    notes: &notes,
                })
                .await
        }
        .await;
        match written {
            Ok(id) => {
                self.after_write().await;
                self.record(&p.recipient(), &what, "saved");
                release(
                    reply,
                    CredentialData {
                        username: n.username,
                        password: None,
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

    /// The one vault item a request names, found like a read finds it (a
    /// host by its URI hosts, anything else by id or name). `None` means the
    /// reason is already recorded and the request is to be denied.
    async fn resolve_one(
        &mut self,
        p: &Pending,
        what: &str,
        search: &str,
    ) -> Option<serde_json::Value> {
        match self.vault.resolve(search).await {
            Resolved::Item(v) => Some(v),
            Resolved::Locked => {
                self.lock("bw reported the vault locked").await;
                self.record(&p.device, what, "denied (vault locked)");
                None
            }
            Resolved::NotFound => {
                self.record(&p.device, what, "not found");
                None
            }
            Resolved::Ambiguous(n) => {
                self.record(
                    &p.device,
                    what,
                    &format!("ambiguous ({n} logins match; request by item id)"),
                );
                None
            }
            Resolved::Error(e) => {
                self.vault_error(p, what, &e).await;
                None
            }
        }
    }

    /// Store an API key the agent has as a hidden field of an item, or of a
    /// new login when there is no such item. A value it replaces stays on the
    /// item. The value never comes back: only username, URI and item id.
    async fn save_field(&mut self, p: Pending, f: intent::SaveField, reply: ReplyTx) {
        let what = format!("field {} {}", f.item, f.name);
        if !self.admit(&p, &what).await || !self.sync(&p, &what).await {
            return deny(reply);
        }
        let date = bitwarden::utc_date(now_secs());
        match self.vault.resolve(&f.item).await {
            Resolved::Item(mut item) => {
                let id = item["id"].as_str().map(String::from);
                let name = item["name"].as_str().map(String::from);
                let username = item["login"]["username"]
                    .as_str()
                    .filter(|u| !u.is_empty())
                    .map(String::from);
                let uri = item["login"]["uris"][0]["uri"].as_str().map(String::from);
                let state = bitwarden::field_state(&item, &f.name, &f.value);
                wipe(&mut item);
                let Some(id) = id else {
                    self.record(&p.device, &what, "refused (item has no id)");
                    return deny(reply);
                };
                let (change, field_shown) = match state {
                    bitwarden::FieldState::Same => {
                        self.record(&p.recipient(), &what, "unchanged");
                        return release(
                            reply,
                            CredentialData {
                                username: None,
                                password: None,
                                totp: None,
                                uri: None,
                                notes: None,
                                credential_id: None,
                                domain: Some("unchanged".to_string()),
                            },
                        );
                    }
                    bitwarden::FieldState::Ambiguous(n) => {
                        self.record(
                            &p.device,
                            &what,
                            &format!("refused ({n} fields named {})", f.name),
                        );
                        return deny(reply);
                    }
                    bitwarden::FieldState::Linked => {
                        self.record(&p.device, &what, "refused (field is linked)");
                        return deny(reply);
                    }
                    bitwarden::FieldState::Absent | bitwarden::FieldState::Empty => {
                        (FieldChange::Add, f.name.clone())
                    }
                    bitwarden::FieldState::Present { vault_name } => (
                        FieldChange::Replace {
                            archived: format!("{vault_name} (replaced {date})"),
                        },
                        vault_name,
                    ),
                };
                let shown = name.unwrap_or_else(|| f.item.clone());
                let prompt = field_prompt(
                    &p,
                    &shown,
                    username.as_deref(),
                    &field_shown,
                    &change,
                    Source::Agent,
                    self.cfg.approval_timeout,
                );
                if self.approve(&p, &what, prompt).await.is_none() {
                    return deny(reply);
                }
                let write = self.vault.set_field(&id, &f.name, &f.value, &date).await;
                self.field_written(&p, &what, &f.name, write, id, username, uri, reply)
                    .await;
            }
            Resolved::NotFound => self.save_field_new(p, f, &what, reply).await,
            Resolved::Locked => {
                self.lock("bw reported the vault locked").await;
                self.record(&p.device, &what, "denied (vault locked)");
                deny(reply);
            }
            Resolved::Ambiguous(n) => {
                self.record(
                    &p.device,
                    &what,
                    &format!("ambiguous ({n} logins match; request by item id)"),
                );
                deny(reply);
            }
            Resolved::Error(e) => {
                self.vault_error(&p, &what, &e).await;
                deny(reply);
            }
        }
    }

    /// `savefield:` for an item that does not exist yet: a new login in
    /// `Agent-created` that holds the field.
    async fn save_field_new(
        &mut self,
        p: Pending,
        f: intent::SaveField,
        what: &str,
        reply: ReplyTx,
    ) {
        let Some(login_name) = intent::new_login_name(&f.item) else {
            self.record(&p.device, what, "not found");
            return deny(reply);
        };
        let uri = f.uri.clone().or_else(|| intent::new_login_uri(&f.item));
        if !self.may_create(&p, what, &login_name, uri.as_deref()).await {
            return deny(reply);
        }
        let prompt = field_prompt(
            &p,
            &login_name,
            f.username.as_deref(),
            &f.name,
            &FieldChange::Create,
            Source::Agent,
            self.cfg.approval_timeout,
        );
        if self.approve(&p, what, prompt).await.is_none()
            || !self.may_create(&p, what, &login_name, uri.as_deref()).await
        {
            return deny(reply);
        }
        self.field_login_created(
            &p,
            what,
            &login_name,
            f.username,
            uri,
            (&f.name, &f.value),
            reply,
        )
        .await;
    }

    /// Report the result of writing a field to an existing item.
    #[allow(clippy::too_many_arguments)]
    async fn field_written(
        &mut self,
        p: &Pending,
        what: &str,
        name: &str,
        write: Result<FieldWrite, String>,
        id: String,
        username: Option<String>,
        uri: Option<String>,
        reply: ReplyTx,
    ) {
        match write {
            Ok(write @ (FieldWrite::Added | FieldWrite::Replaced { .. })) => {
                self.after_write().await;
                let outcome = match write {
                    FieldWrite::Replaced { archived } => {
                        format!("field replaced (old value kept as \u{201c}{archived}\u{201d})")
                    }
                    _ => "field saved".to_string(),
                };
                self.record(&p.recipient(), what, &outcome);
                release(
                    reply,
                    CredentialData {
                        username,
                        password: None,
                        totp: None,
                        uri,
                        notes: None,
                        credential_id: Some(id),
                        domain: None,
                    },
                );
            }
            Ok(FieldWrite::Unchanged) => {
                self.record(&p.recipient(), what, "unchanged");
                deny(reply);
            }
            Ok(FieldWrite::Ambiguous(n)) => {
                self.record(
                    &p.device,
                    what,
                    &format!("refused ({n} fields named {name})"),
                );
                deny(reply);
            }
            Ok(FieldWrite::Linked) => {
                self.record(&p.device, what, "refused (field is linked)");
                deny(reply);
            }
            Err(e) => {
                self.vault_error(p, what, &e).await;
                deny(reply);
            }
        }
    }

    /// Create a login in `Agent-created` that holds one hidden field, and report it.
    #[allow(clippy::too_many_arguments)]
    async fn field_login_created(
        &mut self,
        p: &Pending,
        what: &str,
        login_name: &str,
        username: Option<String>,
        uri: Option<String>,
        field: (&str, &str),
        reply: ReplyTx,
    ) {
        let written = async {
            let folder = self
                .vault
                .agent_folder(true)
                .await?
                .ok_or("no Agent-created folder")?;
            let notes = format!(
                "Saved by aac-touchid for {} on {}: {}",
                p.agent.as_deref().unwrap_or("an agent"),
                p.device,
                p.why.as_deref().unwrap_or("no reason given")
            );
            self.vault
                .create_login(&bitwarden::NewLogin {
                    name: login_name,
                    username: username.as_deref(),
                    password: None,
                    field: Some(field),
                    uri: uri.as_deref(),
                    folder_id: &folder,
                    notes: &notes,
                })
                .await
        }
        .await;
        match written {
            Ok(id) => {
                self.after_write().await;
                self.record(&p.recipient(), what, "field saved (new login)");
                release(
                    reply,
                    CredentialData {
                        username,
                        password: None,
                        totp: None,
                        uri,
                        notes: None,
                        credential_id: Some(id),
                        domain: None,
                    },
                );
            }
            Err(e) => {
                self.vault_error(p, what, &e).await;
                deny(reply);
            }
        }
    }

    /// `ask:` stores a value the human types on the panel as a hidden field
    /// of an item (or of a new login). The agent never sees the value.
    async fn ask_value(&mut self, p: Pending, a: intent::AskValue, reply: ReplyTx) {
        let what = format!("ask {} {}", a.item, a.name);
        if !self.admit(&p, &what).await || !self.sync(&p, &what).await {
            return deny(reply);
        }
        let date = bitwarden::utc_date(now_secs());
        match self.vault.resolve(&a.item).await {
            Resolved::Item(mut item) => {
                let id = item["id"].as_str().map(String::from);
                let name = item["name"].as_str().map(String::from);
                let username = item["login"]["username"]
                    .as_str()
                    .filter(|u| !u.is_empty())
                    .map(String::from);
                let uri = item["login"]["uris"][0]["uri"].as_str().map(String::from);
                // The sentinel never equals a stored value, so `Same` cannot occur.
                let state = bitwarden::field_state(&item, &a.name, "\u{0}");
                wipe(&mut item);
                let Some(id) = id else {
                    self.record(&p.device, &what, "refused (item has no id)");
                    return deny(reply);
                };
                let (change, field_shown) = match state {
                    bitwarden::FieldState::Ambiguous(n) => {
                        self.record(
                            &p.device,
                            &what,
                            &format!("refused ({n} fields named {})", a.name),
                        );
                        return deny(reply);
                    }
                    bitwarden::FieldState::Linked => {
                        self.record(&p.device, &what, "refused (field is linked)");
                        return deny(reply);
                    }
                    bitwarden::FieldState::Present { vault_name } => (
                        FieldChange::Replace {
                            archived: format!("{vault_name} (replaced {date})"),
                        },
                        vault_name,
                    ),
                    _ => (FieldChange::Add, a.name.clone()),
                };
                let shown = name.unwrap_or_else(|| a.item.clone());
                let prompt = field_prompt(
                    &p,
                    &shown,
                    username.as_deref(),
                    &field_shown,
                    &change,
                    Source::Human,
                    ASK_TIMEOUT,
                );
                let Some(value) = self.typed_value(&p, &what, prompt).await else {
                    return deny(reply);
                };
                let write = self.vault.set_field(&id, &a.name, &value, &date).await;
                self.field_written(&p, &what, &a.name, write, id, username, uri, reply)
                    .await;
            }
            Resolved::NotFound => {
                let Some(login_name) = intent::new_login_name(&a.item) else {
                    self.record(&p.device, &what, "not found");
                    return deny(reply);
                };
                let uri = a.uri.clone().or_else(|| intent::new_login_uri(&a.item));
                if !self
                    .may_create(&p, &what, &login_name, uri.as_deref())
                    .await
                {
                    return deny(reply);
                }
                let prompt = field_prompt(
                    &p,
                    &login_name,
                    a.username.as_deref(),
                    &a.name,
                    &FieldChange::Create,
                    Source::Human,
                    ASK_TIMEOUT,
                );
                let Some(value) = self.typed_value(&p, &what, prompt).await else {
                    return deny(reply);
                };
                if !self
                    .may_create(&p, &what, &login_name, uri.as_deref())
                    .await
                {
                    return deny(reply);
                }
                self.field_login_created(
                    &p,
                    &what,
                    &login_name,
                    a.username,
                    uri,
                    (&a.name, &value),
                    reply,
                )
                .await;
            }
            Resolved::Locked => {
                self.lock("bw reported the vault locked").await;
                self.record(&p.device, &what, "denied (vault locked)");
                deny(reply);
            }
            Resolved::Ambiguous(n) => {
                self.record(
                    &p.device,
                    &what,
                    &format!("ambiguous ({n} logins match; request by item id)"),
                );
                deny(reply);
            }
            Resolved::Error(e) => {
                self.vault_error(&p, &what, &e).await;
                deny(reply);
            }
        }
    }

    /// Show a panel with a value field and return what the human typed, if
    /// they approved and it is storable.
    async fn typed_value(
        &mut self,
        p: &Pending,
        what: &str,
        prompt: Prompt,
    ) -> Option<Zeroizing<String>> {
        let approval = self.approve(p, what, prompt).await?;
        let value = approval
            .value
            .map(|v| Zeroizing::new(v.trim().to_string()))?;
        if !intent::valid_field_value(&value) {
            self.record(
                &p.device,
                what,
                "refused (value must be 1-4096 characters without control characters)",
            );
            return None;
        }
        Some(value)
    }

    /// Replace an existing login's password with a generated one.
    async fn rotate(&mut self, p: Pending, r: Rotate, reply: ReplyTx) {
        let what = format!("rotate {}", r.item);
        if !self.admit(&p, &what).await || !self.sync(&p, &what).await {
            return deny(reply);
        }
        let Some(mut item) = self.resolve_one(&p, &what, &r.item).await else {
            return deny(reply);
        };
        let id = item["id"].as_str().map(String::from);
        let name = item["name"].as_str().map(String::from);
        let username = item["login"]["username"]
            .as_str()
            .filter(|u| !u.is_empty())
            .map(String::from);
        // Setting the username it already has is no change.
        let new_username = r.username.clone().filter(|u| Some(u) != username.as_ref());
        let uri = item["login"]["uris"][0]["uri"].as_str().map(String::from);
        let is_login = item["type"].as_i64() == Some(1) && item["login"].is_object();
        wipe(&mut item);
        let refusal = match &id {
            _ if !is_login => Some("refused (not a login)"),
            None => Some("refused (item has no id)"),
            _ => None,
        };
        let (Some(id), None) = (id, refusal) else {
            self.record(&p.device, &what, refusal.unwrap_or("refused"));
            return deny(reply);
        };
        let shown = name.unwrap_or_else(|| r.item.clone());
        let prompt = rotate_prompt(
            &p,
            &shown,
            username.as_deref(),
            new_username.as_deref(),
            &r.secret.describe(),
            self.cfg.approval_timeout,
        );
        if self.approve(&p, &what, prompt).await.is_none() {
            return deny(reply);
        }
        let written = async {
            let password = self.vault.generate(r.secret).await?;
            let write = self
                .vault
                .set_password(&id, &password, new_username.as_deref())
                .await?;
            Ok::<_, String>((password, write))
        }
        .await;
        match written {
            Ok((password, PasswordWrite::Replaced { history_kept })) => {
                self.after_write().await;
                let username = new_username.or(username);
                if history_kept {
                    self.record(&p.recipient(), &what, "rotated");
                } else {
                    warn!("rotate: the old password is not in the item's history");
                    self.record(
                        &p.recipient(),
                        &what,
                        "rotated (old password not kept in history)",
                    );
                }
                release(
                    reply,
                    CredentialData {
                        username,
                        password: Some(password),
                        totp: None,
                        uri,
                        notes: None,
                        credential_id: Some(id),
                        domain: None,
                    },
                );
            }
            Ok((_, PasswordWrite::NotLogin)) => {
                self.record(&p.device, &what, "refused (not a login)");
                deny(reply);
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
        let Some(mut item) = self.resolve_one(&p, &what, &t.item).await else {
            return deny(reply);
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
        let prompt = totp_prompt(&p, &shown, username.as_deref(), self.cfg.approval_timeout);
        if self.approve(&p, &what, prompt).await.is_none() {
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

/// What `status` shows for a grant: the item, and its field when it has one.
fn grant_label(item: &str, field: Option<&str>) -> String {
    match field {
        Some(f) => format!("{item} \u{b7} field {f}"),
        None => item.to_string(),
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
                let mut s = shared(&shared_state);
                let grants = s.grants.snapshot(Instant::now());
                Response {
                    ok: true,
                    status: Some(Status {
                        unlocked: s.unlocked,
                        relay: s.relay.clone(),
                        devices: FileConnections::load(&dir)
                            .map(|c| c.devices())
                            .unwrap_or_default(),
                        recent: s.recent.iter().cloned().collect(),
                        grants,
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
            Request::Forget => {
                let n = shared(&shared_state).grants.clear();
                Response::ok(format!("forgot {n} remembered approval(s)"))
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
                Ok(n) => {
                    shared(&shared_state).grants.clear();
                    Response::ok(format!("revoked {n} device(s) named {name}"))
                }
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
    fn recent_for_filters_by_device_and_age() {
        let d = |at: u64, device: &str, query: &str, outcome: &str| Decision {
            at,
            device: device.to_string(),
            query: query.to_string(),
            outcome: outcome.to_string(),
        };
        let now = 10_000;
        let mut recent: VecDeque<Decision> = VecDeque::new();
        // Newest first, like `Service::record`.
        recent.push_back(d(now - 10, "mac-pro", "other", "approved"));
        recent.push_back(d(
            now - 40,
            "nuc",
            "new Speedtest",
            "refused (already exists)",
        ));
        recent.push_back(d(now - 100, "pi (nuc)", "github.com", "approved"));
        recent.push_back(d(now - 1000, "nuc", "old", "denied"));
        assert_eq!(
            recent_for(&recent, "nuc", now),
            "new Speedtest: refused (already exists), 40 s ago; github.com: approved, 1 min ago"
        );
        assert_eq!(
            recent_for(&recent, "laptop", now),
            "no decisions for this device in the last 15 min"
        );
        for i in 0..8 {
            recent.push_front(d(now - i, "nuc", &format!("q{i}"), "denied"));
        }
        assert_eq!(recent_for(&recent, "nuc", now).split("; ").count(), 5);
    }

    #[test]
    fn audit_and_labels_never_show_a_seed() {
        let seed = "JBSWY3DPEHPK3PXP";
        for raw in [
            format!("totp:acme.io secret={seed} | pi | enroll"),
            format!("totp:acme.io uri=otpauth://totp/a?secret={seed}"),
            format!("totp:acme.io secret={seed} {seed}"),
            format!("save:Acme Corp user=a password64={seed} | pi | store"),
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

    fn pending(agent: Option<&str>, why: Option<&str>) -> Pending {
        Pending {
            identity: IdentityKeyPair::generate().identity().fingerprint(),
            device: "nuc".into(),
            who: requester(agent, "nuc"),
            agent: agent.map(String::from),
            why: why.map(String::from),
        }
    }

    fn mins(d: u64) -> Option<Duration> {
        Some(Duration::from_secs(d * 60))
    }

    fn labels(c: &[Choice]) -> Vec<&str> {
        c.iter().map(|c| c.label.as_str()).collect()
    }

    #[test]
    fn read_choices_offer_and_preselect() {
        let (c, d) = read_choices(None, Duration::from_secs(3600));
        assert_eq!(labels(&c), ["Allow once", "Allow 15 min", "Allow 1 h"]);
        assert_eq!(d, Some(0));
        let (c, d) = read_choices(mins(15), Duration::from_secs(3600));
        assert_eq!(labels(&c), ["Allow once", "Allow 15 min", "Allow 1 h"]);
        assert_eq!(d, Some(1));
        let (c, d) = read_choices(mins(30), Duration::from_secs(3600));
        assert_eq!(
            labels(&c),
            ["Allow once", "Allow 15 min", "Allow 30 min", "Allow 1 h"]
        );
        assert_eq!(d, Some(2));
        let (c, _) = read_choices(None, Duration::ZERO);
        assert_eq!(labels(&c), ["Allow once"]);
        let (c, d) = read_choices(mins(10), Duration::from_secs(600));
        assert_eq!(labels(&c), ["Allow once", "Allow 10 min"]);
        assert_eq!(d, Some(1));
    }

    #[test]
    fn read_prompt_rows() {
        let t = Duration::from_secs(60);
        let p = pending(Some("pi \u{b7} homelab"), Some("log in with gh"));
        let pr = read_prompt(
            &p,
            "GitHub",
            Some("me@x.com"),
            "password + 2FA code",
            None,
            Duration::from_secs(3600),
            t,
        );
        assert_eq!(pr.title, "Share a password + 2FA code");
        let rows: Vec<(&str, &str)> = pr
            .rows
            .iter()
            .map(|r| (r.label.as_str(), r.value.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("Agent", "pi \u{b7} homelab"),
                ("Device", "nuc"),
                ("Item", "GitHub"),
                ("Username", "me@x.com"),
                ("Releases", "password + 2FA code"),
                ("Reason", "log in with gh"),
            ]
        );
        assert_eq!(pr.touch_reason, "share GitHub with nuc");
        assert_eq!(pr.timeout_secs, 60);
        assert!(pr.note.is_some() && pr.input.is_none());
        let p = pending(None, None);
        let pr = read_prompt(&p, "x", Some(""), "password", None, Duration::ZERO, t);
        assert_eq!(pr.rows[0].value, "not given");
        assert_eq!(
            pr.rows.last().map(|r| r.value.as_str()),
            Some("no reason given")
        );
        assert!(pr.rows.iter().all(|r| r.label != "Username"));
    }

    #[test]
    fn batch_prompt_rows() {
        let t = Duration::from_secs(60);
        let p = pending(Some("pi"), Some("ship"));
        let lines = [
            BatchLine {
                name: "GitHub".into(),
                username: Some("me".into()),
                fields: "password".into(),
            },
            BatchLine {
                name: "npm".into(),
                username: None,
                fields: "password + 2FA code".into(),
            },
        ];
        let pr = batch_prompt(&p, &lines, None, Duration::from_secs(3600), t);
        assert_eq!(pr.title, "Share 2 logins");
        let v = |l: &str| {
            pr.rows
                .iter()
                .find(|r| r.label == l)
                .map(|r| r.value.clone())
        };
        assert_eq!(v("Item 1").as_deref(), Some("GitHub (me) \u{b7} password"));
        assert_eq!(
            v("Item 2").as_deref(),
            Some("npm \u{b7} password + 2FA code")
        );
        let one = batch_prompt(&p, &lines[..1], None, Duration::ZERO, t);
        assert_eq!(one.title, "Share 1 login");
    }

    #[test]
    fn write_prompts() {
        let t = Duration::from_secs(60);
        let p = pending(Some("pi"), Some("why"));
        let c = create_prompt(&p, "Acme", Some("bot"), "6-word passphrase", t);
        assert_eq!(c.title, "Create a login");
        assert_eq!(labels(&c.choices), ["Create"]);
        assert_eq!(c.default_choice, None);
        assert!(
            c.rows
                .iter()
                .any(|r| r.label == "Password" && r.value == "new 6-word passphrase")
        );
        let r = rotate_prompt(&p, "Acme", None, Some("st"), "6-word passphrase", t);
        assert_eq!(r.title, "Replace a password");
        assert!(
            r.rows
                .iter()
                .any(|r| r.label == "New username" && r.value == "st")
        );
        let r = rotate_prompt(&p, "Acme", None, None, "6-word passphrase", t);
        assert!(r.rows.iter().all(|r| r.label != "New username"));
        assert_eq!(labels(&r.choices), ["Replace"]);
        let s = save_prompt(&p, "Acme", None, t);
        assert_eq!(s.title, "Save a password the agent supplied");
        assert_eq!(labels(&s.choices), ["Save"]);
        let a = totp_prompt(&p, "Acme", None, t);
        assert_eq!(a.title, "Add 2FA and share a 2FA code");
        assert_eq!(labels(&a.choices), ["Add 2FA"]);
        let g = pairing_prompt("nuc", 75, t);
        assert_eq!(g.title, "Pair a new device");
        assert_eq!(
            g.rows,
            vec![
                row("Device", "nuc"),
                row("Pairing code", "issued 1 min ago")
            ]
        );
        assert!(g.note.is_none());
        assert_eq!(labels(&g.choices), ["Pair"]);
    }

    #[test]
    fn field_prompts() {
        let p = pending(Some("pi"), None);
        let replace = FieldChange::Replace {
            archived: "K (replaced 2026-11-17)".into(),
        };
        let title =
            |c: &FieldChange, by| field_prompt(&p, "x", None, "K", c, by, ASK_TIMEOUT).title;
        assert_eq!(
            title(&FieldChange::Add, Source::Agent),
            "Save the field \u{201c}K\u{201d} the agent supplied"
        );
        assert_eq!(
            title(&replace, Source::Agent),
            "Replace the field \u{201c}K\u{201d} with a value the agent supplied"
        );
        assert_eq!(
            title(&FieldChange::Create, Source::Agent),
            "Create a login holding the field \u{201c}K\u{201d} the agent supplied"
        );
        assert_eq!(
            title(&FieldChange::Add, Source::Human),
            "Enter a value for the field \u{201c}K\u{201d}"
        );
        assert_eq!(
            title(&replace, Source::Human),
            "Enter a new value for the field \u{201c}K\u{201d}"
        );
        assert_eq!(
            title(&FieldChange::Create, Source::Human),
            "Create a login holding the field \u{201c}K\u{201d}"
        );
        let h = field_prompt(&p, "x", None, "K", &replace, Source::Human, ASK_TIMEOUT);
        assert!(h.rows.iter().any(|r| r.label == "Old value"));
        assert!(h.input.is_some());
        assert_eq!(h.timeout_secs, 180);
        let a = field_prompt(
            &p,
            "x",
            None,
            "K",
            &FieldChange::Add,
            Source::Agent,
            ASK_TIMEOUT,
        );
        assert!(a.rows.iter().all(|r| r.label != "Old value"));
        assert!(a.input.is_none());
    }

    #[test]
    fn clean_strips_invisible() {
        assert_eq!(
            clean("a\u{202e}b\u{200b}c\u{2066}d", 80).as_deref(),
            Some("abcd")
        );
    }
}
