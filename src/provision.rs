//! Keep agent machines paired with no setup step.
//!
//! The service is told which machines' agents it approves for: this Mac
//! (`--pair-local <name>`) and hosts reached over ssh (`--pair-ssh <host>`).
//! Whenever the relay connects, and every 30 minutes, it checks each one's
//! `aac` client and pairs any that is not paired with this listener: it issues
//! a one-time pre-shared-key token and hands it straight to that machine's
//! `aac` over the local process or ssh (on stdin, never on a command line).
//! A PSK pairing authenticates both ends cryptographically, so it needs no
//! Touch ID; every credential request still does.
//!
//! This Mac's own `aac` is paired with this listener alone (`aac` refuses to
//! choose between several connections). An ssh host may be paired with several
//! Macs: while you use a Mac, its listener marks it present on each host every
//! minute (`~/.local/state/aac-touchid/presence/<listener fingerprint>`), and
//! the host's `aac` wrapper asks the Mac you used most recently.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use ap_client::IdentityProvider;
use ap_client::UserClient;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{info, warn};

use crate::storage::{FileConnections, FileIdentity};

/// The request a pairing check sends; the listener answers it without a sheet.
pub const MARKER: &str = "aac-touchid.pairing";
const RUN_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Where {
    Local,
    Ssh(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub name: String,
    pub at: Where,
}

impl Target {
    pub fn local(name: &str) -> Self {
        Self {
            name: name.to_string(),
            at: Where::Local,
        }
    }
    pub fn ssh(host: &str) -> Self {
        Self {
            name: host.to_string(),
            at: Where::Ssh(host.to_string()),
        }
    }
}

/// What `aac connections list --client-type remote` says about a machine.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ClientSide {
    pub identity: Option<String>,
    pub peers: Vec<String>,
}

pub fn parse_list(out: &str) -> ClientSide {
    let mut side = ClientSide::default();
    for line in strip_ansi(out).lines() {
        let line = line.trim();
        if let Some(id) = line.strip_prefix("Your identity:") {
            if side.identity.is_none() {
                side.identity = Some(id.trim().to_ascii_lowercase());
            }
        } else if let Some(peer) = line.strip_prefix("- ") {
            let peer = peer.trim();
            if peer.len() == 64 && peer.chars().all(|c| c.is_ascii_hexdigit()) {
                side.peers.push(peer.to_ascii_lowercase());
            }
        }
    }
    side
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Run an `aac` command line on the target; `stdin` becomes `AAC_TOKEN`.
async fn aac(at: &Where, args: &[&str], token: Option<&str>) -> Result<(bool, String), String> {
    let line = args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ");
    let script = match token {
        Some(_) => format!("PATH=\"$HOME/.local/bin:$PATH\"; AAC_TOKEN=$(cat) exec aac {line}"),
        None => format!("PATH=\"$HOME/.local/bin:$PATH\"; exec aac {line}"),
    };
    let mut cmd = match at {
        Where::Local => {
            let mut c = Command::new("/bin/sh");
            c.arg("-c").arg(&script);
            c
        }
        Where::Ssh(host) => {
            let mut c = Command::new("/usr/bin/ssh");
            c.args(SSH_OPTS).arg(host).arg(&script);
            c
        }
    };
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        if let Some(t) = token {
            let _ = stdin.write_all(t.as_bytes()).await;
        }
    }
    let out = tokio::time::timeout(RUN_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|e| format!("wait: {e}"))?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    ))
}

async fn client_side(at: &Where) -> Result<ClientSide, String> {
    let (ok, out) = aac(
        at,
        &["connections", "list", "--client-type", "remote"],
        None,
    )
    .await?;
    if !ok {
        return Err("aac is not installed there, or the host is unreachable".to_string());
    }
    Ok(parse_list(&out))
}

const SSH_OPTS: &[&str] = &[
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "ClearAllForwardings=yes",
];

/// Paired when the listener knows the machine's current identity and the
/// machine has this listener as its only peer (this Mac) or among its peers
/// (an ssh host shared by several Macs).
pub fn is_paired(side: &ClientSide, own: &str, known: &[String], shared: bool) -> bool {
    let peers_ok = if shared {
        side.peers.iter().any(|p| p == own)
    } else {
        side.peers == [own.to_string()]
    };
    peers_ok && side.identity.as_ref().is_some_and(|id| known.contains(id))
}

pub async fn listener_fingerprint(dir: &Path) -> Option<String> {
    let id = FileIdentity::load_or_generate(dir).ok()?;
    Some(hex::encode(id.identity().await.identity().fingerprint().0))
}

/// Check one machine and pair it if needed. Returns a short outcome.
pub async fn ensure(
    target: &Target,
    client: &UserClient,
    dir: &Path,
    own: &str,
) -> Result<&'static str, String> {
    let known = || -> Vec<String> {
        FileConnections::load(dir)
            .map(|c| c.devices().into_iter().map(|d| d.fingerprint).collect())
            .unwrap_or_default()
    };
    let shared = matches!(target.at, Where::Ssh(_));
    let side = client_side(&target.at).await?;
    if is_paired(&side, own, &known(), shared) {
        return Ok("already paired");
    }
    // A stale connection to this listener (or, on this Mac, any other) would
    // make `aac` use a dead session; `aac` can only clear them all. Other Macs
    // sharing a host re-pair on their next check.
    if (!shared && !side.peers.is_empty()) || side.peers.iter().any(|p| p == own) {
        aac(
            &target.at,
            &[
                "connections",
                "clear",
                "connections",
                "--client-type",
                "remote",
            ],
            None,
        )
        .await?;
    }
    let token = client
        .get_psk_token(Some(target.name.clone()), false)
        .await
        .map_err(|e| format!("token: {e}"))?;
    let _ = aac(
        &target.at,
        &[
            "run",
            "--domain",
            MARKER,
            "--env",
            "X=username",
            "--timeout",
            "60",
            "--",
            "true",
        ],
        Some(&token),
    )
    .await?;
    let side = client_side(&target.at).await?;
    if is_paired(&side, own, &known(), shared) {
        Ok("paired")
    } else {
        Err("pairing did not complete".to_string())
    }
}

pub async fn ensure_all(targets: &[Target], client: &UserClient, dir: &Path) {
    let Some(own) = listener_fingerprint(dir).await else {
        warn!("pairing: no listener identity");
        return;
    };
    for t in targets {
        match ensure(t, client, dir, &own).await {
            Ok("already paired") => {}
            Ok(outcome) => info!("pairing: {} {outcome}", t.name),
            Err(e) => warn!("pairing: {} not paired: {e}", t.name),
        }
    }
}

/// Seconds since the last keyboard or pointer input on this Mac.
fn idle_secs() -> Option<u64> {
    let out = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-c", "IOHIDSystem", "-d", "4"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.contains("\"HIDIdleTime\""))?;
    let ns: u64 = line.rsplit('=').next()?.trim().parse().ok()?;
    Some(ns / 1_000_000_000)
}

pub const PRESENCE_ACTIVE: u64 = 90;

/// Mark this Mac present on each ssh host while someone is using it.
pub async fn mark_present(targets: &[Target], own: &str, name: &str) {
    let idle = tokio::task::spawn_blocking(idle_secs).await.ok().flatten();
    if idle.is_none_or(|s| s > PRESENCE_ACTIVE) {
        return;
    }
    for t in targets {
        let Where::Ssh(host) = &t.at else { continue };
        let script = format!(
            "d=\"$HOME/.local/state/aac-touchid/presence\"; mkdir -p \"$d\" && echo \"$(date +%s) {}\" > \"$d/{own}.tmp\" && mv \"$d/{own}.tmp\" \"$d/{own}\"",
            quote(name)
        );
        let status = Command::new("/usr/bin/ssh")
            .args(SSH_OPTS)
            .arg(host)
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status();
        if !matches!(tokio::time::timeout(Duration::from_secs(20), status).await, Ok(Ok(s)) if s.success())
        {
            tracing::debug!("presence: {host} unreachable");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "7a21d7f545e47fd8239a0c4828d19c9aba5d934984fbae1850ba055a1401893d";
    const L: &str = "b6f1f3aacbd4114b5a31d30da329b7afe431b18fd437a83dcc89f134722ed6d9";

    #[test]
    fn parses_aac_listing() {
        let out = format!(
            "\u{1b}[1m── Remote Client (ap-cli connect) ──\u{1b}[0m\n  Your identity: {A}\n  Connections: (1 peer)\n    - {L}\n      Paired: just now  |  Last used: just now\n"
        );
        assert_eq!(
            parse_list(&out),
            ClientSide {
                identity: Some(A.into()),
                peers: vec![L.into()]
            }
        );
        let none = format!("  Your identity: {A}\n  Connections: (none)\n");
        assert_eq!(parse_list(&none).peers, Vec::<String>::new());
    }

    #[test]
    fn paired_needs_both_ends() {
        let one = |peers: Vec<&str>| ClientSide {
            identity: Some(A.into()),
            peers: peers.into_iter().map(String::from).collect(),
        };
        assert!(is_paired(&one(vec![L]), L, &[A.into()], false));
        assert!(
            !is_paired(&one(vec![L]), L, &[], false),
            "listener forgot the machine"
        );
        assert!(
            !is_paired(&one(vec![L, A]), L, &[A.into()], false),
            "this Mac's aac needs one peer"
        );
        assert!(
            is_paired(&one(vec![L, A]), L, &[A.into()], true),
            "a shared host may have several"
        );
        assert!(!is_paired(&one(vec![A]), L, &[A.into()], true));
    }

    #[test]
    fn quoting() {
        assert_eq!(quote("a'b"), r"'a'\''b'");
    }
}
