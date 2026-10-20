//! aac-touchid: a background Bitwarden Agent Access listener for macOS that
//! releases each credential only after a Touch ID (or Apple Watch) approval.
//!
//! Agents keep using Bitwarden's `aac` client (`aac run --domain ...`).

mod bitwarden;
mod control;
mod dialog;
mod provision;
mod serve;
mod storage;
mod touchid;

use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};

const DEFAULT_PROXY_URL: &str = "wss://ap.lesspassword.dev";

#[derive(Parser)]
#[command(
    version,
    about = "Approve Bitwarden Agent Access requests with Touch ID"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the listener (launchd runs this; not meant for a terminal).
    Serve {
        /// Agent Access relay ("proxy") URL; must match the agents' `aac`.
        #[arg(long, default_value = DEFAULT_PROXY_URL)]
        proxy_url: String,
        /// Lock the vault after this many hours without an approval.
        #[arg(long, default_value_t = 8)]
        lock_after_hours: u64,
        /// Seconds to wait for a Touch ID answer before denying.
        #[arg(long, default_value_t = 60)]
        approval_timeout: u64,
        /// Keep this Mac's own `aac` paired, under this name.
        #[arg(long, value_name = "NAME")]
        pair_local: Option<String>,
        /// Keep this ssh host's `aac` paired (repeatable).
        #[arg(long, value_name = "HOST")]
        pair_ssh: Vec<String>,
    },
    /// Print a one-time pairing code (5 minutes) for a new device.
    Pair {
        /// Name to show in approval prompts, e.g. `nuc`.
        name: Option<String>,
    },
    /// Show lock state, relay connection, paired devices and recent decisions.
    Status {
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Lock the vault now.
    Lock,
    /// Forget a paired device by name (or fingerprint prefix).
    Revoke { name: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("aac-touchid: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(async {
        match cli.command {
            Command::Serve {
                proxy_url,
                lock_after_hours,
                approval_timeout,
                pair_local,
                pair_ssh,
            } => {
                tracing_subscriber::fmt()
                    .with_env_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| "aac_touchid=info,ap_client=warn".into()),
                    )
                    .with_writer(std::io::stderr)
                    .with_ansi(false)
                    .init();
                let cfg = serve::Config {
                    proxy_url,
                    lock_after: Duration::from_secs(lock_after_hours * 3600),
                    approval_timeout: Duration::from_secs(approval_timeout),
                    targets: pair_local
                        .iter()
                        .map(|n| provision::Target::local(n))
                        .chain(pair_ssh.iter().map(|h| provision::Target::ssh(h)))
                        .collect(),
                };
                match serve::run(cfg).await {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        eprintln!("aac-touchid: {e}");
                        ExitCode::FAILURE
                    }
                }
            }
            Command::Pair { name } => client(control::Request::Pair { name }, false).await,
            Command::Status { json } => client(control::Request::Status, json).await,
            Command::Lock => client(control::Request::Lock, false).await,
            Command::Revoke { name } => client(control::Request::Revoke { name }, false).await,
        }
    })
}

fn ago(at: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let s = now.saturating_sub(at);
    match s {
        0..60 => format!("{s}s ago"),
        60..3600 => format!("{}m ago", s / 60),
        3600..86400 => format!("{}h ago", s / 3600),
        _ => format!("{}d ago", s / 86400),
    }
}

async fn client(req: control::Request, json: bool) -> ExitCode {
    let dir = match storage::state_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("aac-touchid: {e}");
            return ExitCode::FAILURE;
        }
    };
    let resp = match control::call(&control::socket_path(&dir), &req).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("aac-touchid: {e}");
            return ExitCode::FAILURE;
        }
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&resp).unwrap_or_default()
        );
    } else if let Some(code) = &resp.code {
        println!("{code}");
        eprintln!(
            "Pairing code, valid 5 minutes. On the other machine: aac run --token {code} --domain <domain> --env VAR=password -- <command>\nApprove the pairing with Touch ID when it appears."
        );
    } else if let Some(s) = &resp.status {
        println!("vault: {}", if s.unlocked { "unlocked" } else { "locked" });
        println!("relay: {}", s.relay);
        println!("paired devices:");
        if s.devices.is_empty() {
            println!("  (none)");
        }
        for d in &s.devices {
            println!(
                "  {}  {}",
                d.name,
                &d.fingerprint[..12.min(d.fingerprint.len())]
            );
        }
        println!("recent decisions:");
        if s.recent.is_empty() {
            println!("  (none)");
        }
        for r in &s.recent {
            println!(
                "  {:>9}  {}  {}  {}",
                ago(r.at),
                r.device,
                r.query,
                r.outcome
            );
        }
    } else if let Some(m) = &resp.message {
        if resp.ok {
            println!("{m}");
        } else {
            eprintln!("aac-touchid: {m}");
        }
    }
    if resp.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
