//! Vault access through the official Bitwarden CLI (`bw`).
//!
//! Modeled on Bitwarden Agent Access `ap-cli` (`providers/bitwarden.rs`,
//! v0.11.0, Apache-2.0). The session key exists only in this process's
//! memory and reaches `bw` only as the environment of a short-lived child.

use std::process::Command;

use ap_client::{CredentialData, CredentialQuery};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use zeroize::Zeroizing;

const BW_FALLBACK_PATHS: &[&str] = &["/opt/homebrew/bin/bw", "/usr/local/bin/bw"];

#[derive(Debug)]
pub enum Lookup {
    /// The credential and the vault item's name.
    Found(Box<CredentialData>, Option<String>),
    NotFound,
    /// Several logins match; the requester must ask by item id.
    Ambiguous(usize),
    Locked,
    Error(String),
}

pub struct Vault {
    bw: Option<String>,
    session: Option<SecretString>,
}

#[derive(Deserialize)]
struct BwItem {
    id: Option<String>,
    name: Option<String>,
    notes: Option<String>,
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

impl Vault {
    pub fn new() -> Self {
        Self {
            bw: resolve_bw(),
            session: None,
        }
    }

    pub fn installed(&self) -> bool {
        self.bw.is_some()
    }

    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
    }

    fn cmd(&self, args: &[&str]) -> Option<Command> {
        let mut c = Command::new(self.bw.as_deref()?);
        c.args(args).env("BW_NOINTERACTION", "true");
        if let Some(s) = &self.session {
            c.env("BW_SESSION", s.expose_secret());
        }
        Some(c)
    }

    /// Unlock with the master password, then sync.
    pub fn unlock(&mut self, password: &str) -> Result<(), String> {
        let bw = self.bw.as_deref().ok_or("Bitwarden CLI (bw) not found")?;
        let out = Command::new(bw)
            .args(["unlock", "--passwordenv", "BW_MASTER_PASSWORD", "--raw"])
            .env("BW_MASTER_PASSWORD", password)
            .env("BW_NOINTERACTION", "true")
            .output()
            .map_err(|e| format!("run bw unlock: {e}"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(if err.is_empty() {
                "bw unlock failed".to_string()
            } else {
                err
            });
        }
        let key = Zeroizing::new(String::from_utf8_lossy(&out.stdout).trim().to_string());
        if key.is_empty() {
            return Err("bw unlock returned no session key".to_string());
        }
        self.session = Some(SecretString::from(key.as_str().to_string()));
        if let Some(mut c) = self.cmd(&["sync"]) {
            let _ = c.output();
        }
        Ok(())
    }

    /// Forget the session key and lock the CLI so the key is useless if it leaked.
    pub fn lock(&mut self) {
        if self.session.is_some() {
            if let Some(mut c) = self.cmd(&["lock"]) {
                let _ = c.output();
            }
        }
        self.session = None;
    }

    pub fn lookup(&self, query: &CredentialQuery) -> Lookup {
        if self.bw.is_none() {
            return Lookup::Error("Bitwarden CLI (bw) not found".to_string());
        }
        if self.session.is_none() {
            return Lookup::Locked;
        }
        let search = query.search_string();
        let Some(mut c) = self.cmd(&["get", "item", search]) else {
            return Lookup::Error("bw not found".to_string());
        };
        let out = match c.output() {
            Ok(o) => o,
            Err(e) => return Lookup::Error(format!("run bw: {e}")),
        };
        if out.status.success() {
            return match serde_json::from_slice::<BwItem>(&out.stdout) {
                Ok(item) => self.to_credential(item),
                Err(e) => Lookup::Error(format!("parse bw item: {e}")),
            };
        }
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("More than one result") {
            return self.lookup_by_url(search);
        }
        if err.contains("Not found") {
            return Lookup::NotFound;
        }
        if err.contains("locked") || err.contains("Session key is invalid") {
            return Lookup::Locked;
        }
        Lookup::Error(err.trim().to_string())
    }

    /// Disambiguate a domain by exact login URI host.
    fn lookup_by_url(&self, domain: &str) -> Lookup {
        let Some(mut c) = self.cmd(&["list", "items", "--search", domain]) else {
            return Lookup::Error("bw not found".to_string());
        };
        let items: Vec<BwItem> = match c.output() {
            Ok(o) if o.status.success() => serde_json::from_slice(&o.stdout).unwrap_or_default(),
            _ => return Lookup::NotFound,
        };
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
                Some(item) => self.to_credential(item),
                None => Lookup::NotFound,
            },
            n => Lookup::Ambiguous(n),
        }
    }

    fn to_credential(&self, item: BwItem) -> Lookup {
        let Some(login) = item.login else {
            return Lookup::NotFound;
        };
        let uri = login.uris.iter().flatten().find_map(|u| u.uri.clone());
        let domain = uri
            .as_deref()
            .and_then(host_of)
            .or_else(|| item.name.clone());
        // The vault stores the TOTP seed; send the current code instead.
        let totp = match (&login.totp, &item.id) {
            (Some(_), Some(id)) => self.cmd(&["get", "totp", id]).and_then(|mut c| {
                c.output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            }),
            _ => None,
        };
        Lookup::Found(
            Box::new(CredentialData {
                username: login.username,
                password: login.password.map(Zeroizing::new),
                totp,
                uri,
                notes: item.notes,
                credential_id: item.id,
                domain,
            }),
            item.name,
        )
    }
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
    fn locked_vault_never_runs_bw() {
        let v = Vault {
            bw: Some("/nonexistent/bw".to_string()),
            session: None,
        };
        assert!(matches!(
            v.lookup(&CredentialQuery::Domain("github.com".into())),
            Lookup::Locked
        ));
    }
}
