//! `aac-touchid run`: fill `bw://` references in a command's environment.
//!
//! Sends one `batch:` request when several items are needed (one Touch ID
//! sheet), then reads each item with stock `aac connect --output json`, and
//! `exec`s the command. Secrets only ever live in that process's environment.

use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use ap_client::CredentialData;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::intent;
use crate::refs::{self, Part};

pub struct Args {
    pub env_files: Vec<PathBuf>,
    pub agent: Option<String>,
    pub reason: Option<String>,
    pub remember: Option<String>,
    pub timeout: u64,
    pub command: Vec<String>,
}

#[derive(Debug)]
struct Failure {
    code: u8,
    message: String,
}

fn failure(message: impl Into<String>) -> Failure {
    Failure {
        code: 1,
        message: message.into(),
    }
}

fn fail(f: Failure) -> ExitCode {
    eprintln!("aac-touchid: {}", f.message);
    ExitCode::from(f.code)
}

pub fn main(args: Args) -> ExitCode {
    match go(args) {
        Ok(never) => match never {},
        Err(f) => fail(f),
    }
}

fn go(args: Args) -> Result<std::convert::Infallible, Failure> {
    if let Some(r) = &args.remember {
        intent::parse_span(r).map_err(|e| failure(e.to_string()))?;
    }
    let mut env: BTreeMap<OsString, OsString> = std::env::vars_os().collect();
    for path in &args.env_files {
        let text = std::fs::read_to_string(path)
            .map_err(|e| failure(format!("cannot read {}: {e}", path.display())))?;
        let pairs = refs::parse_env_file(&path.display().to_string(), &text).map_err(failure)?;
        for (k, v) in pairs {
            env.insert(k.into(), v.into());
        }
    }
    let agent = args
        .agent
        .clone()
        .or_else(|| std::env::var("AAC_AGENT").ok());
    let tail = tail(agent.as_deref(), args.reason.as_deref());
    let aac = std::env::var_os("AAC_TOUCHID_AAC").unwrap_or_else(|| "aac".into());
    let timeout = args.timeout;
    resolve(&mut env, args.remember.as_deref(), &tail, &mut |d| {
        fetch_with(&aac, d, timeout)
    })?;
    let Some((cmd, rest)) = args.command.split_first() else {
        return Err(failure("no command given"));
    };
    let err = Command::new(cmd).args(rest).env_clear().envs(&env).exec();
    Err(Failure {
        code: if err.kind() == std::io::ErrorKind::NotFound {
            127
        } else {
            126
        },
        message: format!("cannot run {cmd}: {err}"),
    })
}

/// The ` | agent | reason` part of a request.
fn tail(agent: Option<&str>, reason: Option<&str>) -> String {
    let agent = agent
        .map(|a| a.replace('|', " ").trim().to_string())
        .filter(|a| !a.is_empty());
    let reason = reason
        .map(|r| r.replace(['\n', '\r'], " ").trim().to_string())
        .filter(|r| !r.is_empty());
    match (agent, reason) {
        (Some(a), Some(r)) => format!(" | {a} | {r}"),
        (Some(a), None) => format!(" | {a} | "),
        (None, Some(r)) => format!(" | {r}"),
        (None, None) => String::new(),
    }
}

/// The batch request (when two or more items) and the per-item reads.
fn plan_domains(
    items: &[String],
    remember: Option<&str>,
    tail: &str,
) -> (Option<String>, Vec<String>) {
    let rem = remember.map_or_else(String::new, |r| format!(" remember={r}"));
    if items.len() == 1 {
        return (None, vec![format!("{}{rem}{tail}", items[0])]);
    }
    (
        Some(format!("batch:{}{rem}{tail}", items.join(","))),
        items.iter().map(|i| format!("{i}{tail}")).collect(),
    )
}

type Fetch<'a> = dyn FnMut(&str) -> Result<CredentialData, Failure> + 'a;

fn resolve(
    env: &mut BTreeMap<OsString, OsString>,
    remember: Option<&str>,
    tail: &str,
    fetch: &mut Fetch<'_>,
) -> Result<(), Failure> {
    let mut parsed: Vec<(OsString, Vec<Part>)> = Vec::new();
    let mut items: Vec<String> = Vec::new();
    for (key, value) in env.iter() {
        let Some(v) = value.to_str() else { continue };
        let name = key.to_string_lossy();
        if let Some(parts) = refs::parse_value(v).map_err(|e| failure(format!("{name}: {e}")))? {
            for p in &parts {
                if let Part::Ref(r) = p {
                    if !items.contains(&r.item) {
                        items.push(r.item.clone());
                    }
                }
            }
            parsed.push((key.clone(), parts));
        }
    }
    if items.is_empty() {
        return Ok(());
    }
    if items.len() > intent::MAX_BATCH {
        return Err(failure("at most 10 items per run"));
    }
    let (batch, reads) = plan_domains(&items, remember, tail);
    if let Some(b) = batch {
        fetch(&b)?;
    }
    let mut creds: HashMap<String, CredentialData> = HashMap::new();
    for (item, domain) in items.iter().zip(reads) {
        creds.insert(item.clone(), fetch(&domain)?);
    }
    for (key, parts) in parsed {
        let name = key.to_string_lossy().into_owned();
        let mut out = String::new();
        for p in &parts {
            match p {
                Part::Text(t) => out.push_str(t),
                Part::Ref(r) => {
                    let value =
                        creds
                            .get(&r.item)
                            .and_then(|c| r.field.get(c))
                            .ok_or_else(|| {
                                failure(format!(
                                    "{name}: bw://{} has no {}",
                                    r.item,
                                    r.field.name()
                                ))
                            })?;
                    out.push_str(value);
                }
            }
        }
        env.insert(key, out.into());
    }
    Ok(())
}

#[derive(Deserialize)]
struct Out {
    #[serde(default)]
    success: bool,
    credential: Option<CredentialData>,
    error: Option<OutErr>,
}

#[derive(Deserialize)]
struct OutErr {
    message: String,
}

fn fetch_with(aac: &OsStr, domain: &str, timeout: u64) -> Result<CredentialData, Failure> {
    let out = Command::new(aac)
        .args([
            "connect",
            "--domain",
            domain,
            "--output",
            "json",
            "--timeout",
            &timeout.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| failure(format!("cannot run aac: {e}")))?;
    let stdout = Zeroizing::new(out.stdout);
    let parsed = serde_json::from_slice::<Out>(&stdout).ok();
    if out.status.success() {
        if let Some(Out {
            success: true,
            credential: Some(c),
            ..
        }) = parsed
        {
            return Ok(c);
        }
    }
    let code = out.status.code().unwrap_or(1);
    let label = domain
        .split([' ', '|'])
        .next()
        .unwrap_or(domain)
        .to_string();
    let msg = parsed
        .and_then(|o| o.error.map(|e| e.message))
        .unwrap_or_else(|| format!("aac exited with {code}"));
    Err(Failure {
        code: code.clamp(1, 255) as u8,
        message: format!("{label}: {msg}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(pw: &str, user: Option<&str>) -> CredentialData {
        CredentialData {
            username: user.map(String::from),
            password: Some(Zeroizing::new(pw.to_string())),
            totp: None,
            uri: None,
            notes: None,
            credential_id: None,
            domain: None,
        }
    }

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<OsString, OsString> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect()
    }

    #[test]
    fn tails() {
        assert_eq!(tail(Some("pi"), Some("why")), " | pi | why");
        assert_eq!(tail(Some("pi"), None), " | pi | ");
        assert_eq!(tail(None, Some("why")), " | why");
        assert_eq!(tail(None, None), "");
        assert_eq!(tail(Some("a|b"), Some("x\ny")), " | a b | x y");
        assert_eq!(tail(Some(" "), Some("")), "");
    }

    #[test]
    fn domains() {
        let one = vec!["a.com".to_string()];
        assert_eq!(plan_domains(&one, None, ""), (None, vec!["a.com".into()]));
        assert_eq!(
            plan_domains(&one, Some("5m"), " | pi | r"),
            (None, vec!["a.com remember=5m | pi | r".into()])
        );
        let three: Vec<String> = ["a", "b", "c"].map(String::from).to_vec();
        assert_eq!(
            plan_domains(&three, Some("5m"), " | pi | r"),
            (
                Some("batch:a,b,c remember=5m | pi | r".into()),
                vec![
                    "a | pi | r".into(),
                    "b | pi | r".into(),
                    "c | pi | r".into()
                ]
            )
        );
    }

    #[test]
    fn resolves_with_one_fetch_per_item() {
        let mut e = env(&[
            ("U", "bw://db#username"),
            ("P", "bw://db#password"),
            ("URL", "pg://${bw://db#username}:${bw://other}@h"),
            ("PLAIN", "x"),
        ]);
        let mut seen: Vec<String> = Vec::new();
        resolve(&mut e, None, "", &mut |d| {
            seen.push(d.to_string());
            Ok(if d == "db" {
                cred("dbpw", Some("dbu"))
            } else {
                cred("otherpw", None)
            })
        })
        .expect("ok");
        assert_eq!(seen, vec!["batch:db,other", "db", "other"]);
        assert_eq!(e[OsStr::new("U")], "dbu");
        assert_eq!(e[OsStr::new("P")], "dbpw");
        assert_eq!(e[OsStr::new("URL")], "pg://dbu:otherpw@h");
        assert_eq!(e[OsStr::new("PLAIN")], "x");
    }

    #[test]
    fn resolve_failures() {
        let mut e = env(&[("T", "bw://db#totp")]);
        let f = resolve(&mut e, None, "", &mut |_| Ok(cred("p", None))).expect_err("no totp");
        assert_eq!(f.code, 1);
        assert_eq!(f.message, "T: bw://db has no totp");

        let pairs: Vec<(String, String)> = (0..11)
            .map(|i| (format!("V{i}"), format!("bw://h{i}.com")))
            .collect();
        let mut e: BTreeMap<OsString, OsString> =
            pairs.iter().map(|(k, v)| (k.into(), v.into())).collect();
        let mut called = false;
        let f = resolve(&mut e, None, "", &mut |_| {
            called = true;
            Ok(cred("p", None))
        })
        .expect_err("too many");
        assert_eq!(f.message, "at most 10 items per run");
        assert!(!called);

        let mut e = env(&[("A", "x")]);
        resolve(&mut e, None, "", &mut |_| {
            called = true;
            Ok(cred("p", None))
        })
        .expect("ok");
        assert!(!called);
    }

    fn script(name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("aac-touchid-run-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    #[test]
    fn fetches_through_aac() {
        let ok = script(
            "ok",
            r#"echo '{"success":true,"credential":{"password":"pw","credentialId":"i"}}'"#,
        );
        let c = fetch_with(ok.as_os_str(), "x.com", 5).expect("ok");
        assert_eq!(c.password.as_deref().map(String::as_str), Some("pw"));

        let denied = script(
            "denied",
            r#"echo '{"success":false,"error":{"message":"Request denied","code":"credential_not_found"}}'; exit 4"#,
        );
        let f = fetch_with(denied.as_os_str(), "x.com | pi | r", 5).expect_err("denied");
        assert_eq!(f.code, 4);
        assert_eq!(f.message, "x.com: Request denied");

        let junk = script("junk", "echo nope; exit 2");
        let f = fetch_with(junk.as_os_str(), "x.com", 5).expect_err("junk");
        assert_eq!(f.code, 2);
    }
}
