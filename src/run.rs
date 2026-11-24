//! `aac-touchid run`: fill `bw://` references in a command's environment.
//!
//! Sends one `batch:` request when several items are needed (one Touch ID
//! sheet), then reads each item with stock `aac connect --output json`, and
//! `exec`s the command. Secrets only ever live in that process's environment.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, ExitCode, ExitStatus, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};

use ap_client::CredentialData;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::grants::same_field;
use crate::intent::{self, Target};
use crate::mask::Masker;
use crate::refs::{self, Part};

pub struct Args {
    pub env_flags: Vec<String>,
    pub dry_run: bool,
    pub no_mask: bool,
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
    apply_env_flags(&mut env, &args.env_flags)?;
    let agent = args
        .agent
        .clone()
        .or_else(|| std::env::var("AAC_AGENT").ok());
    let tail = tail(agent.as_deref(), args.reason.as_deref());
    if args.dry_run {
        let report = dry_run_report(&env, args.remember.as_deref(), &tail)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
        std::process::exit(0);
    }
    let aac = std::env::var_os("AAC_TOUCHID_AAC").unwrap_or_else(|| "aac".into());
    let timeout = args.timeout;
    let secrets = resolve(&mut env, args.remember.as_deref(), &tail, &mut |d| {
        fetch_with(&aac, d, timeout)
    })
    .map_err(|f| explain(&aac, f))?;
    let Some((cmd, rest)) = args.command.split_first() else {
        return Err(failure("no command given"));
    };
    if !args.no_mask && !secrets.is_empty() {
        return match run_masked(
            cmd,
            rest,
            &env,
            &secrets,
            Box::new(std::io::stdout()),
            Box::new(std::io::stderr()),
        ) {
            Ok((status, count)) => {
                if count > 0 {
                    eprintln!("aac-touchid: masked {count} secret value(s) in the output");
                }
                let code = status
                    .code()
                    .or_else(|| status.signal().map(|s| 128 + s))
                    .unwrap_or(1);
                std::process::exit(code.clamp(0, 255));
            }
            Err(e) => Err(spawn_failure(cmd, &e)),
        };
    }
    let err = Command::new(cmd).args(rest).env_clear().envs(&env).exec();
    Err(spawn_failure(cmd, &err))
}

fn spawn_failure(cmd: &str, err: &std::io::Error) -> Failure {
    Failure {
        code: if err.kind() == std::io::ErrorKind::NotFound {
            127
        } else {
            126
        },
        message: format!("cannot run {cmd}: {err}"),
    }
}

/// Apply `--env NAME=VALUE` flags over the environment and env files.
fn apply_env_flags(
    env: &mut BTreeMap<OsString, OsString>,
    flags: &[String],
) -> Result<(), Failure> {
    for f in flags {
        match f.split_once('=') {
            Some((k, v)) if !k.is_empty() => {
                env.insert(k.into(), v.into());
            }
            _ => return Err(failure("--env needs NAME=VALUE")),
        }
    }
    Ok(())
}

/// What `--dry-run` prints: the requests that would be sent and the
/// variables that hold references.
fn dry_run_report(
    env: &BTreeMap<OsString, OsString>,
    remember: Option<&str>,
    tail: &str,
) -> Result<serde_json::Value, Failure> {
    let (parsed, targets) = plan(env)?;
    let mut requests: Vec<String> = Vec::new();
    if !targets.is_empty() {
        let (batch, reads) = plan_domains(&targets, remember, tail);
        requests.extend(batch);
        requests.extend(reads);
    }
    let mut variables: Vec<String> = parsed
        .iter()
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();
    variables.sort();
    Ok(serde_json::json!({ "requests": requests, "variables": variables }))
}

/// On a denial (`aac` exit 4), ask the Mac why and say so, with advice not
/// to repeat the request.
fn explain(aac: &OsStr, f: Failure) -> Failure {
    if f.code != 4 {
        return f;
    }
    let why = fetch_with(aac, "why:", 30).ok().and_then(|c| c.domain);
    let message = match why {
        Some(w) => format!(
            "{}\naac-touchid: the Mac says: {w}\naac-touchid: do not repeat this request; if you cannot fix the reason, ask the user.",
            f.message
        ),
        None => format!(
            "{}\naac-touchid: could not ask the Mac why (aac-touchid status there shows it)",
            f.message
        ),
    };
    Failure { message, ..f }
}

static CHILD: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward(sig: libc::c_int) {
    let pid = CHILD.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: kill(2) is async-signal-safe.
        unsafe { libc::kill(pid, sig) };
    }
}

extern "C" fn ignore(_sig: libc::c_int) {}

/// Copy a stream through a masker, flushing as it goes.
fn pump(
    mut from: impl Read,
    mut to: Box<dyn Write + Send>,
    secrets: &[(String, Zeroizing<String>)],
) -> usize {
    let mut m = Masker::new(secrets);
    let mut buf = Zeroizing::new(vec![0u8; 8192]);
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let out = Zeroizing::new(m.push(&buf[..n]));
                if to.write_all(&out).is_err() {
                    break;
                }
                let _ = to.flush();
            }
        }
    }
    let rest = Zeroizing::new(m.finish());
    let _ = to.write_all(&rest);
    let _ = to.flush();
    m.count
}

/// Run the command with its output masked. Returns its status and how many
/// values were replaced.
fn run_masked(
    cmd: &str,
    args: &[String],
    env: &BTreeMap<OsString, OsString>,
    secrets: &[(String, Zeroizing<String>)],
    out: Box<dyn Write + Send>,
    err: Box<dyn Write + Send>,
) -> std::io::Result<(ExitStatus, usize)> {
    let mut child = Command::new(cmd)
        .args(args)
        .env_clear()
        .envs(env)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    CHILD.store(child.id() as i32, Ordering::SeqCst);
    // SAFETY: handlers only call async-signal-safe functions. SIGINT is
    // not ignored (the child would inherit that): the terminal sends it to
    // the child too.
    unsafe {
        libc::signal(libc::SIGTERM, forward as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, forward as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, ignore as *const () as libc::sighandler_t);
    }
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let count = std::thread::scope(|scope| {
        let a = stdout.map(|s| scope.spawn(move || pump(s, out, secrets)));
        let b = stderr.map(|s| scope.spawn(move || pump(s, err, secrets)));
        a.and_then(|h| h.join().ok()).unwrap_or(0) + b.and_then(|h| h.join().ok()).unwrap_or(0)
    });
    let status = child.wait()?;
    CHILD.store(0, Ordering::SeqCst);
    Ok((status, count))
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

/// Whether two references fetch the same thing: the same item, and the same
/// custom field (or none).
fn same_target(a: &Target, b: &Target) -> bool {
    a.item == b.item && same_field(a.field.as_deref(), b.field.as_deref())
}

/// ` field=NAME`, or nothing.
fn field_option(t: &Target) -> String {
    t.field
        .as_ref()
        .map_or_else(String::new, |f| format!(" field={f}"))
}

/// The batch request (when two or more targets) and the per-target reads.
fn plan_domains(
    targets: &[Target],
    remember: Option<&str>,
    tail: &str,
) -> (Option<String>, Vec<String>) {
    let rem = remember.map_or_else(String::new, |r| format!(" remember={r}"));
    if let [one] = targets {
        return (
            None,
            vec![format!("{}{}{rem}{tail}", one.item, field_option(one))],
        );
    }
    let labels: Vec<String> = targets.iter().map(Target::label).collect();
    (
        Some(format!("batch:{}{rem}{tail}", labels.join(","))),
        targets
            .iter()
            .map(|t| format!("{}{}{tail}", t.item, field_option(t)))
            .collect(),
    )
}

type Fetch<'a> = dyn FnMut(&str) -> Result<CredentialData, Failure> + 'a;

type Parsed = Vec<(OsString, Vec<Part>)>;

/// The variables that hold `bw://` references, and the distinct items they need.
fn plan(env: &BTreeMap<OsString, OsString>) -> Result<(Parsed, Vec<Target>), Failure> {
    let mut parsed: Parsed = Vec::new();
    let mut targets: Vec<Target> = Vec::new();
    for (key, value) in env.iter() {
        let Some(v) = value.to_str() else { continue };
        let name = key.to_string_lossy();
        if let Some(parts) = refs::parse_value(v).map_err(|e| failure(format!("{name}: {e}")))? {
            for p in &parts {
                if let Part::Ref(r) = p {
                    let t = r.target();
                    if !targets.iter().any(|x| same_target(x, &t)) {
                        targets.push(t);
                    }
                }
            }
            parsed.push((key.clone(), parts));
        }
    }
    if targets.len() > intent::MAX_BATCH {
        return Err(failure("at most 10 items per run"));
    }
    Ok((parsed, targets))
}

/// Fill the references. Returns `(variable, value)` for each secret value
/// (passwords and custom fields) that went into the environment.
fn resolve(
    env: &mut BTreeMap<OsString, OsString>,
    remember: Option<&str>,
    tail: &str,
    fetch: &mut Fetch<'_>,
) -> Result<Vec<(String, Zeroizing<String>)>, Failure> {
    let (parsed, targets) = plan(env)?;
    let mut secrets: Vec<(String, Zeroizing<String>)> = Vec::new();
    if targets.is_empty() {
        return Ok(secrets);
    }
    let (batch, reads) = plan_domains(&targets, remember, tail);
    if let Some(b) = batch {
        fetch(&b)?;
    }
    let mut creds: Vec<CredentialData> = Vec::new();
    for domain in reads {
        creds.push(fetch(&domain)?);
    }
    for (key, parts) in parsed {
        let name = key.to_string_lossy().into_owned();
        let mut out = String::new();
        for p in &parts {
            match p {
                Part::Text(t) => out.push_str(t),
                Part::Ref(r) => {
                    let t = r.target();
                    let value = targets
                        .iter()
                        .position(|x| same_target(x, &t))
                        .and_then(|i| creds.get(i))
                        .and_then(|c| r.field.get(c))
                        .ok_or_else(|| {
                            failure(format!("{name}: bw://{} has no {}", r.item, r.field.name()))
                        })?;
                    if matches!(r.field, refs::Field::Password | refs::Field::Custom(_))
                        && !secrets.iter().any(|(_, v)| v.as_str() == value)
                    {
                        secrets.push((name.clone(), Zeroizing::new(value.to_string())));
                    }
                    out.push_str(value);
                }
            }
        }
        env.insert(key, out.into());
    }
    Ok(secrets)
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
        let t = |item: &str, field: Option<&str>| Target {
            item: item.into(),
            field: field.map(String::from),
        };
        let one = vec![t("a.com", None)];
        assert_eq!(plan_domains(&one, None, ""), (None, vec!["a.com".into()]));
        assert_eq!(
            plan_domains(&one, Some("5m"), " | pi | r"),
            (None, vec!["a.com remember=5m | pi | r".into()])
        );
        let keyed = vec![t("a.com", Some("K"))];
        assert_eq!(
            plan_domains(&keyed, Some("5m"), " | pi | r"),
            (None, vec!["a.com field=K remember=5m | pi | r".into()])
        );
        let mixed = vec![t("a", None), t("b", Some("K"))];
        assert_eq!(
            plan_domains(&mixed, Some("5m"), " | pi | r"),
            (
                Some("batch:a,b#field:K remember=5m | pi | r".into()),
                vec!["a | pi | r".into(), "b field=K | pi | r".into()]
            )
        );
        let three: Vec<Target> = ["a", "b", "c"].map(|i| t(i, None)).to_vec();
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
    fn resolves_fields() {
        let mut e = env(&[
            ("U", "bw://db#username"),
            ("K", "bw://db#field:TOKEN"),
            ("K2", "bw://db#field:token"),
        ]);
        let mut seen: Vec<String> = Vec::new();
        resolve(&mut e, None, "", &mut |d| {
            seen.push(d.to_string());
            Ok(if d == "db field=TOKEN" {
                cred("tok", None)
            } else {
                cred("dbpw", Some("dbu"))
            })
        })
        .expect("ok");
        assert_eq!(
            seen,
            vec!["batch:db#field:TOKEN,db", "db field=TOKEN", "db"]
        );
        assert_eq!(e[OsStr::new("U")], "dbu");
        assert_eq!(e[OsStr::new("K")], "tok");
        assert_eq!(e[OsStr::new("K2")], "tok");
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

    #[test]
    fn env_flags() {
        let mut e = env(&[("A", "file"), ("C", "keep")]);
        apply_env_flags(&mut e, &["A=1".into(), "B=bw://x".into()]).expect("ok");
        assert_eq!(e[OsStr::new("A")], "1");
        assert_eq!(e[OsStr::new("B")], "bw://x");
        assert_eq!(e[OsStr::new("C")], "keep");
        for bad in ["nope", "=x"] {
            let f = apply_env_flags(&mut e, &[bad.into()]).expect_err("bad");
            assert_eq!(f.message, "--env needs NAME=VALUE");
        }
    }

    #[test]
    fn resolve_returns_secrets() {
        let mut e = env(&[
            ("U", "bw://db#username"),
            ("P", "bw://db#password"),
            ("K", "bw://db#field:TOKEN"),
        ]);
        let secrets = resolve(&mut e, None, "", &mut |d| {
            Ok(if d.contains("field=TOKEN") {
                cred("tok-value", None)
            } else {
                cred("dbpw-value", Some("dbu"))
            })
        })
        .expect("ok");
        let values: Vec<&str> = secrets.iter().map(|(_, v)| v.as_str()).collect();
        assert!(values.contains(&"dbpw-value") && values.contains(&"tok-value"));
        assert!(!values.contains(&"dbu"));
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn dry_run_report_lists_requests() {
        let e = env(&[("T", "bw://github.com"), ("PLAIN", "x")]);
        let r = dry_run_report(&e, None, "").expect("ok");
        assert_eq!(
            r,
            serde_json::json!({"requests": ["github.com"], "variables": ["T"]})
        );
        let e = env(&[("A", "bw://a.com"), ("B", "bw://b.com")]);
        let r = dry_run_report(&e, Some("5m"), " | pi | r").expect("ok");
        assert_eq!(r["requests"][0], "batch:a.com,b.com remember=5m | pi | r");
        assert_eq!(r["variables"], serde_json::json!(["A", "B"]));
    }

    #[test]
    fn explains_denials() {
        let aac = script(
            "why",
            r#"case "$*" in *why:*) echo '{"success":true,"credential":{"domain":"github.com: denied, 5 s ago"}}';; *) echo '{"success":false,"error":{"message":"Request denied"}}'; exit 4;; esac"#,
        );
        let f = fetch_with(aac.as_os_str(), "github.com", 5).expect_err("denied");
        let f = explain(aac.as_os_str(), f);
        assert_eq!(f.code, 4);
        assert!(
            f.message.contains("the Mac says: github.com: denied"),
            "{}",
            f.message
        );
        assert!(f.message.contains("do not repeat"));
        let other = explain(
            aac.as_os_str(),
            Failure {
                code: 2,
                message: "x".into(),
            },
        );
        assert_eq!(other.message, "x");
    }

    #[test]
    fn masked_run() {
        use std::sync::{Arc, Mutex};
        struct Sink(Arc<Mutex<Vec<u8>>>);
        impl Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("lock").extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let sh = script("echo-k", r#"echo "$K"; printf %s "$K" | base64; exit 3"#);
        let e = env(&[("K", "supersecret1"), ("PATH", "/usr/bin:/bin")]);
        let out = Arc::new(Mutex::new(Vec::new()));
        let err = Arc::new(Mutex::new(Vec::new()));
        let secrets = vec![("K".to_string(), Zeroizing::new("supersecret1".to_string()))];
        let (status, count) = run_masked(
            sh.to_str().expect("utf8"),
            &[],
            &e,
            &secrets,
            Box::new(Sink(out.clone())),
            Box::new(Sink(err.clone())),
        )
        .expect("run");
        let text = String::from_utf8(out.lock().expect("lock").clone()).expect("utf8");
        assert_eq!(text, "<masked:K>\n<masked:K>\n");
        assert!(!text.contains("supersecret1"));
        assert_eq!(status.code(), Some(3));
        assert_eq!(count, 2);
    }
}
