//! What an agent asks for in the item part of `--domain` (or `--id`).
//!
//! Stock `aac` 0.11 sends only free text, so two writes ride in it, before
//! the `| agent | reason` fields:
//!
//! - `new:<name> [user=<u>] [url=<full url>] [length=12-128] [symbols=no]`
//!   creates a login with a generated password.
//! - `totp:<item> secret=<base32>` or `totp:<item> uri=otpauth://totp/...`
//!   stores a 2FA seed on a login.
//!
//! Anything else is a read. Parsing is pure. Errors are fixed strings that
//! never echo the request, which may hold a seed.

use std::fmt;

use zeroize::Zeroizing;

use crate::bitwarden::host_of;

pub const MIN_LENGTH: u32 = 12;
pub const MAX_LENGTH: u32 = 128;
pub const DEFAULT_LENGTH: u32 = 24;
const MAX_NAME: usize = 64;
const MAX_ITEM: usize = 128;
const MAX_USER: usize = 128;
const MAX_URL: usize = 2048;
const MIN_SECRET: usize = 16;
const MAX_SECRET: usize = 128;

#[derive(Debug, PartialEq, Eq)]
pub enum Intent {
    /// A normal read, unchanged.
    Read,
    Create(NewLogin),
    AddTotp(AddTotp),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLogin {
    pub name: String,
    pub username: Option<String>,
    pub uri: Option<String>,
    pub length: u32,
    pub symbols: bool,
}

#[derive(PartialEq, Eq)]
pub struct AddTotp {
    /// One word: a domain, an item name without spaces, or an item id.
    pub item: String,
    /// What goes into the login's TOTP field: a normalized base32 secret, or
    /// an `otpauth://totp/` URI with its secret normalized.
    pub seed: Zeroizing<String>,
}

impl fmt::Debug for AddTotp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddTotp")
            .field("item", &self.item)
            .field("seed", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    MissingName,
    BadName,
    MissingItem,
    BadItem,
    UnexpectedText,
    UnknownOption,
    DuplicateOption,
    BadUser,
    BadUrl,
    BadLength,
    BadSymbols,
    MissingSeed,
    DuplicateSeed,
    BadSecret,
    BadOtpauth,
    Hotp,
    OtpauthWithoutSecret,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingName => "new: needs a name",
            Self::BadName => "name must be 1-64 letters, digits, spaces or . - _ @ & + '",
            Self::MissingItem => "totp: needs an item",
            Self::BadItem => "item must be one word of at most 128 characters",
            Self::UnexpectedText => "unexpected text after the options",
            Self::UnknownOption => "unknown option",
            Self::DuplicateOption => "option given twice",
            Self::BadUser => "user must be at most 128 printable characters",
            Self::BadUrl => "url must be a full http(s) URL",
            Self::BadLength => "length must be 12-128",
            Self::BadSymbols => "symbols must be yes or no",
            Self::MissingSeed => "totp: needs secret= or uri=",
            Self::DuplicateSeed => "more than one seed given",
            Self::BadSecret => "secret must be base32 (A-Z, 2-7), 16-128 characters",
            Self::BadOtpauth => "uri must be otpauth://totp/...",
            Self::Hotp => "HOTP (counter-based) seeds are not supported",
            Self::OtpauthWithoutSecret => "otpauth uri has no secret",
        })
    }
}

pub fn parse(what: &str) -> Result<Intent, ParseError> {
    let s = what.trim();
    if let Some(rest) = strip_prefix_ci(s, "new:") {
        parse_new(rest).map(Intent::Create)
    } else if let Some(rest) = strip_prefix_ci(s, "totp:") {
        parse_totp(rest).map(Intent::AddTotp)
    } else {
        Ok(Intent::Read)
    }
}

/// A request with anything after `totp:<item>` (up to the first `|`)
/// removed, safe to log.
pub fn redact(raw: &str) -> String {
    let lead = raw.len() - raw.trim_start().len();
    let s = &raw[lead..];
    let Some(rest) = strip_prefix_ci(s, "totp:") else {
        return raw.to_string();
    };
    let (head, tail) = rest.find('|').map_or((rest, ""), |i| rest.split_at(i));
    let item = head
        .split_whitespace()
        .next()
        .filter(|w| !w.contains('='))
        .unwrap_or_default();
    let dropped = head.split_whitespace().count() > usize::from(!item.is_empty());
    let mut out = format!("{}{}", &s[..5], item);
    if dropped {
        out.push_str(if item.is_empty() { "[redacted]" } else { " [redacted]" });
    }
    if !tail.is_empty() {
        out.push(' ');
        out.push_str(tail);
    }
    out
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    s.get(..prefix.len())
        .filter(|p| p.eq_ignore_ascii_case(prefix))
        .map(|_| &s[prefix.len()..])
}

/// Leading words without `=`, then `key=value` options.
fn split_words(rest: &str) -> Result<(Vec<&str>, Vec<(&str, &str)>), ParseError> {
    let mut words = Vec::new();
    let mut options = Vec::new();
    for token in rest.split_whitespace() {
        match token.split_once('=') {
            Some((k, v)) => options.push((k, v)),
            None if options.is_empty() => words.push(token),
            None => return Err(ParseError::UnexpectedText),
        }
    }
    Ok((words, options))
}

fn parse_new(rest: &str) -> Result<NewLogin, ParseError> {
    let (words, options) = split_words(rest)?;
    if words.is_empty() {
        return Err(ParseError::MissingName);
    }
    let name = words.join(" ");
    if name.len() > MAX_NAME
        || !name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '-' | '_' | '@' | '&' | '+' | '\'')
        })
    {
        return Err(ParseError::BadName);
    }
    let mut username = None;
    let mut url = None;
    let mut length = None;
    let mut symbols = None;
    for (key, value) in options {
        let slot_taken = match key.to_ascii_lowercase().as_str() {
            "user" => {
                if value.is_empty()
                    || value.len() > MAX_USER
                    || value.chars().any(char::is_control)
                {
                    return Err(ParseError::BadUser);
                }
                username.replace(value.to_string()).is_some()
            }
            "url" => {
                let scheme_ok = strip_prefix_ci(value, "https://")
                    .or_else(|| strip_prefix_ci(value, "http://"))
                    .is_some();
                if !scheme_ok
                    || value.len() > MAX_URL
                    || value.chars().any(char::is_control)
                    || host_of(value).is_none()
                {
                    return Err(ParseError::BadUrl);
                }
                url.replace(value.to_string()).is_some()
            }
            "length" => {
                let n: u32 = value.parse().map_err(|_| ParseError::BadLength)?;
                if !(MIN_LENGTH..=MAX_LENGTH).contains(&n) {
                    return Err(ParseError::BadLength);
                }
                length.replace(n).is_some()
            }
            "symbols" => {
                let on = match value.to_ascii_lowercase().as_str() {
                    "yes" => true,
                    "no" => false,
                    _ => return Err(ParseError::BadSymbols),
                };
                symbols.replace(on).is_some()
            }
            _ => return Err(ParseError::UnknownOption),
        };
        if slot_taken {
            return Err(ParseError::DuplicateOption);
        }
    }
    let uri = url.or_else(|| looks_like_host(&name).then(|| format!("https://{}", name.to_ascii_lowercase())));
    Ok(NewLogin {
        name,
        username,
        uri,
        length: length.unwrap_or(DEFAULT_LENGTH),
        symbols: symbols.unwrap_or(true),
    })
}

/// `github.com`, `api.example.co.uk`: dotted labels with an alphabetic TLD.
fn looks_like_host(name: &str) -> bool {
    let labels: Vec<&str> = name.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
        && labels
            .last()
            .is_some_and(|t| t.len() >= 2 && t.chars().all(|c| c.is_ascii_alphabetic()))
}

fn parse_totp(rest: &str) -> Result<AddTotp, ParseError> {
    let (words, options) = split_words(rest)?;
    let item = match words.as_slice() {
        [] => return Err(ParseError::MissingItem),
        [item] => *item,
        _ => return Err(ParseError::BadItem),
    };
    if item.len() > MAX_ITEM || item.chars().any(char::is_control) {
        return Err(ParseError::BadItem);
    }
    let mut seed: Option<Zeroizing<String>> = None;
    for (key, value) in options {
        let parsed = match key.to_ascii_lowercase().as_str() {
            "secret" => normalize_base32(value).ok_or(ParseError::BadSecret)?,
            "uri" => parse_otpauth(value)?,
            _ => return Err(ParseError::UnknownOption),
        };
        if seed.replace(parsed).is_some() {
            return Err(ParseError::DuplicateSeed);
        }
    }
    Ok(AddTotp {
        item: item.to_string(),
        seed: seed.ok_or(ParseError::MissingSeed)?,
    })
}

/// Uppercase, drop `=` padding and `-` grouping, then require A-Z2-7 only,
/// 16-128 characters.
fn normalize_base32(s: &str) -> Option<Zeroizing<String>> {
    let out = Zeroizing::new(
        s.chars()
            .filter(|c| !matches!(c, '=' | '-'))
            .map(|c| c.to_ascii_uppercase())
            .collect::<String>(),
    );
    (out.len() >= MIN_SECRET
        && out.len() <= MAX_SECRET
        && out.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')))
    .then_some(out)
}

/// `otpauth://totp/<label>?secret=...&...`, rebuilt with its secret
/// normalized and every other parameter kept.
fn parse_otpauth(uri: &str) -> Result<Zeroizing<String>, ParseError> {
    if uri.len() > MAX_URL || uri.chars().any(char::is_control) {
        return Err(ParseError::BadOtpauth);
    }
    let rest = strip_prefix_ci(uri, "otpauth://").ok_or(ParseError::BadOtpauth)?;
    let (kind, rest) = rest.split_once('/').ok_or(ParseError::BadOtpauth)?;
    if kind.eq_ignore_ascii_case("hotp") {
        return Err(ParseError::Hotp);
    }
    if !kind.eq_ignore_ascii_case("totp") {
        return Err(ParseError::BadOtpauth);
    }
    let rest = rest.split_once('#').map_or(rest, |(r, _)| r);
    let (label, query) = rest
        .split_once('?')
        .ok_or(ParseError::OtpauthWithoutSecret)?;
    let mut secret: Option<Zeroizing<String>> = None;
    let mut params: Vec<&str> = Vec::new();
    for param in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = param.split_once('=').unwrap_or((param, ""));
        if k.eq_ignore_ascii_case("secret") {
            let decoded = pct_decode(v).ok_or(ParseError::BadSecret)?;
            let normalized = normalize_base32(&decoded).ok_or(ParseError::BadSecret)?;
            if secret.replace(normalized).is_some() {
                return Err(ParseError::DuplicateSeed);
            }
        } else {
            params.push(param);
        }
    }
    let secret = secret.ok_or(ParseError::OtpauthWithoutSecret)?;
    let mut out = Zeroizing::new(format!("otpauth://totp/{label}?secret="));
    out.push_str(&secret);
    for p in params {
        out.push('&');
        out.push_str(p);
    }
    Ok(out)
}

fn pct_decode(s: &str) -> Option<Zeroizing<String>> {
    let bytes = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out.to_vec()).ok().map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "JBSWY3DPEHPK3PXP";

    fn new(s: &str) -> NewLogin {
        match parse(s) {
            Ok(Intent::Create(n)) => n,
            other => panic!("unexpected {other:?}"),
        }
    }

    fn totp(s: &str) -> AddTotp {
        match parse(s) {
            Ok(Intent::AddTotp(t)) => t,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn reads_are_unchanged() {
        for s in ["github.com", "GitHub", "1f0c-uuid", "news.example.com", "totpal.com", ""] {
            assert_eq!(parse(s), Ok(Intent::Read), "{s}");
        }
    }

    #[test]
    fn new_with_defaults() {
        assert_eq!(
            new("new:Acme"),
            NewLogin {
                name: "Acme".into(),
                username: None,
                uri: None,
                length: DEFAULT_LENGTH,
                symbols: true,
            }
        );
        assert_eq!(
            new(" NEW: example.com ").uri.as_deref(),
            Some("https://example.com")
        );
        assert_eq!(
            new("new:Api.Example.co.uk").uri.as_deref(),
            Some("https://api.example.co.uk")
        );
        assert_eq!(new("new:Acme Corp").name, "Acme Corp");
        assert_eq!(new("new:Acme Corp").uri, None);
        assert_eq!(new("new:Acme\n  Corp").name, "Acme Corp");
        assert_eq!(new("new:v1.2").uri, None, "numeric TLD is not a host");
    }

    #[test]
    fn new_with_options() {
        assert_eq!(
            new("new:Acme user=me@x.com url=https://acme.io/login length=32 symbols=no"),
            NewLogin {
                name: "Acme".into(),
                username: Some("me@x.com".into()),
                uri: Some("https://acme.io/login".into()),
                length: 32,
                symbols: false,
            }
        );
        assert_eq!(
            new("new:example.com url=https://login.example.com").uri.as_deref(),
            Some("https://login.example.com"),
            "url wins over the name"
        );
        assert_eq!(new("new:x length=12").length, 12);
        assert_eq!(new("new:x length=128").length, 128);
        assert!(new("new:x symbols=yes").symbols);
    }

    #[test]
    fn new_rejections() {
        use ParseError::*;
        let cases = [
            ("new:", MissingName),
            ("new:  user=me", MissingName),
            ("new:a\u{202e}b", BadName),
            (&format!("new:{}", "a".repeat(65)), BadName),
            ("new:x length=11", BadLength),
            ("new:x length=129", BadLength),
            ("new:x length=abc", BadLength),
            ("new:x symbols=maybe", BadSymbols),
            ("new:x url=ftp://x.com", BadUrl),
            ("new:x url=x.com", BadUrl),
            ("new:x url=https://", BadUrl),
            ("new:x user=", BadUser),
            ("new:x user=a user=b", DuplicateOption),
            ("new:x length=20 length=30", DuplicateOption),
            ("new:x password=hunter2", UnknownOption),
            ("new:x user=me stray", UnexpectedText),
        ];
        for (s, e) in cases {
            assert_eq!(parse(s), Err(e), "{s:?}");
        }
    }

    #[test]
    fn totp_secret() {
        let t = totp(&format!("totp:github.com secret={SEED}"));
        assert_eq!(t.item, "github.com");
        assert_eq!(t.seed.as_str(), SEED);
        assert_eq!(
            totp("TOTP:x secret=jbsw-y3dp-ehpk-3pxp====").seed.as_str(),
            SEED
        );
    }

    #[test]
    fn totp_otpauth() {
        let t = totp(
            "totp:x uri=otpauth://totp/Acme:me%40x.com?secret=jbswy3dpehpk3pxp&issuer=Acme&digits=8",
        );
        assert_eq!(
            t.seed.as_str(),
            format!("otpauth://totp/Acme:me%40x.com?secret={SEED}&issuer=Acme&digits=8")
        );
        assert_eq!(
            totp(&format!("totp:x uri=OTPAUTH://TOTP/a?issuer=A&secret={SEED}%3D%3D")).seed.as_str(),
            format!("otpauth://totp/a?secret={SEED}&issuer=A")
        );
    }

    #[test]
    fn totp_rejections() {
        use ParseError::*;
        let cases = [
            ("totp:".to_string(), MissingItem),
            (format!("totp: secret={SEED}"), MissingItem),
            ("totp:x".to_string(), MissingSeed),
            (format!("totp:x {SEED}"), BadItem),
            (format!("totp:a b secret={SEED}"), BadItem),
            ("totp:x secret=JBSWY3DP".to_string(), BadSecret),
            ("totp:x secret=JBSWY3DPEHPK3PX1".to_string(), BadSecret),
            (format!("totp:x secret={}", "A".repeat(129)), BadSecret),
            (format!("totp:x secret={SEED} secret={SEED}"), DuplicateSeed),
            (
                format!("totp:x secret={SEED} uri=otpauth://totp/a?secret={SEED}"),
                DuplicateSeed,
            ),
            (
                format!("totp:x uri=otpauth://totp/a?secret={SEED}&secret={SEED}"),
                DuplicateSeed,
            ),
            (format!("totp:x uri=otpauth://hotp/a?secret={SEED}&counter=1"), Hotp),
            ("totp:x uri=otpauth://totp/a?issuer=A".to_string(), OtpauthWithoutSecret),
            ("totp:x uri=otpauth://totp/a".to_string(), OtpauthWithoutSecret),
            (format!("totp:x uri=https://x.com/?secret={SEED}"), BadOtpauth),
            (format!("totp:x uri=otpauth://totp/a?secret={SEED}%G1"), BadSecret),
            (format!("totp:x seed={SEED}"), UnknownOption),
            (format!("totp:x secret={SEED} trailing"), UnexpectedText),
        ];
        for (s, e) in cases {
            assert_eq!(parse(&s).map(|_| ()), Err(e), "{s:?}");
        }
    }

    #[test]
    fn errors_never_echo_the_request() {
        let secretish = "QWERTYQWERTYQWERTY";
        for s in [
            format!("totp:x secret={secretish} {secretish}"),
            format!("totp:x {secretish}=1 secret={SEED}"),
            format!("totp:x uri=otpauth://totp/{secretish}"),
            format!("new:x {secretish}=y"),
            format!("totp:x secret={secretish}9"),
        ] {
            let e = parse(&s).expect_err(&s).to_string();
            assert!(!e.contains(secretish), "{e}");
            assert!(!e.contains("QWERTY"), "{e}");
        }
    }

    #[test]
    fn redaction() {
        assert_eq!(redact("github.com | pi | why"), "github.com | pi | why");
        assert_eq!(redact("new:x user=me | pi | why"), "new:x user=me | pi | why");
        assert_eq!(
            redact(&format!("totp:github.com secret={SEED} | pi | enroll")),
            "totp:github.com [redacted] | pi | enroll"
        );
        assert_eq!(
            redact(&format!(" TOTP:x uri=otpauth://totp/a?secret={SEED}")),
            "TOTP:x [redacted]"
        );
        assert_eq!(redact(&format!("totp:secret={SEED}|a")), "totp:[redacted] |a");
        assert_eq!(redact("totp:x"), "totp:x");
        assert_eq!(redact(&format!("totp:x {SEED}")), "totp:x [redacted]");
        for s in [
            format!("totp:x secret={SEED}"),
            format!("totp:x uri=otpauth://totp/a?secret={SEED} | a | b"),
            format!("totp: secret={SEED}"),
        ] {
            assert!(!redact(&s).contains(SEED), "{s}");
        }
    }

    #[test]
    fn debug_hides_the_seed() {
        let t = totp(&format!("totp:x secret={SEED}"));
        assert!(!format!("{t:?}").contains(SEED));
    }
}
