//! What an agent asks for in the item part of `--domain` (or `--id`).
//!
//! Stock `aac` 0.11 sends only free text, so two writes ride in it, before
//! the `| agent | reason` fields:
//!
//! - `new:<name> [user=<u>] [url=<full url>] [words=3-20]` creates a login
//!   with a generated six-word passphrase (`Violet-Shrug0-Broken-...`), or with
//!   `[length=12-128] [symbols=no]` a random password.
//! - `save:<name> [user=<u>] [url=<full url>] password64=<base64>` stores a
//!   password the agent already has as a new login.
//! - `rotate:<item> [user=<u>] [words=3-20] [length=12-128] [symbols=no]`
//!   replaces the password of an existing login with a generated one, and
//!   with `user=` sets its username too.
//! - `totp:<item> secret=<base32>` or `totp:<item> uri=otpauth://totp/...`
//!   stores a 2FA seed on a login.
//!
//! - `why:` asks, without a sheet, why this device's recent requests were
//!   refused.
//! - `<item> remember=15m` is a read that also asks to release the same item
//!   again for that long (1m-24h) without another sheet.
//! - `<item> field=<NAME>` reads one custom field of an item (its value
//!   arrives in the password slot); it combines with `remember=`.
//! - `batch:<a>,<b>,... [remember=15m]` approves several items on one sheet;
//!   an entry may be `<item>#field:<NAME>`.
//!
//! Anything else is a read. Parsing is pure. Errors are fixed strings that
//! never echo the request, which may hold a seed.

use std::fmt;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::bitwarden::host_of;

pub const MIN_LENGTH: u32 = 12;
pub const MAX_LENGTH: u32 = 128;
pub const DEFAULT_LENGTH: u32 = 24;
pub const MIN_WORDS: u32 = 3;
pub const MAX_WORDS: u32 = 20;
pub const DEFAULT_WORDS: u32 = 6;
pub const MAX_BATCH: usize = 10;
const MAX_NAME: usize = 64;
const MAX_FIELD: usize = 64;
const MAX_ITEM: usize = 128;
const MAX_USER: usize = 128;
const MAX_URL: usize = 2048;
const MAX_SAVED: usize = 512;
const MAX_B64: usize = 700;
const MIN_SECRET: usize = 16;
const MAX_SECRET: usize = 128;

#[derive(Debug, PartialEq, Eq)]
pub enum Intent {
    /// A read, optionally asking to be remembered.
    Read(Read),
    /// Several reads approved on one sheet.
    Batch(Batch),
    Create(NewLogin),
    AddTotp(AddTotp),
    Rotate(Rotate),
    Save(SaveLogin),
    /// The device's own recent decisions, no sheet.
    Why,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read {
    pub item: String,
    /// One custom field of the item, instead of its login.
    pub field: Option<String>,
    pub remember: Option<Duration>,
}

/// One batch entry: an item, and optionally one of its custom fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub item: String,
    pub field: Option<String>,
}

impl Target {
    /// `item` or `item#field:NAME`, as written in `batch:`.
    pub fn label(&self) -> String {
        match &self.field {
            Some(f) => format!("{}#field:{f}", self.item),
            None => self.item.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub items: Vec<Target>,
    pub remember: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLogin {
    pub name: String,
    pub username: Option<String>,
    pub uri: Option<String>,
    pub secret: Generator,
}

/// How the new login's password is generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Generator {
    /// Capitalized words joined by `-`, one with a digit: `Violet-Shrug0-Broken`.
    Passphrase { words: u32 },
    /// Upper, lower, digits, and symbols unless turned off.
    Password { length: u32, symbols: bool },
}

impl Generator {
    /// For the approval sheet: the format, never the password.
    pub fn describe(&self) -> String {
        match self {
            Self::Passphrase { words } => format!("{words}-word passphrase"),
            Self::Password {
                length,
                symbols: true,
            } => format!("{length}-character password"),
            Self::Password {
                length,
                symbols: false,
            } => format!("{length}-character password without symbols"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotate {
    /// A host, URL, item name or item id, resolved like a read.
    pub item: String,
    /// A username to set on the login in the same write.
    pub username: Option<String>,
    pub secret: Generator,
}

/// A login the agent already has the password for.
#[derive(PartialEq, Eq)]
pub struct SaveLogin {
    pub name: String,
    pub username: Option<String>,
    pub uri: Option<String>,
    pub password: Zeroizing<String>,
}

impl fmt::Debug for SaveLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SaveLogin")
            .field("name", &self.name)
            .field("username", &self.username)
            .field("uri", &self.uri)
            .field("password", &"[redacted]")
            .finish()
    }
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
    BadWords,
    MixedGenerators,
    MissingPassword,
    BadPassword,
    MissingSeed,
    DuplicateSeed,
    BadSecret,
    BadOtpauth,
    Hotp,
    OtpauthWithoutSecret,
    EmptyItem,
    BadRemember,
    BadField,
    EmptyBatch,
    TooManyItems,
    DuplicateItem,
    BadBatch,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingName => "new: needs a name",
            Self::BadName => "name must be 1-64 letters, digits, spaces or . - _ @ & + '",
            Self::MissingItem => "totp: and rotate: need an item",
            Self::BadItem => "item must be one word of at most 128 characters",
            Self::UnexpectedText => "unexpected text after the options",
            Self::UnknownOption => "unknown option",
            Self::DuplicateOption => "option given twice",
            Self::BadUser => "user must be at most 128 printable characters",
            Self::BadUrl => "url must be a full http(s) URL",
            Self::BadLength => "length must be 12-128",
            Self::BadSymbols => "symbols must be yes or no",
            Self::BadWords => "words must be 3-20",
            Self::MixedGenerators => "words= cannot be combined with length= or symbols=",
            Self::MissingPassword => "save: needs password64=",
            Self::BadPassword => {
                "password64 must be base64 of 1-512 bytes of text without control characters"
            }
            Self::MissingSeed => "totp: needs secret= or uri=",
            Self::DuplicateSeed => "more than one seed given",
            Self::BadSecret => "secret must be base32 (A-Z, 2-7), 16-128 characters",
            Self::BadOtpauth => "uri must be otpauth://totp/...",
            Self::Hotp => "HOTP (counter-based) seeds are not supported",
            Self::OtpauthWithoutSecret => "otpauth uri has no secret",
            Self::EmptyItem => "request names no item",
            Self::BadRemember => "remember must be 1m-24h, like 15m or 2h",
            Self::BadField => "field must be 1-64 letters, digits or _ . -",
            Self::EmptyBatch => "batch: needs items",
            Self::TooManyItems => "batch: at most 10 items",
            Self::DuplicateItem => "item listed twice",
            Self::BadBatch => "batch: items are one comma-separated word",
        })
    }
}

pub fn parse(what: &str) -> Result<Intent, ParseError> {
    let s = what.trim();
    if let Some(rest) = strip_prefix_ci(s, "new:") {
        parse_new(rest).map(Intent::Create)
    } else if let Some(rest) = strip_prefix_ci(s, "save:") {
        parse_save(rest).map(Intent::Save)
    } else if let Some(rest) = strip_prefix_ci(s, "totp:") {
        parse_totp(rest).map(Intent::AddTotp)
    } else if let Some(rest) = strip_prefix_ci(s, "rotate:") {
        parse_rotate(rest).map(Intent::Rotate)
    } else if let Some(rest) = strip_prefix_ci(s, "batch:") {
        parse_batch(rest).map(Intent::Batch)
    } else if let Some(rest) = strip_prefix_ci(s, "why:") {
        if rest.trim().is_empty() {
            Ok(Intent::Why)
        } else {
            Err(ParseError::UnexpectedText)
        }
    } else {
        parse_read(what).map(Intent::Read)
    }
}

/// `15m`, `2h`: 1 minute to 24 hours.
pub fn parse_span(v: &str) -> Result<Duration, ParseError> {
    let v = v.to_ascii_lowercase();
    let (digits, per) = if let Some(d) = v.strip_suffix('m') {
        (d, 1u64)
    } else if let Some(d) = v.strip_suffix('h') {
        (d, 60)
    } else {
        return Err(ParseError::BadRemember);
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(ParseError::BadRemember);
    }
    let minutes = digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(per))
        .ok_or(ParseError::BadRemember)?;
    if !(1..=1440).contains(&minutes) {
        return Err(ParseError::BadRemember);
    }
    Ok(Duration::from_secs(minutes * 60))
}

fn is_remember(word: &str) -> bool {
    word.get(..9)
        .is_some_and(|p| p.eq_ignore_ascii_case("remember="))
}

fn is_field(word: &str) -> bool {
    word.get(..6)
        .is_some_and(|p| p.eq_ignore_ascii_case("field="))
}

/// A custom field's name in a request: 1-64 of `A-Z a-z 0-9 _ . -`.
pub fn parse_field(v: &str) -> Result<String, ParseError> {
    if v.is_empty()
        || v.len() > MAX_FIELD
        || !v
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return Err(ParseError::BadField);
    }
    Ok(v.to_string())
}

/// Whether a vault field name is the one a request asked for: a space in the
/// vault's name is written `_` in requests, and case is ignored.
pub fn field_matches(vault_name: &str, wanted: &str) -> bool {
    vault_name
        .trim()
        .replace(' ', "_")
        .eq_ignore_ascii_case(wanted)
}

fn parse_read(what: &str) -> Result<Read, ParseError> {
    let t = what.trim_end();
    let lead = t.trim_start();
    if is_remember(lead) || is_field(lead) {
        return Err(ParseError::EmptyItem);
    }
    let mut head = t;
    let mut remember = None;
    let mut field = None;
    let mut any = false;
    while let Some((rest, last)) = head.rsplit_once(char::is_whitespace) {
        if is_remember(last) {
            if remember.replace(parse_span(&last[9..])?).is_some() {
                return Err(ParseError::DuplicateOption);
            }
        } else if is_field(last) {
            if field.replace(parse_field(&last[6..])?).is_some() {
                return Err(ParseError::DuplicateOption);
            }
        } else {
            break;
        }
        any = true;
        head = rest.trim_end();
    }
    if !any {
        return Ok(Read {
            item: what.to_string(),
            field: None,
            remember: None,
        });
    }
    let item = head.trim();
    if item.is_empty() {
        return Err(ParseError::EmptyItem);
    }
    Ok(Read {
        item: item.to_string(),
        field,
        remember,
    })
}

fn parse_batch(rest: &str) -> Result<Batch, ParseError> {
    let (words, options) = split_words(rest)?;
    let list = match words.as_slice() {
        [] if options
            .iter()
            .any(|(k, _)| !k.eq_ignore_ascii_case("remember")) =>
        {
            return Err(ParseError::BadItem);
        }
        [] => return Err(ParseError::EmptyBatch),
        [one] => *one,
        _ => return Err(ParseError::BadBatch),
    };
    let mut remember = None;
    for (key, value) in options {
        if !key.eq_ignore_ascii_case("remember") {
            return Err(ParseError::UnknownOption);
        }
        if remember.replace(parse_span(value)?).is_some() {
            return Err(ParseError::DuplicateOption);
        }
    }
    let mut items: Vec<Target> = Vec::new();
    for entry in list.split(',') {
        if entry.is_empty() {
            return Err(ParseError::EmptyBatch);
        }
        let (item, field) = match entry.to_ascii_lowercase().find("#field:") {
            Some(i) => (&entry[..i], Some(parse_field(&entry[i + 7..])?)),
            None => (entry, None),
        };
        if item.is_empty()
            || item.len() > MAX_ITEM
            || item.chars().any(char::is_control)
            || item.contains('=')
        {
            return Err(ParseError::BadItem);
        }
        if items.iter().any(|t| {
            t.item.eq_ignore_ascii_case(item)
                && match (&t.field, &field) {
                    (None, None) => true,
                    (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                    _ => false,
                }
        }) {
            return Err(ParseError::DuplicateItem);
        }
        items.push(Target {
            item: item.to_string(),
            field,
        });
    }
    if items.len() > MAX_BATCH {
        return Err(ParseError::TooManyItems);
    }
    Ok(Batch { items, remember })
}

/// A request with anything after `totp:<item>` or `save:<name>` (up to the
/// first `|`) removed, safe to log.
pub fn redact(raw: &str) -> String {
    let lead = raw.len() - raw.trim_start().len();
    let s = &raw[lead..];
    let (prefix, many) = if strip_prefix_ci(s, "totp:").is_some() {
        (&s[..5], false)
    } else if strip_prefix_ci(s, "save:").is_some() {
        // A name may have spaces; everything from the first option on goes.
        (&s[..5], true)
    } else {
        return raw.to_string();
    };
    let rest = &s[5..];
    let (head, tail) = rest.find('|').map_or((rest, ""), |i| rest.split_at(i));
    let words: Vec<&str> = head.split_whitespace().collect();
    let kept: Vec<&str> = words
        .iter()
        .copied()
        .take_while(|w| !w.contains('='))
        .take(if many { usize::MAX } else { 1 })
        .collect();
    let item = kept.join(" ");
    let dropped = words.len() > kept.len();
    let mut out = format!("{prefix}{item}");
    if dropped {
        out.push_str(if item.is_empty() {
            "[redacted]"
        } else {
            " [redacted]"
        });
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

type Options<'a> = Vec<(&'a str, &'a str)>;

/// Leading words without `=`, then `key=value` options.
fn split_words(rest: &str) -> Result<(Vec<&str>, Options<'_>), ParseError> {
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

fn parse_name(words: &[&str]) -> Result<String, ParseError> {
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
    Ok(name)
}

fn parse_user(value: &str) -> Result<String, ParseError> {
    if value.is_empty() || value.len() > MAX_USER || value.chars().any(char::is_control) {
        return Err(ParseError::BadUser);
    }
    Ok(value.to_string())
}

fn parse_url(value: &str) -> Result<String, ParseError> {
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
    Ok(value.to_string())
}

/// `https://<name>` when the name looks like a host.
fn default_uri(name: &str) -> Option<String> {
    looks_like_host(name).then(|| format!("https://{}", name.to_ascii_lowercase()))
}

/// The password generator options: `length=`, `symbols=`, `words=`.
#[derive(Default)]
struct GenOptions {
    length: Option<u32>,
    symbols: Option<bool>,
    words: Option<u32>,
}

impl GenOptions {
    /// Take the option if it is a generator one: `Ok(true)` when it was.
    fn take(&mut self, key: &str, value: &str) -> Result<bool, ParseError> {
        let taken = match key.to_ascii_lowercase().as_str() {
            "length" => {
                let n: u32 = value.parse().map_err(|_| ParseError::BadLength)?;
                if !(MIN_LENGTH..=MAX_LENGTH).contains(&n) {
                    return Err(ParseError::BadLength);
                }
                self.length.replace(n).is_some()
            }
            "words" => {
                let n: u32 = value.parse().map_err(|_| ParseError::BadWords)?;
                if !(MIN_WORDS..=MAX_WORDS).contains(&n) {
                    return Err(ParseError::BadWords);
                }
                self.words.replace(n).is_some()
            }
            "symbols" => {
                let on = match value.to_ascii_lowercase().as_str() {
                    "yes" => true,
                    "no" => false,
                    _ => return Err(ParseError::BadSymbols),
                };
                self.symbols.replace(on).is_some()
            }
            _ => return Ok(false),
        };
        if taken {
            return Err(ParseError::DuplicateOption);
        }
        Ok(true)
    }

    fn finish(self) -> Result<Generator, ParseError> {
        match (self.words, self.length, self.symbols) {
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) => Err(ParseError::MixedGenerators),
            (None, None, None) => Ok(Generator::Passphrase {
                words: DEFAULT_WORDS,
            }),
            (Some(words), _, _) => Ok(Generator::Passphrase { words }),
            (None, length, symbols) => Ok(Generator::Password {
                length: length.unwrap_or(DEFAULT_LENGTH),
                symbols: symbols.unwrap_or(true),
            }),
        }
    }
}

fn parse_new(rest: &str) -> Result<NewLogin, ParseError> {
    let (words, options) = split_words(rest)?;
    let name = parse_name(&words)?;
    let mut username = None;
    let mut url = None;
    let mut generator = GenOptions::default();
    for (key, value) in options {
        let slot_taken = if generator.take(key, value)? {
            false
        } else {
            match key.to_ascii_lowercase().as_str() {
                "user" => username.replace(parse_user(value)?).is_some(),
                "url" => url.replace(parse_url(value)?).is_some(),
                _ => return Err(ParseError::UnknownOption),
            }
        };
        if slot_taken {
            return Err(ParseError::DuplicateOption);
        }
    }
    let uri = url.or_else(|| default_uri(&name));
    Ok(NewLogin {
        name,
        username,
        uri,
        secret: generator.finish()?,
    })
}

fn parse_save(rest: &str) -> Result<SaveLogin, ParseError> {
    let (words, options) = split_words(rest)?;
    let name = parse_name(&words)?;
    let mut username = None;
    let mut url = None;
    let mut password: Option<Zeroizing<String>> = None;
    for (key, value) in options {
        let slot_taken = match key.to_ascii_lowercase().as_str() {
            "user" => username.replace(parse_user(value)?).is_some(),
            "url" => url.replace(parse_url(value)?).is_some(),
            "password64" => password.replace(parse_password64(value)?).is_some(),
            _ => return Err(ParseError::UnknownOption),
        };
        if slot_taken {
            return Err(ParseError::DuplicateOption);
        }
    }
    let uri = url.or_else(|| default_uri(&name));
    Ok(SaveLogin {
        name,
        username,
        uri,
        password: password.ok_or(ParseError::MissingPassword)?,
    })
}

fn parse_password64(value: &str) -> Result<Zeroizing<String>, ParseError> {
    if value.len() > MAX_B64 {
        return Err(ParseError::BadPassword);
    }
    let bytes = decode_base64(value).ok_or(ParseError::BadPassword)?;
    let text = String::from_utf8(bytes.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| ParseError::BadPassword)?;
    if text.is_empty() || text.len() > MAX_SAVED || text.chars().any(char::is_control) {
        return Err(ParseError::BadPassword);
    }
    Ok(text)
}

/// Standard or URL-safe base64, padding optional.
fn decode_base64(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let s = s.trim_end_matches('=');
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() * 3 / 4));
    let mut acc: u32 = 0;
    let mut bits = 0;
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn parse_rotate(rest: &str) -> Result<Rotate, ParseError> {
    let (words, options) = split_words(rest)?;
    let item = match words.as_slice() {
        [] => return Err(ParseError::MissingItem),
        [item] => *item,
        _ => return Err(ParseError::BadItem),
    };
    if item.len() > MAX_ITEM || item.chars().any(char::is_control) {
        return Err(ParseError::BadItem);
    }
    let mut username = None;
    let mut generator = GenOptions::default();
    for (key, value) in options {
        if generator.take(key, value)? {
            continue;
        }
        if !key.eq_ignore_ascii_case("user") {
            return Err(ParseError::UnknownOption);
        }
        if username.replace(parse_user(value)?).is_some() {
            return Err(ParseError::DuplicateOption);
        }
    }
    Ok(Rotate {
        item: item.to_string(),
        username,
        secret: generator.finish()?,
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

    fn rotate(s: &str) -> Rotate {
        match parse(s) {
            Ok(Intent::Rotate(r)) => r,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rotate_defaults_and_options() {
        let r = rotate("rotate:speedtest.example.com");
        assert_eq!(r.item, "speedtest.example.com");
        assert_eq!(r.secret, Generator::Passphrase { words: 6 });
        assert_eq!(
            rotate("rotate:x words=8").secret,
            Generator::Passphrase { words: 8 }
        );
        assert_eq!(
            rotate("rotate:x length=32 symbols=no").secret,
            Generator::Password {
                length: 32,
                symbols: false
            }
        );
        assert_eq!(rotate("ROTATE:x").item, "x");
        assert_eq!(rotate("rotate:x").username, None);
        let r = rotate("rotate:x user=speedtest@example.com words=4");
        assert_eq!(r.username.as_deref(), Some("speedtest@example.com"));
        assert_eq!(r.secret, Generator::Passphrase { words: 4 });
    }

    #[test]
    fn rotate_rejections() {
        use ParseError::*;
        for (input, err) in [
            ("rotate:", MissingItem),
            ("rotate:a b", BadItem),
            ("rotate:x password64=YQ", UnknownOption),
            ("rotate:x url=https://x.com", UnknownOption),
            ("rotate:x user=", BadUser),
            ("rotate:x user=a user=b", DuplicateOption),
            ("rotate:x words=5 length=20", MixedGenerators),
            ("rotate:x words=4 words=5", DuplicateOption),
            ("rotate:x length=5", BadLength),
        ] {
            assert_eq!(parse(input), Err(err), "{input}");
        }
    }

    fn save(s: &str) -> SaveLogin {
        match parse(s) {
            Ok(Intent::Save(v)) => v,
            other => panic!("unexpected {other:?}"),
        }
    }

    // base64 of "hunter2|pipe"
    const PW64: &str = "aHVudGVyMnxwaXBl";

    #[test]
    fn save_decodes() {
        let s = save(&format!(
            "save:Letterboxarr user=admin url=https://lbx.example.com password64={PW64}"
        ));
        assert_eq!(s.name, "Letterboxarr");
        assert_eq!(s.username.as_deref(), Some("admin"));
        assert_eq!(s.uri.as_deref(), Some("https://lbx.example.com"));
        assert_eq!(s.password.as_str(), "hunter2|pipe");
        assert!(!format!("{s:?}").contains("hunter2"));
        // Unpadded, padded and URL-safe forms.
        assert_eq!(save("save:a password64=YWI").password.as_str(), "ab");
        assert_eq!(save("save:a password64=YWI=").password.as_str(), "ab");
        assert_eq!(save("save:a password64=Pz8-").password.as_str(), "??>");
        assert_eq!(save("save:a password64=Pz8+").password.as_str(), "??>");
        let s = save(&format!("save:acme.io password64={PW64}"));
        assert_eq!(s.uri.as_deref(), Some("https://acme.io"));
    }

    #[test]
    fn save_rejections() {
        use ParseError::*;
        let too_big = "QUFB".repeat(171); // 513 bytes
        assert_eq!(too_big.len(), 684);
        for (input, err) in [
            ("save:x".to_string(), MissingPassword),
            ("save:x password64=***".to_string(), BadPassword),
            ("save:x password64=A".to_string(), BadPassword),
            ("save:x password64=YQpi".to_string(), BadPassword), // "a\nb"
            (format!("save:x password64={too_big}"), BadPassword),
            ("save:x password64=".to_string(), BadPassword),
            ("save:x password=x".to_string(), UnknownOption),
            (
                format!("save:x password64={PW64} password64={PW64}"),
                DuplicateOption,
            ),
            (format!("save:x words=5 password64={PW64}"), UnknownOption),
            (format!("save: password64={PW64}"), MissingName),
        ] {
            assert_eq!(parse(&input), Err(err), "{input}");
        }
    }

    #[test]
    fn redact_save() {
        assert_eq!(
            redact("save:Acme Corp user=a password64=SECRET | pi | r"),
            "save:Acme Corp [redacted] | pi | r"
        );
        assert_eq!(redact("save:acme.io"), "save:acme.io");
        assert_eq!(redact("save:password64=SECRET"), "save:[redacted]");
    }

    #[test]
    fn why_parses() {
        assert_eq!(parse("why:"), Ok(Intent::Why));
        assert_eq!(parse(" WHY:  "), Ok(Intent::Why));
        assert_eq!(parse("why: x"), Err(ParseError::UnexpectedText));
    }

    #[test]
    fn reads_are_unchanged() {
        for s in [
            "github.com",
            "GitHub",
            "1f0c-uuid",
            "news.example.com",
            "totpal.com",
            "",
        ] {
            assert_eq!(
                parse(s),
                Ok(Intent::Read(Read {
                    item: s.into(),
                    field: None,
                    remember: None
                })),
                "{s}"
            );
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
                secret: Generator::Passphrase {
                    words: DEFAULT_WORDS
                },
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
                secret: Generator::Password {
                    length: 32,
                    symbols: false
                },
            }
        );
        assert_eq!(
            new("new:example.com url=https://login.example.com")
                .uri
                .as_deref(),
            Some("https://login.example.com"),
            "url wins over the name"
        );
        assert_eq!(
            new("new:x length=12").secret,
            Generator::Password {
                length: 12,
                symbols: true
            }
        );
        assert_eq!(
            new("new:x symbols=no").secret,
            Generator::Password {
                length: DEFAULT_LENGTH,
                symbols: false
            }
        );
        assert_eq!(
            new("new:x words=6").secret,
            Generator::Passphrase { words: 6 }
        );
    }

    #[test]
    fn generator_descriptions() {
        assert_eq!(new("new:x").secret.describe(), "6-word passphrase");
        assert_eq!(
            new("new:x length=32").secret.describe(),
            "32-character password"
        );
        assert_eq!(
            new("new:x symbols=no").secret.describe(),
            "24-character password without symbols"
        );
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
            ("new:x words=2", BadWords),
            ("new:x words=21", BadWords),
            ("new:x words=5 length=20", MixedGenerators),
            ("new:x symbols=no words=5", MixedGenerators),
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
            totp(&format!(
                "totp:x uri=OTPAUTH://TOTP/a?issuer=A&secret={SEED}%3D%3D"
            ))
            .seed
            .as_str(),
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
            (
                format!("totp:x uri=otpauth://hotp/a?secret={SEED}&counter=1"),
                Hotp,
            ),
            (
                "totp:x uri=otpauth://totp/a?issuer=A".to_string(),
                OtpauthWithoutSecret,
            ),
            (
                "totp:x uri=otpauth://totp/a".to_string(),
                OtpauthWithoutSecret,
            ),
            (
                format!("totp:x uri=https://x.com/?secret={SEED}"),
                BadOtpauth,
            ),
            (
                format!("totp:x uri=otpauth://totp/a?secret={SEED}%G1"),
                BadSecret,
            ),
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
            format!("x field={secretish}/"),
        ] {
            let e = parse(&s).expect_err(&s).to_string();
            assert!(!e.contains(secretish), "{e}");
            assert!(!e.contains("QWERTY"), "{e}");
        }
    }

    #[test]
    fn redaction() {
        assert_eq!(redact("github.com | pi | why"), "github.com | pi | why");
        assert_eq!(
            redact("new:x user=me | pi | why"),
            "new:x user=me | pi | why"
        );
        assert_eq!(
            redact(&format!("totp:github.com secret={SEED} | pi | enroll")),
            "totp:github.com [redacted] | pi | enroll"
        );
        assert_eq!(
            redact(&format!(" TOTP:x uri=otpauth://totp/a?secret={SEED}")),
            "TOTP:x [redacted]"
        );
        assert_eq!(
            redact(&format!("totp:secret={SEED}|a")),
            "totp:[redacted] |a"
        );
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

    #[test]
    fn read_remember() {
        let r = |s: &str| parse(s);
        assert_eq!(
            r("github.com remember=15m"),
            Ok(Intent::Read(Read {
                item: "github.com".into(),
                field: None,
                remember: Some(Duration::from_secs(900))
            }))
        );
        assert_eq!(
            r("My Item  REMEMBER=2h"),
            Ok(Intent::Read(Read {
                item: "My Item".into(),
                field: None,
                remember: Some(Duration::from_secs(7200))
            }))
        );
        assert_eq!(r("remember=5m"), Err(ParseError::EmptyItem));
        for bad in [
            "x remember=0m",
            "x remember=25h",
            "x remember=15",
            "x remember=99999999999h",
        ] {
            assert_eq!(r(bad), Err(ParseError::BadRemember), "{bad}");
        }
        assert_eq!(
            r("remember.com"),
            Ok(Intent::Read(Read {
                item: "remember.com".into(),
                field: None,
                remember: None
            }))
        );
    }

    fn t(item: &str) -> Target {
        Target {
            item: item.into(),
            field: None,
        }
    }

    #[test]
    fn read_field() {
        let read = |s: &str| match parse(s) {
            Ok(Intent::Read(r)) => r,
            other => panic!("unexpected {other:?}"),
        };
        let r = read("openai.com field=API_KEY");
        assert_eq!(r.item, "openai.com");
        assert_eq!(r.field.as_deref(), Some("API_KEY"));
        assert_eq!(r.remember, None);
        for s in ["x FIELD=a remember=5m", "x remember=5m field=a"] {
            let r = read(s);
            assert_eq!(r.item, "x", "{s}");
            assert_eq!(r.field.as_deref(), Some("a"), "{s}");
            assert_eq!(r.remember, Some(Duration::from_secs(300)), "{s}");
        }
        assert_eq!(read("My Item field=t").item, "My Item");
        assert_eq!(parse("field=a"), Err(ParseError::EmptyItem));
        assert_eq!(parse("field=a x"), Err(ParseError::EmptyItem));
        assert_eq!(parse("x field="), Err(ParseError::BadField));
        assert_eq!(parse("x field=a/b"), Err(ParseError::BadField));
        assert_eq!(
            parse(&format!("x field={}", "a".repeat(65))),
            Err(ParseError::BadField)
        );
        assert_eq!(
            parse(&format!("x field={}", "a".repeat(64))).map(|_| ()),
            Ok(())
        );
        assert_eq!(parse("x field=a field=b"), Err(ParseError::DuplicateOption));
        assert_eq!(read("fieldwork.com").field, None);
    }

    #[test]
    fn target_labels() {
        assert_eq!(t("a.com").label(), "a.com");
        let f = Target {
            item: "a.com".into(),
            field: Some("K".into()),
        };
        assert_eq!(f.label(), "a.com#field:K");
    }

    #[test]
    fn batch_fields() {
        let Ok(Intent::Batch(b)) = parse("batch:a.com#field:K,a.com") else {
            panic!("not a batch")
        };
        assert_eq!(b.items.len(), 2);
        assert_eq!(b.items[0].field.as_deref(), Some("K"));
        assert_eq!(b.items[1].field, None);
        assert_eq!(
            parse("batch:a.com#FIELD:k,a.com#field:K"),
            Err(ParseError::DuplicateItem)
        );
        assert_eq!(parse("batch:#field:k"), Err(ParseError::BadItem));
        assert_eq!(parse("batch:a.com#field:"), Err(ParseError::BadField));
    }

    #[test]
    fn batch_parse() {
        assert_eq!(
            parse("batch:a.com,b.com"),
            Ok(Intent::Batch(Batch {
                items: vec![t("a.com"), t("b.com")],
                remember: None
            }))
        );
        assert_eq!(
            parse("BATCH:a.com remember=10m"),
            Ok(Intent::Batch(Batch {
                items: vec![t("a.com")],
                remember: Some(Duration::from_secs(600))
            }))
        );
        assert_eq!(parse("batch:"), Err(ParseError::EmptyBatch));
        assert_eq!(parse("batch:a.com,,b.com"), Err(ParseError::EmptyBatch));
        assert_eq!(parse("batch:a.com b.com"), Err(ParseError::BadBatch));
        let many = (0..11).map(|i| format!("h{i}.com")).collect::<Vec<_>>();
        assert_eq!(
            parse(&format!("batch:{}", many.join(","))),
            Err(ParseError::TooManyItems)
        );
        assert_eq!(parse("batch:a.com,A.COM"), Err(ParseError::DuplicateItem));
        assert_eq!(parse("batch:a.com foo=1"), Err(ParseError::UnknownOption));
        assert_eq!(
            parse("batch:a.com remember=5m remember=6m"),
            Err(ParseError::DuplicateOption)
        );
        assert_eq!(parse("batch:a=b"), Err(ParseError::BadItem));
    }
}
