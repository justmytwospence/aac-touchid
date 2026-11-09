//! `bw://ITEM[#FIELD]` references in environment values, and .env files.

use ap_client::CredentialData;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Username,
    Password,
    Totp,
    Uri,
    Domain,
    CredentialId,
}

impl Field {
    pub fn parse(s: &str) -> Option<Field> {
        Some(match s {
            "username" => Self::Username,
            "password" => Self::Password,
            "totp" => Self::Totp,
            "uri" => Self::Uri,
            "domain" => Self::Domain,
            "credential_id" => Self::CredentialId,
            _ => return None,
        })
    }

    pub fn get(self, c: &CredentialData) -> Option<&str> {
        match self {
            Self::Username => c.username.as_deref(),
            Self::Password => c.password.as_deref().map(String::as_str),
            Self::Totp => c.totp.as_deref(),
            Self::Uri => c.uri.as_deref(),
            Self::Domain => c.domain.as_deref(),
            Self::CredentialId => c.credential_id.as_deref(),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Password => "password",
            Self::Totp => "totp",
            Self::Uri => "uri",
            Self::Domain => "domain",
            Self::CredentialId => "credential_id",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ref {
    pub item: String,
    pub field: Field,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    Text(String),
    Ref(Ref),
}

const PREFIX: &str = "bw://";

/// `s` is `bw://ITEM[#FIELD]`.
pub fn parse_ref(s: &str) -> Result<Ref, String> {
    let rest = s.strip_prefix(PREFIX).ok_or("not a bw:// reference")?;
    let (item, field) = match rest.split_once('#') {
        Some((i, f)) => (i, Some(f)),
        None => (rest, None),
    };
    if item.is_empty() {
        return Err("reference names no item".to_string());
    }
    if item.len() > 128
        || item
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "#},|=${".contains(c))
    {
        return Err("bad item in reference".to_string());
    }
    let field = match field {
        None => Field::Password,
        Some("notes") => return Err("notes are never released".to_string()),
        Some(f) => Field::parse(f).ok_or_else(|| {
            format!(
                "unknown field \"{f}\" (use username, password, totp, uri, domain or credential_id)"
            )
        })?,
    };
    Ok(Ref {
        item: item.to_string(),
        field,
    })
}

/// `None` when the value holds no references.
pub fn parse_value(v: &str) -> Result<Option<Vec<Part>>, String> {
    if v.starts_with(PREFIX) {
        return Ok(Some(vec![Part::Ref(parse_ref(v)?)]));
    }
    let open = "${bw://";
    if !v.contains(open) {
        return Ok(None);
    }
    let mut parts = Vec::new();
    let mut rest = v;
    while let Some(i) = rest.find(open) {
        if i > 0 {
            parts.push(Part::Text(rest[..i].to_string()));
        }
        let after = &rest[i + 2..];
        let end = after.find('}').ok_or("unterminated ${bw://")?;
        parts.push(Part::Ref(parse_ref(&after[..end])?));
        rest = &after[end + 1..];
    }
    if !rest.is_empty() {
        parts.push(Part::Text(rest.to_string()));
    }
    Ok(Some(parts))
}

pub fn parse_env_file(name: &str, contents: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for (i, line) in contents.lines().enumerate() {
        let n = i + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("{name}:{n}: invalid line"));
        };
        let key = key.trim();
        let mut chars = key.chars();
        let valid = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(format!("{name}:{n}: invalid line"));
        }
        let mut value = value.trim();
        if value.starts_with('"') || value.starts_with('\'') {
            let q = &value[..1];
            if value.len() < 2 || !value.ends_with(q) {
                return Err(format!("{name}:{n}: unterminated quote"));
            }
            value = &value[1..value.len() - 1];
        }
        out.push((key.to_string(), value.to_string()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(item: &str, field: Field) -> Part {
        Part::Ref(Ref {
            item: item.into(),
            field,
        })
    }

    #[test]
    fn refs() {
        assert_eq!(
            parse_ref("bw://github.com"),
            Ok(Ref {
                item: "github.com".into(),
                field: Field::Password
            })
        );
        assert_eq!(parse_ref("bw://x#totp").map(|r| r.field), Ok(Field::Totp));
        assert_eq!(
            parse_ref("bw://x#credential_id").map(|r| r.field),
            Ok(Field::CredentialId)
        );
        for bad in [
            "bw://x#notes",
            "bw://x#bogus",
            "bw://",
            "bw://a b",
            "bw://x#",
        ] {
            assert!(parse_ref(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn values() {
        assert_eq!(
            parse_value("bw://a#username"),
            Ok(Some(vec![r("a", Field::Username)]))
        );
        let p = parse_value("postgres://${bw://db#username}:${bw://db#password}@h/app")
            .expect("ok")
            .expect("some");
        assert_eq!(
            p,
            vec![
                Part::Text("postgres://".into()),
                r("db", Field::Username),
                Part::Text(":".into()),
                r("db", Field::Password),
                Part::Text("@h/app".into()),
            ]
        );
        assert!(parse_value("a ${bw://x").is_err());
        assert_eq!(parse_value("plain"), Ok(None));
        assert_eq!(parse_value("x bw://y"), Ok(None));
    }

    #[test]
    fn env_files() {
        let f = parse_env_file("f", "# c\n\nexport A=bw://x\nB=\"q v\"\nC='s'\nD=plain=1\n")
            .expect("ok");
        assert_eq!(
            f,
            vec![
                ("A".into(), "bw://x".into()),
                ("B".into(), "q v".into()),
                ("C".into(), "s".into()),
                ("D".into(), "plain=1".into()),
            ]
        );
        let e = parse_env_file("f", "A=1\n\nbad key=SECRETVALUE\n").expect_err("bad");
        assert_eq!(e, "f:3: invalid line");
        assert!(!e.contains("SECRETVALUE"));
        assert!(parse_env_file("f", "A=\"x\n").is_err());
    }
}
