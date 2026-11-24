//! Masking of secret values in a command's output: the value itself and its
//! base64, percent-encoded and JSON-escaped forms, also when it is split
//! across reads. A safety net for accidents, not a sandbox.

use zeroize::{Zeroize, Zeroizing};

const MIN_LEN: usize = 6;

fn b64(data: &[u8], alphabet: &[u8; 64], pad: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        let chars = chunk.len() + 1;
        for i in 0..4 {
            if i < chars {
                out.push(alphabet[((n >> (18 - 6 * i)) & 63) as usize]);
            } else if pad {
                out.push(b'=');
            }
        }
    }
    out
}

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn percent(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b);
        } else {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        }
    }
    out
}

fn json(value: &str) -> Vec<u8> {
    let quoted = serde_json::to_string(value).unwrap_or_default();
    quoted
        .strip_prefix('"')
        .and_then(|q| q.strip_suffix('"'))
        .unwrap_or_default()
        .as_bytes()
        .to_vec()
}

/// The forms a value may appear in, at least [`MIN_LEN`] bytes each.
pub fn variants(value: &str) -> Vec<Vec<u8>> {
    let raw = value.as_bytes();
    let mut all = vec![
        raw.to_vec(),
        b64(raw, STD, true),
        b64(raw, STD, false),
        b64(raw, URL, false),
        percent(value),
        json(value),
    ];
    all.retain(|v| v.len() >= MIN_LEN);
    all.sort();
    all.dedup();
    all
}

pub struct Masker {
    pats: Vec<(Zeroizing<Vec<u8>>, Vec<u8>)>,
    keep: usize,
    buf: Vec<u8>,
    /// How many values were replaced.
    pub count: usize,
}

impl Masker {
    pub fn new(secrets: &[(String, Zeroizing<String>)]) -> Self {
        let mut pats: Vec<(Zeroizing<Vec<u8>>, Vec<u8>)> = Vec::new();
        for (name, value) in secrets {
            if value.len() < MIN_LEN {
                continue;
            }
            for v in variants(value) {
                pats.push((Zeroizing::new(v), format!("<masked:{name}>").into_bytes()));
            }
        }
        pats.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
        let keep = pats.first().map_or(0, |(p, _)| p.len() - 1);
        Self {
            pats,
            keep,
            buf: Vec::new(),
            count: 0,
        }
    }

    fn drain(&mut self, all: bool) -> Vec<u8> {
        let limit = if all {
            self.buf.len()
        } else {
            self.buf.len().saturating_sub(self.keep)
        };
        let mut out = Vec::with_capacity(limit);
        let mut i = 0;
        while i < limit {
            let rest = &self.buf[i..];
            if let Some((p, r)) = self.pats.iter().find(|(p, _)| rest.starts_with(p)) {
                out.extend_from_slice(r);
                i += p.len();
                self.count += 1;
            } else {
                out.push(self.buf[i]);
                i += 1;
            }
        }
        self.buf.drain(..i);
        out
    }

    /// Feed output; returns what is safe to write now.
    pub fn push(&mut self, data: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(data);
        self.drain(false)
    }

    /// The end of the output: everything still held back.
    pub fn finish(&mut self) -> Vec<u8> {
        self.drain(true)
    }
}

impl Drop for Masker {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masker(pairs: &[(&str, &str)]) -> Masker {
        let v: Vec<(String, Zeroizing<String>)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), Zeroizing::new((*v).to_string())))
            .collect();
        Masker::new(&v)
    }

    fn run(m: &mut Masker, chunks: &[&[u8]]) -> String {
        let mut out = Vec::new();
        for c in chunks {
            out.extend(m.push(c));
        }
        out.extend(m.finish());
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn variants_cover_encodings() {
        let v: Vec<String> = variants("s3cr3t/val+ue")
            .into_iter()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .collect();
        assert!(v.contains(&"s3cr3t/val+ue".to_string()));
        assert!(v.contains(&"czNjcjN0L3ZhbCt1ZQ==".to_string()));
        assert!(v.contains(&"czNjcjN0L3ZhbCt1ZQ".to_string()));
        assert!(v.contains(&"s3cr3t%2Fval%2Bue".to_string()));
        let url: Vec<&String> = v
            .iter()
            .filter(|s| s.contains('-') || s.contains('_'))
            .collect();
        assert!(
            url.is_empty(),
            "this value has no url-safe difference: {url:?}"
        );
        assert!(variants("abc").is_empty());
        assert!(
            variants("a\"b\\cdefg")
                .iter()
                .any(|b| b == br#"a\"b\\cdefg"#)
        );
    }

    #[test]
    fn masks_across_chunks() {
        let mut m = masker(&[("K", "s3cr3t/val+ue")]);
        let out = run(&mut m, &[b"x s3cr", b"3t/val+ue y"]);
        assert_eq!(out, "x <masked:K> y");
        assert_eq!(m.count, 1);
    }

    #[test]
    fn masks_base64_form() {
        let mut m = masker(&[("K", "supersecret1")]);
        let out = run(&mut m, &[b"c3VwZXJzZWNyZXQx and supersecret1\n"]);
        assert_eq!(out, "<masked:K> and <masked:K>\n");
        assert_eq!(m.count, 2);
    }

    #[test]
    fn longest_pattern_wins() {
        let mut m = masker(&[("A", "abcdef"), ("B", "abcdefgh")]);
        assert_eq!(run(&mut m, &[b"abcdefgh"]), "<masked:B>");
        assert_eq!(m.count, 1);
    }

    #[test]
    fn short_values_and_clean_output_pass() {
        let mut m = masker(&[("K", "abc")]);
        assert_eq!(run(&mut m, &[b"abc abc"]), "abc abc");
        assert_eq!(m.count, 0);
    }
}
