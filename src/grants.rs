//! Approvals the user gave for later: `remember=` windows and one-shot batches.
//! Keyed on the verified device and the resolved vault item id, never the
//! self-reported agent name. In memory only; cleared on lock and on `forget`.

use std::time::{Duration, Instant};

use ap_client::IdentityFingerprint;

use crate::control::GrantInfo;

pub const BATCH_WINDOW: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Remembered,
    Batch,
}

impl Kind {
    pub fn outcome(self) -> &'static str {
        match self {
            Self::Remembered => "approved (remembered)",
            Self::Batch => "approved (batch)",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Remembered => "remembered",
            Self::Batch => "batch",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Grant {
    pub device: IdentityFingerprint,
    pub device_label: String,
    pub item_id: String,
    /// Display name, for status.
    pub item: String,
    pub kind: Kind,
    pub expires: Instant,
    /// `None` means unlimited until expiry.
    pub uses_left: Option<u32>,
}

#[derive(Default)]
pub struct Grants {
    list: Vec<Grant>,
}

impl Grants {
    pub fn add(&mut self, g: Grant) {
        if let Some(i) = self
            .list
            .iter()
            .position(|e| e.device == g.device && e.item_id == g.item_id)
        {
            let e = &self.list[i];
            if e.kind == Kind::Remembered && e.expires >= g.expires {
                return;
            }
            self.list.remove(i);
        }
        self.list.push(g);
    }

    /// Whether a live remembered grant covers this item, without using it.
    pub fn remembers(&mut self, device: &IdentityFingerprint, item_id: &str, now: Instant) -> bool {
        self.list.retain(|g| g.expires > now);
        self.list
            .iter()
            .any(|g| g.device == *device && g.item_id == item_id && g.kind == Kind::Remembered)
    }

    pub fn take(
        &mut self,
        device: &IdentityFingerprint,
        item_id: &str,
        now: Instant,
    ) -> Option<Kind> {
        self.list.retain(|g| g.expires > now);
        let i = self
            .list
            .iter()
            .position(|g| g.device == *device && g.item_id == item_id)?;
        let kind = self.list[i].kind;
        if let Some(n) = self.list[i].uses_left {
            if n <= 1 {
                self.list.remove(i);
            } else {
                self.list[i].uses_left = Some(n - 1);
            }
        }
        Some(kind)
    }

    pub fn clear(&mut self) -> usize {
        let n = self.list.len();
        self.list.clear();
        n
    }

    pub fn snapshot(&mut self, now: Instant) -> Vec<GrantInfo> {
        self.list.retain(|g| g.expires > now);
        self.list
            .iter()
            .map(|g| GrantInfo {
                device: g.device_label.clone(),
                item: g.item.clone(),
                kind: g.kind.label().to_string(),
                expires_in: g.expires.saturating_duration_since(now).as_secs(),
                uses_left: g.uses_left,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ap_proxy_protocol::IdentityKeyPair;

    fn fp() -> IdentityFingerprint {
        IdentityKeyPair::generate().identity().fingerprint()
    }

    fn grant(device: IdentityFingerprint, id: &str, kind: Kind, secs: u64) -> Grant {
        Grant {
            device,
            device_label: "nuc".into(),
            item_id: id.into(),
            item: "GitHub".into(),
            kind,
            expires: Instant::now() + Duration::from_secs(secs),
            uses_left: (kind == Kind::Batch).then_some(1),
        }
    }

    #[test]
    fn one_shot_is_taken_once() {
        let d = fp();
        let mut g = Grants::default();
        g.add(grant(d, "a", Kind::Batch, 120));
        assert_eq!(g.take(&d, "a", Instant::now()), Some(Kind::Batch));
        assert_eq!(g.take(&d, "a", Instant::now()), None);
    }

    #[test]
    fn remembered_repeats_until_expiry() {
        let d = fp();
        let mut g = Grants::default();
        let gr = grant(d, "a", Kind::Remembered, 60);
        let expires = gr.expires;
        g.add(gr);
        assert_eq!(g.take(&d, "a", Instant::now()), Some(Kind::Remembered));
        assert_eq!(g.take(&d, "a", Instant::now()), Some(Kind::Remembered));
        assert_eq!(g.take(&d, "a", expires), None);
    }

    #[test]
    fn remembers_only_live_remembered_grants() {
        let d = fp();
        let mut g = Grants::default();
        g.add(grant(d, "a", Kind::Remembered, 60));
        g.add(grant(d, "b", Kind::Batch, 60));
        assert!(g.remembers(&d, "a", Instant::now()));
        assert!(g.remembers(&d, "a", Instant::now()), "not consumed");
        assert!(!g.remembers(&d, "b", Instant::now()));
        assert!(!g.remembers(&fp(), "a", Instant::now()));
        assert!(!g.remembers(&d, "a", Instant::now() + Duration::from_secs(61)));
    }

    #[test]
    fn other_device_or_item_gets_nothing() {
        let (d, e) = (fp(), fp());
        let mut g = Grants::default();
        g.add(grant(d, "a", Kind::Remembered, 60));
        assert_eq!(g.take(&e, "a", Instant::now()), None);
        assert_eq!(g.take(&d, "b", Instant::now()), None);
    }

    #[test]
    fn add_keeps_longer_remembered_and_replaces_shorter() {
        let d = fp();
        let mut g = Grants::default();
        g.add(grant(d, "a", Kind::Remembered, 600));
        g.add(grant(d, "a", Kind::Batch, 120));
        assert_eq!(g.take(&d, "a", Instant::now()), Some(Kind::Remembered));
        assert_eq!(g.take(&d, "a", Instant::now()), Some(Kind::Remembered));

        let mut g = Grants::default();
        g.add(grant(d, "a", Kind::Remembered, 60));
        g.add(grant(d, "a", Kind::Remembered, 600));
        let snap = g.snapshot(Instant::now());
        assert_eq!(snap.len(), 1);
        assert!(snap[0].expires_in > 60);
    }

    #[test]
    fn clear_counts_and_snapshot_drops_expired() {
        let d = fp();
        let mut g = Grants::default();
        g.add(grant(d, "a", Kind::Batch, 120));
        g.add(grant(d, "b", Kind::Remembered, 0));
        let snap = g.snapshot(Instant::now() + Duration::from_millis(1));
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].kind, "batch");
        assert_eq!(snap[0].uses_left, Some(1));
        assert!(snap[0].expires_in >= 118);
        assert_eq!(g.clear(), 1);
        assert_eq!(g.clear(), 0);
    }
}
