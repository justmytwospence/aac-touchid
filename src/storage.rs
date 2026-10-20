//! File-backed identity and connection stores.
//!
//! Adapted from Bitwarden Agent Access `ap-cli` (`crates/ap-cli/src/storage`,
//! v0.11.0, Apache-2.0). Differences: everything lives in one private state
//! directory (0700, files 0600), and connections can be listed and removed
//! from outside the running client.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ap_client::{ClientError, ConnectionInfo, ConnectionStore, ConnectionUpdate, IdentityProvider};
use ap_noise::{MultiDeviceTransport, PersistentTransportState};
use ap_proxy_protocol::{IdentityFingerprint, IdentityKeyPair};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// The private state directory: `~/Library/Application Support/aac-touchid`
/// (or `$AAC_TOUCHID_STATE_DIR`).
pub fn state_dir() -> std::io::Result<PathBuf> {
    let dir = match std::env::var_os("AAC_TOUCHID_STATE_DIR") {
        Some(d) => PathBuf::from(d),
        None => dirs::data_dir()
            .ok_or_else(|| std::io::Error::other("no data directory"))?
            .join("aac-touchid"),
    };
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

/// Write a file atomically with mode 0600.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// The listener's long-lived identity keypair, stored as COSE bytes.
pub struct FileIdentity {
    keypair: IdentityKeyPair,
}

impl FileIdentity {
    pub fn load_or_generate(dir: &Path) -> Result<Self, ClientError> {
        let path = dir.join("identity.key");
        let keypair = if path.exists() {
            let bytes = fs::read(&path)
                .map_err(|e| ClientError::IdentityStorageFailed(format!("read identity: {e}")))?;
            IdentityKeyPair::from_cose(&bytes).map_err(|_| {
                ClientError::IdentityStorageFailed("identity file is corrupt".to_string())
            })?
        } else {
            let keypair = IdentityKeyPair::generate();
            write_private(&path, &keypair.to_cose())
                .map_err(|e| ClientError::IdentityStorageFailed(format!("write identity: {e}")))?;
            keypair
        };
        Ok(Self { keypair })
    }
}

#[async_trait]
impl IdentityProvider for FileIdentity {
    async fn identity(&self) -> IdentityKeyPair {
        self.keypair.clone()
    }
}

// ---------------------------------------------------------------------------
// Connections (paired devices)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectionRecord {
    remote_fingerprint: IdentityFingerprint,
    cached_at: u64,
    last_connected_at: u64,
    #[serde(default)]
    transport_state: Option<Vec<u8>>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ConnectionFile {
    connections: Vec<ConnectionRecord>,
}

fn record_to_info(record: &ConnectionRecord) -> Result<ConnectionInfo, ClientError> {
    let transport_state = match &record.transport_state {
        Some(bytes) => {
            Some(PersistentTransportState::from_bytes(bytes).map(MultiDeviceTransport::from)?)
        }
        None => None,
    };
    Ok(ConnectionInfo {
        fingerprint: record.remote_fingerprint,
        name: record.name.clone(),
        cached_at: record.cached_at,
        last_connected_at: record.last_connected_at,
        transport_state,
    })
}

fn info_to_record(info: &ConnectionInfo) -> Result<ConnectionRecord, ClientError> {
    let transport_state =
        match &info.transport_state {
            Some(t) => Some(PersistentTransportState::from(t).to_bytes().map_err(|e| {
                ClientError::NoiseProtocol(format!("serialize transport state: {e}"))
            })?),
            None => None,
        };
    Ok(ConnectionRecord {
        remote_fingerprint: info.fingerprint,
        cached_at: info.cached_at,
        last_connected_at: info.last_connected_at,
        transport_state,
        name: info.name.clone(),
    })
}

/// A paired device as shown by `status`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
    pub name: String,
    pub fingerprint: String,
    pub paired_at: u64,
    pub last_connected_at: u64,
}

/// Human label for a fingerprint: the paired name, else a short hex prefix.
pub fn short_hex(fp: &IdentityFingerprint) -> String {
    hex::encode(fp.0).chars().take(12).collect()
}

pub struct FileConnections {
    path: PathBuf,
    data: ConnectionFile,
}

impl FileConnections {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("connections.json")
    }

    pub fn load(dir: &Path) -> Result<Self, ClientError> {
        let path = Self::path(dir);
        let data = if path.exists() {
            let text = fs::read_to_string(&path)
                .map_err(|e| ClientError::ConnectionCache(format!("read connections: {e}")))?;
            serde_json::from_str(&text)
                .map_err(|e| ClientError::ConnectionCache(format!("parse connections: {e}")))?
        } else {
            ConnectionFile::default()
        };
        Ok(Self { path, data })
    }

    fn persist(&self) -> Result<(), ClientError> {
        let json = serde_json::to_vec_pretty(&self.data)
            .map_err(|e| ClientError::ConnectionCache(format!("serialize connections: {e}")))?;
        write_private(&self.path, &json)
            .map_err(|e| ClientError::ConnectionCache(format!("write connections: {e}")))
    }

    pub fn devices(&self) -> Vec<Device> {
        self.data
            .connections
            .iter()
            .map(|r| Device {
                name: r
                    .name
                    .clone()
                    .unwrap_or_else(|| short_hex(&r.remote_fingerprint)),
                fingerprint: hex::encode(r.remote_fingerprint.0),
                paired_at: r.cached_at,
                last_connected_at: r.last_connected_at,
            })
            .collect()
    }

    pub fn label(&self, fp: &IdentityFingerprint) -> Option<String> {
        self.data
            .connections
            .iter()
            .find(|r| r.remote_fingerprint == *fp)
            .map(|r| r.name.clone().unwrap_or_else(|| short_hex(fp)))
    }

    /// Remove devices whose name or fingerprint prefix matches. Returns how many.
    pub fn remove(&mut self, name_or_prefix: &str) -> Result<usize, ClientError> {
        let before = self.data.connections.len();
        self.data.connections.retain(|r| {
            let hexfp = hex::encode(r.remote_fingerprint.0);
            r.name.as_deref() != Some(name_or_prefix)
                && !(name_or_prefix.len() >= 6 && hexfp.starts_with(name_or_prefix))
        });
        let removed = before - self.data.connections.len();
        if removed > 0 {
            self.persist()?;
        }
        Ok(removed)
    }
}

#[async_trait]
impl ConnectionStore for FileConnections {
    async fn get(&self, fingerprint: &IdentityFingerprint) -> Option<ConnectionInfo> {
        self.data
            .connections
            .iter()
            .find(|r| r.remote_fingerprint == *fingerprint)
            .and_then(|r| record_to_info(r).ok())
    }

    async fn save(&mut self, connection: ConnectionInfo) -> Result<(), ClientError> {
        let record = info_to_record(&connection)?;
        match self
            .data
            .connections
            .iter_mut()
            .find(|r| r.remote_fingerprint == connection.fingerprint)
        {
            Some(existing) => *existing = record,
            None => self.data.connections.push(record),
        }
        self.persist()
    }

    async fn update(&mut self, update: ConnectionUpdate) -> Result<(), ClientError> {
        let record = self
            .data
            .connections
            .iter_mut()
            .find(|r| r.remote_fingerprint == update.fingerprint)
            .ok_or_else(|| ClientError::ConnectionCache("connection not found".to_string()))?;
        record.last_connected_at = update.last_connected_at;
        self.persist()
    }

    async fn list(&self) -> Vec<ConnectionInfo> {
        self.data
            .connections
            .iter()
            .filter_map(|r| record_to_info(r).ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aac-touchid-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("mkdir");
        d
    }

    #[tokio::test]
    async fn save_list_remove_round_trip() {
        let dir = tmpdir("conn");
        let mut store = FileConnections::load(&dir).expect("load");
        let fp = IdentityKeyPair::generate().identity().fingerprint();
        store
            .save(ConnectionInfo {
                fingerprint: fp,
                name: Some("nuc".to_string()),
                cached_at: 1,
                last_connected_at: 2,
                transport_state: None,
            })
            .await
            .expect("save");
        let reloaded = FileConnections::load(&dir).expect("reload");
        assert_eq!(reloaded.devices().len(), 1);
        assert_eq!(reloaded.label(&fp).as_deref(), Some("nuc"));
        let mode = fs::metadata(FileConnections::path(&dir))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        let mut reloaded = reloaded;
        assert_eq!(reloaded.remove("other").expect("remove"), 0);
        assert_eq!(reloaded.remove("nuc").expect("remove"), 1);
        assert!(
            FileConnections::load(&dir)
                .expect("load")
                .devices()
                .is_empty()
        );
    }

    #[test]
    fn identity_is_stable_and_private() {
        let dir = tmpdir("id");
        let a = FileIdentity::load_or_generate(&dir).expect("gen");
        let b = FileIdentity::load_or_generate(&dir).expect("load");
        assert_eq!(
            a.keypair.identity().fingerprint(),
            b.keypair.identity().fingerprint()
        );
        let mode = fs::metadata(dir.join("identity.key"))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
