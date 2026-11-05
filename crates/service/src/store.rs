//! What the service keeps on disk, in the folder the program gives it: this device's identity and the
//! paired devices. Two small JSON files, each written whole to a temporary file and renamed over the old.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use kdeconnect_link::DeviceCert;
use serde::{Deserialize, Serialize};

const IDENTITY: &str = "kdeconnect-identity.json";
const TRUSTED: &str = "kdeconnect-trusted.json";

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    device_id: String,
    cert: String,
    key: String,
}

/// A paired device as remembered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Trusted {
    pub name: String,
    pub device_type: String,
    /// The pinned certificate, base64 DER.
    pub cert: String,
    /// The last address it was linked from, tried again at start (android `TrustedDevices`, kde "remembered IPs").
    #[serde(default)]
    pub last_address: Option<String>,
}

impl Trusted {
    pub fn cert_der(&self) -> Option<Vec<u8>> {
        B64.decode(&self.cert).ok()
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// This device's identity: read from `dir`, or made and written there the first time. A certificate whose CN
/// is not the device id is replaced (android `SslHelper.initialiseCertificate` does the same, and also
/// forgets every paired device, since none of them would accept the new certificate).
pub fn load_identity(dir: &Path) -> io::Result<(String, DeviceCert, bool)> {
    let path = dir.join(IDENTITY);
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(f) = serde_json::from_slice::<IdentityFile>(&bytes) {
            if let (Ok(cert_der), Ok(key_der)) = (B64.decode(&f.cert), B64.decode(&f.key)) {
                let cert = DeviceCert { cert_der, key_der };
                if cert.device_id().ok().as_deref() == Some(f.device_id.as_str()) {
                    return Ok((f.device_id, cert, false));
                }
            }
        }
    }
    let device_id = kdeconnect_proto::identity::new_device_id();
    let cert = DeviceCert::generate(&device_id).map_err(io::Error::other)?;
    std::fs::create_dir_all(dir)?;
    let f = IdentityFile { device_id: device_id.clone(), cert: B64.encode(&cert.cert_der), key: B64.encode(&cert.key_der) };
    write_atomic(&path, &serde_json::to_vec_pretty(&f)?)?;
    Ok((device_id, cert, true))
}

pub struct TrustStore {
    path: PathBuf,
    pub devices: BTreeMap<String, Trusted>,
}

impl TrustStore {
    pub fn load(dir: &Path, forget_all: bool) -> TrustStore {
        let path = dir.join(TRUSTED);
        let devices = if forget_all {
            BTreeMap::new()
        } else {
            std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
        };
        TrustStore { path, devices }
    }

    pub fn save(&self) -> io::Result<()> {
        write_atomic(&self.path, &serde_json::to_vec_pretty(&self.devices)?)
    }

    pub fn pin(&mut self, id: &str, name: &str, device_type: &str, cert_der: &[u8], address: Option<String>) -> io::Result<()> {
        self.devices.insert(
            id.to_owned(),
            Trusted { name: name.to_owned(), device_type: device_type.to_owned(), cert: B64.encode(cert_der), last_address: address },
        );
        self.save()
    }

    pub fn forget(&mut self, id: &str) -> io::Result<()> {
        if self.devices.remove(id).is_some() {
            self.save()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_kept_and_trust_round_trips() {
        let dir = std::env::temp_dir().join(format!("kdc-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (id, cert, fresh) = load_identity(&dir).unwrap();
        assert!(fresh);
        let (id2, cert2, fresh2) = load_identity(&dir).unwrap();
        assert!(!fresh2);
        assert_eq!(id, id2);
        assert_eq!(cert.cert_der, cert2.cert_der);

        let mut t = TrustStore::load(&dir, false);
        t.pin("peer", "Phone", "phone", &[1, 2, 3], Some("192.168.1.2".into())).unwrap();
        let t2 = TrustStore::load(&dir, false);
        assert_eq!(t2.devices["peer"].cert_der(), Some(vec![1, 2, 3]));
        assert!(TrustStore::load(&dir, true).devices.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
