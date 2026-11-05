//! This device's certificate, and what is read from a peer's.
//!
//! Made the way both apps make theirs (android `SslHelper.initialiseCertificate`, kde `sslhelper.cpp`):
//! self-signed, an EC P-256 key, subject and issuer `CN=<device id>, OU=KDE Connect, O=KDE`, valid from a
//! year ago for ten years. **No subjectAltName**: kde checks the peer name against the CN
//! (`setPeerVerifyName(deviceId)`), which a SAN would replace.

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SerialNumber, PKCS_ECDSA_P256_SHA256};
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("could not make the certificate: {0}")]
    Generate(#[from] rcgen::Error),
    #[error("not a certificate: {0}")]
    Parse(String),
    #[error("the certificate has no common name")]
    NoCommonName,
}

/// A device certificate and its private key, both DER. The program keeps them (they are the device's
/// identity to every paired peer) and passes them back on the next start.
#[derive(Clone)]
pub struct DeviceCert {
    pub cert_der: Vec<u8>,
    /// PKCS#8.
    pub key_der: Vec<u8>,
}

impl std::fmt::Debug for DeviceCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCert").field("cert_der", &self.cert_der.len()).finish_non_exhaustive()
    }
}

impl DeviceCert {
    pub fn generate(device_id: &str) -> Result<Self, CertError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, device_id);
        dn.push(DnType::OrganizationalUnitName, "KDE Connect");
        dn.push(DnType::OrganizationName, "KDE");
        params.distinguished_name = dn;
        params.serial_number = Some(SerialNumber::from_slice(&[1]));
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(365);
        params.not_after = now + time::Duration::days(3650);
        let cert = params.self_signed(&key)?;
        Ok(DeviceCert { cert_der: cert.der().to_vec(), key_der: key.serialize_der() })
    }

    /// The device id this certificate was made for. The program makes a new certificate when it no
    /// longer matches the device id or has expired, as android does.
    pub fn device_id(&self) -> Result<String, CertError> {
        common_name(&self.cert_der)
    }
}

fn parse(der: &[u8]) -> Result<X509Certificate<'_>, CertError> {
    X509Certificate::from_der(der).map(|(_, c)| c).map_err(|e| CertError::Parse(e.to_string()))
}

/// The certificate's CN, which both apps require to equal the device id (kde `LanLinkProvider::addLink`).
pub fn common_name(der: &[u8]) -> Result<String, CertError> {
    let c = parse(der)?;
    let cn = c.subject().iter_common_name().next().ok_or(CertError::NoCommonName)?;
    cn.as_str().map(str::to_owned).map_err(|e| CertError::Parse(e.to_string()))
}

/// The SubjectPublicKeyInfo, DER: what the verification key is made from (android `certificate.publicKey.encoded`).
pub fn spki(der: &[u8]) -> Result<Vec<u8>, CertError> {
    Ok(parse(der)?.public_key().raw.to_vec())
}

/// Whether the certificate carries a subjectAltName (ours must not).
pub fn has_san(der: &[u8]) -> Result<bool, CertError> {
    Ok(parse(der)?.subject_alternative_name().map_err(|e| CertError::Parse(e.to_string()))?.is_some())
}
