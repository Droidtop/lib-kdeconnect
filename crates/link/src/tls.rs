//! TLS for links and payloads (README, "TLS").
//!
//! - Versions 1.2 and 1.3: kdeconnect-android pins its context to TLS 1.2 (`SslHelper.createSslContext`).
//! - Both sides present a certificate. The TLS server requires one from the client, because pairing needs
//!   the peer's certificate (android asks for it with `wantClientAuth` before pairing, `needClientAuth`
//!   after).
//! - A peer that is not paired may present any certificate; it is recorded and pinned at pairing. A paired
//!   peer must present exactly the pinned one, byte for byte.
//! - The handshake's signatures are always checked, with the peer certificate's own key.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig, SignatureScheme};

use crate::cert::DeviceCert;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Accepts the certificate that is pinned, or any certificate when nothing is.
#[derive(Debug)]
struct Pinned {
    pin: Option<Vec<u8>>,
    algs: WebPkiSupportedAlgorithms,
}

impl Pinned {
    fn check(&self, end_entity: &CertificateDer<'_>) -> Result<(), Error> {
        match &self.pin {
            Some(pin) if pin.as_slice() != end_entity.as_ref() => {
                Err(Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure))
            }
            _ => Ok(()),
        }
    }
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.check(end_entity).map(|_| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

impl ClientCertVerifier for Pinned {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.check(end_entity).map(|_| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

fn identity(me: &DeviceCert) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    (vec![CertificateDer::from(me.cert_der.clone())], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(me.key_der.clone())))
}

/// The TLS server side. `pin` is the peer's certificate when it is paired.
pub fn server_config(me: &DeviceCert, pin: Option<Vec<u8>>) -> Result<Arc<ServerConfig>, Error> {
    let p = provider();
    let verifier = Arc::new(Pinned { pin, algs: p.signature_verification_algorithms });
    let (chain, key) = identity(me);
    let cfg = ServerConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)?;
    Ok(Arc::new(cfg))
}

/// The TLS client side. `pin` is the peer's certificate when it is paired.
pub fn client_config(me: &DeviceCert, pin: Option<Vec<u8>>) -> Result<Arc<ClientConfig>, Error> {
    client_config_with(me, pin, &[&rustls::version::TLS13, &rustls::version::TLS12])
}

fn client_config_with(
    me: &DeviceCert,
    pin: Option<Vec<u8>>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<Arc<ClientConfig>, Error> {
    let p = provider();
    let verifier = Arc::new(Pinned { pin, algs: p.signature_verification_algorithms });
    let (chain, key) = identity(me);
    let cfg = ClientConfig::builder_with_provider(p)
        .with_protocol_versions(versions)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(chain, key)?;
    Ok(Arc::new(cfg))
}

/// The server name sent by the TLS client. Nothing checks it (the certificate is pinned instead); kde sets
/// the device id as the peer name, which a DNS name cannot always hold, so a fixed name is sent.
pub fn server_name() -> ServerName<'static> {
    ServerName::try_from("kdeconnect").expect("a valid DNS name")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{ClientConnection, ServerConnection, StreamOwned};
    use std::net::{TcpListener, TcpStream};

    /// kdeconnect-android offers TLS 1.2 only: the server side here must take it, with client certificates
    /// both ways.
    #[test]
    fn tls12_only_peer_handshakes() {
        let server_cert = DeviceCert::generate("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let client_cert = DeviceCert::generate("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let sc = server_config(&server_cert, None).unwrap();
        let expected_client = client_cert.cert_der.clone();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut s = StreamOwned::new(ServerConnection::new(sc).unwrap(), sock);
            while s.conn.is_handshaking() {
                s.conn.complete_io(&mut s.sock).unwrap();
            }
            assert_eq!(s.conn.peer_certificates().unwrap()[0].as_ref(), expected_client.as_slice());
            s.conn.protocol_version()
        });
        let cc = client_config_with(&client_cert, Some(server_cert.cert_der.clone()), &[&rustls::version::TLS12]).unwrap();
        let mut c = StreamOwned::new(ClientConnection::new(cc, server_name()).unwrap(), TcpStream::connect(addr).unwrap());
        while c.conn.is_handshaking() {
            c.conn.complete_io(&mut c.sock).unwrap();
        }
        assert_eq!(c.conn.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_2));
        assert_eq!(server.join().unwrap(), Some(rustls::ProtocolVersion::TLSv1_2));
    }
}
