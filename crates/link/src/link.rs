//! One device link: the TCP connection, its TLS, and the packets on it (README, "Connection").
//!
//! The device that heard the other's UDP announcement opens the TCP connection, sends its identity in plain
//! text with `targetDeviceId` and `targetProtocolVersion`, and then acts as the **TLS server**; the device
//! that accepted the TCP connection is the TLS client (android `identityPacketReceived`: "If I'm the TCP
//! server I will be the SSL client and vice-versa"). After the handshake both send their identity again,
//! over TLS; only that one is believed, and it must name the same device and version as the plain one.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use kdeconnect_proto::identity::IdentityError;
use kdeconnect_proto::{Identity, Packet, PacketError, MAX_IDENTITY_PACKET_SIZE, MAX_PACKET_SIZE, PROTOCOL_VERSION};
use rustls::{ClientConnection, ServerConnection, StreamOwned};

use crate::cert::{self, DeviceCert};
use crate::tls;

/// Where the program keeps paired devices' certificates.
pub trait Trust: Send + Sync {
    /// The pinned certificate (DER) of a paired device, or `None` when it is not paired.
    fn pinned(&self, device_id: &str) -> Option<Vec<u8>>;
}

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("network: {0}")]
    Io(#[from] io::Error),
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
    #[error("packet: {0}")]
    Packet(#[from] PacketError),
    #[error("identity: {0}")]
    Identity(#[from] IdentityError),
    #[error("certificate: {0}")]
    Cert(#[from] cert::CertError),
    #[error("refused: {0}")]
    Refused(&'static str),
    #[error("the other device closed the link")]
    Closed,
}

/// How long a handshake may take (kde gives the encrypted identity one second; android times reads out at
/// ten). A slow phone on Wi-Fi gets the longer.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

enum Tls {
    Client(StreamOwned<ClientConnection, TcpStream>),
    Server(StreamOwned<ServerConnection, TcpStream>),
}

impl Tls {
    fn peer_cert(&self) -> Option<Vec<u8>> {
        let certs = match self {
            Tls::Client(s) => s.conn.peer_certificates(),
            Tls::Server(s) => s.conn.peer_certificates(),
        };
        certs.and_then(|c| c.first()).map(|c| c.as_ref().to_vec())
    }

    fn sock(&self) -> &TcpStream {
        match self {
            Tls::Client(s) => &s.sock,
            Tls::Server(s) => &s.sock,
        }
    }

    fn handshake(&mut self) -> Result<(), LinkError> {
        match self {
            Tls::Client(s) => {
                while s.conn.is_handshaking() {
                    s.conn.complete_io(&mut s.sock)?;
                }
            }
            Tls::Server(s) => {
                while s.conn.is_handshaking() {
                    s.conn.complete_io(&mut s.sock)?;
                }
            }
        }
        Ok(())
    }
}

impl Read for Tls {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Tls::Client(s) => s.read(buf),
            Tls::Server(s) => s.read(buf),
        }
    }
}

impl Write for Tls {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Tls::Client(s) => s.write(buf),
            Tls::Server(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Tls::Client(s) => s.flush(),
            Tls::Server(s) => s.flush(),
        }
    }
}

/// An established, encrypted link to one device.
pub struct Link {
    tls: Tls,
    buf: Vec<u8>,
    /// The identity the device sent over TLS.
    pub peer: Identity,
    /// Its certificate (DER), pinned by the program when the device is paired.
    pub peer_cert: Vec<u8>,
    pub peer_addr: SocketAddr,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link").field("peer", &self.peer.device_id).field("peer_addr", &self.peer_addr).finish()
    }
}

/// Reads one line of at most `max` bytes a byte at a time, so nothing after it is read ahead: the TLS
/// handshake follows on the same socket (android `readLineBounded`, for the same reason).
fn read_plain_line(sock: &mut TcpStream, max: usize) -> Result<Vec<u8>, LinkError> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        if sock.read(&mut b)? == 0 {
            return Err(LinkError::Closed);
        }
        if b[0] == b'\n' {
            return Ok(line);
        }
        line.push(b[0]);
        if line.len() > max {
            return Err(PacketError::TooLong(max).into());
        }
    }
}

impl Link {
    /// This device heard `peer`'s announcement from `addr` and connects to it.
    pub fn connect(addr: SocketAddr, me: &Identity, cert: &DeviceCert, peer: &Identity, trust: &dyn Trust) -> Result<Link, LinkError> {
        if peer.protocol_version < PROTOCOL_VERSION {
            return Err(LinkError::Refused("protocol version older than 8"));
        }
        let mut sock = TcpStream::connect_timeout(&addr, HANDSHAKE_TIMEOUT)?;
        sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        sock.set_nodelay(true)?;
        sock.write_all(me.connection_packet(peer).to_line().as_bytes())?;
        let pin = trust.pinned(&peer.device_id);
        let conn = ServerConnection::new(tls::server_config(cert, pin)?)?;
        let tls = Tls::Server(StreamOwned::new(conn, sock));
        Link::secure(tls, me, peer, addr)
    }

    /// Another device connected to this one's TCP listener after hearing its announcement.
    pub fn accept(mut sock: TcpStream, me: &Identity, cert: &DeviceCert, trust: &dyn Trust) -> Result<Link, LinkError> {
        let addr = sock.peer_addr()?;
        sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        sock.set_nodelay(true)?;
        let line = read_plain_line(&mut sock, MAX_IDENTITY_PACKET_SIZE)?;
        let peer = Identity::from_packet(&Packet::parse(&line)?, true)?;
        if peer.device_id == me.device_id {
            return Err(LinkError::Refused("a connection from this device itself"));
        }
        if peer.target_device_id.as_deref().is_some_and(|t| t != me.device_id) {
            return Err(LinkError::Refused("a connection for another device"));
        }
        if peer.target_protocol_version.is_some_and(|v| v != PROTOCOL_VERSION) {
            return Err(LinkError::Refused("a connection for another protocol version"));
        }
        if peer.protocol_version < PROTOCOL_VERSION {
            return Err(LinkError::Refused("protocol version older than 8"));
        }
        let pin = trust.pinned(&peer.device_id);
        let conn = ClientConnection::new(tls::client_config(cert, pin)?, tls::server_name())?;
        let tls = Tls::Client(StreamOwned::new(conn, sock));
        Link::secure(tls, me, &peer, addr)
    }

    fn secure(mut tls: Tls, me: &Identity, plain_peer: &Identity, addr: SocketAddr) -> Result<Link, LinkError> {
        tls.handshake()?;
        tls.write_all(me.secure_packet().to_line().as_bytes())?;
        tls.flush()?;
        let peer_cert = tls.peer_cert().ok_or(LinkError::Refused("no peer certificate"))?;
        let mut link = Link { tls, buf: Vec::new(), peer: plain_peer.clone(), peer_cert, peer_addr: addr };
        let np = link.read_packet(MAX_IDENTITY_PACKET_SIZE)?.ok_or(LinkError::Refused("no encrypted identity in time"))?;
        let peer = Identity::from_packet(&np, true)?;
        if peer.device_id != plain_peer.device_id {
            return Err(LinkError::Refused("device id changed during the handshake"));
        }
        if peer.protocol_version != plain_peer.protocol_version {
            return Err(LinkError::Refused("protocol version changed during the handshake"));
        }
        if cert::common_name(&link.peer_cert)? != peer.device_id {
            return Err(LinkError::Refused("the certificate is not the device's"));
        }
        link.peer = peer;
        link.tls.sock().set_read_timeout(None)?;
        Ok(link)
    }

    /// How long [`Link::recv`] waits before returning `Ok(None)`; `None` waits for ever.
    pub fn set_read_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        self.tls.sock().set_read_timeout(t)
    }

    pub fn send(&mut self, np: &Packet) -> Result<(), LinkError> {
        self.tls.write_all(np.to_line().as_bytes())?;
        self.tls.flush()?;
        Ok(())
    }

    /// The next packet, or `None` when the read timeout passed first.
    pub fn recv(&mut self) -> Result<Option<Packet>, LinkError> {
        self.read_packet(MAX_PACKET_SIZE)
    }

    fn read_packet(&mut self, max: usize) -> Result<Option<Packet>, LinkError> {
        loop {
            if let Some(i) = self.buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=i).collect();
                let line = &line[..line.len() - 1];
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                return Ok(Some(Packet::parse(line)?));
            }
            if self.buf.len() > max {
                return Err(PacketError::TooLong(max).into());
            }
            let mut chunk = [0u8; 16 * 1024];
            match self.tls.read(&mut chunk) {
                Ok(0) => return Err(LinkError::Closed),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return Ok(None),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(LinkError::Closed),
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// The certificate pin to keep once this device is paired, and the peer's SubjectPublicKeyInfo for the
    /// verification key.
    pub fn peer_spki(&self) -> Result<Vec<u8>, LinkError> {
        Ok(cert::spki(&self.peer_cert)?)
    }

    pub fn shutdown(&self) {
        let _ = self.tls.sock().shutdown(std::net::Shutdown::Both);
    }
}

/// The verification key both devices show while pairing (kdeconnect-proto `verification_key`), from the two
/// certificates.
pub fn verification_key(mine: &DeviceCert, peer_cert: &[u8], timestamp: i64) -> Result<String, LinkError> {
    Ok(kdeconnect_proto::pairing::verification_key(&cert::spki(&mine.cert_der)?, &cert::spki(peer_cert)?, timestamp))
}
