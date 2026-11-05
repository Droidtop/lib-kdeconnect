//! Payloads: a file or other bytes that go with a packet, on a connection of their own (README, "Payloads").
//!
//! The sender listens on a port in 1739-1764 and puts `payloadTransferInfo: {"port": n}` and `payloadSize`
//! on the packet. The receiver connects to that port at the sender's address. Here, unlike the link, the TCP
//! client is the TLS client (android `LanLink.sendPayload`/`receivedNetworkPacket`). Both sides must be
//! paired: each requires the other's pinned certificate.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use kdeconnect_proto::{Packet, MAX_TCP_PORT, MIN_PAYLOAD_PORT};
use rustls::{ClientConnection, ServerConnection, StreamOwned};
use serde_json::Map;

use crate::cert::DeviceCert;
use crate::link::LinkError;
use crate::tls;

/// How long the sender waits for the receiver to connect (android: 10 s).
pub const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
const BUFFER: usize = 256 * 1024;

/// A payload listener, opened before its packet is sent.
pub struct PayloadOffer {
    listener: TcpListener,
    pub port: u16,
}

impl PayloadOffer {
    /// Listens on the first free port from 1739 to 1764 on `bind` (the unspecified address in programs).
    pub fn open(bind: IpAddr) -> io::Result<Self> {
        Self::open_in(bind, MIN_PAYLOAD_PORT..=MAX_TCP_PORT)
    }

    /// Listens on the first free port of `ports` (port 0 alone lets the system choose: tests).
    pub fn open_in(bind: IpAddr, ports: std::ops::RangeInclusive<u16>) -> io::Result<Self> {
        let mut last = io::Error::new(io::ErrorKind::AddrInUse, "no free payload port");
        for port in ports {
            match TcpListener::bind((bind, port)) {
                Ok(listener) => {
                    let port = listener.local_addr()?.port();
                    return Ok(PayloadOffer { listener, port });
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Puts the payload fields on the packet that announces it. `size` is -1 when it is not known.
    pub fn attach(&self, np: &mut Packet, size: i64) {
        let mut info = Map::new();
        info.insert("port".into(), self.port.into());
        np.payload_size = Some(size);
        np.payload_transfer_info = Some(info);
    }

    /// Waits for the receiver and sends `size` bytes of `data` (all of it when `size` is -1). Calls
    /// `progress` with the bytes sent so far. Returns the bytes sent.
    pub fn serve(
        self,
        me: &DeviceCert,
        peer_cert: Vec<u8>,
        data: &mut dyn Read,
        size: i64,
        progress: &mut dyn FnMut(u64),
    ) -> Result<u64, LinkError> {
        let deadline = Instant::now() + ACCEPT_TIMEOUT;
        self.listener.set_nonblocking(true)?;
        let sock = loop {
            match self.listener.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(LinkError::Io(io::Error::new(io::ErrorKind::TimedOut, "the receiver did not connect")));
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(e.into()),
            }
        };
        drop(self.listener);
        sock.set_nonblocking(false)?;
        sock.set_write_timeout(Some(ACCEPT_TIMEOUT))?;
        sock.set_read_timeout(Some(ACCEPT_TIMEOUT))?;
        let conn = ServerConnection::new(tls::server_config(me, Some(peer_cert))?)?;
        let mut tls = StreamOwned::new(conn, sock);
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock)?;
        }
        let limit = u64::try_from(size).ok();
        let mut sent = 0u64;
        let mut buf = vec![0u8; BUFFER];
        loop {
            let want = match limit {
                Some(l) if sent >= l => break,
                Some(l) => (l - sent).min(BUFFER as u64) as usize,
                None => BUFFER,
            };
            let n = data.read(&mut buf[..want])?;
            if n == 0 {
                if limit.is_some() {
                    return Err(LinkError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "the payload ended early")));
                }
                break;
            }
            tls.write_all(&buf[..n])?;
            sent += n as u64;
            progress(sent);
        }
        tls.flush()?;
        tls.conn.send_close_notify();
        let _ = tls.conn.complete_io(&mut tls.sock);
        Ok(sent)
    }
}

/// A payload being received: reads the stream, at most `payloadSize` bytes.
pub struct PayloadReader {
    tls: StreamOwned<ClientConnection, TcpStream>,
    remaining: Option<u64>,
}

impl PayloadReader {
    /// Connects to the payload the packet `np` from the device at `peer` announces. `None` when it has none.
    pub fn connect(np: &Packet, peer: IpAddr, me: &DeviceCert, peer_cert: Vec<u8>) -> Result<Option<Self>, LinkError> {
        let Some(port) = np.payload_port() else { return Ok(None) };
        let sock = TcpStream::connect_timeout(&SocketAddr::new(peer, port), ACCEPT_TIMEOUT)?;
        sock.set_read_timeout(Some(ACCEPT_TIMEOUT))?;
        let conn = ClientConnection::new(tls::client_config(me, Some(peer_cert))?, tls::server_name())?;
        let mut tls = StreamOwned::new(conn, sock);
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock)?;
        }
        let remaining = np.payload_size.and_then(|s| u64::try_from(s).ok());
        Ok(Some(PayloadReader { tls, remaining }))
    }

    /// Bytes still to come, when the sender said.
    pub fn remaining(&self) -> Option<u64> {
        self.remaining
    }
}

impl Read for PayloadReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = match self.remaining {
            Some(0) => return Ok(0),
            Some(r) => (r.min(buf.len() as u64)) as usize,
            None => buf.len(),
        };
        let n = match self.tls.read(&mut buf[..want]) {
            // A sender that closes without close_notify after the whole payload is still a whole payload.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && self.remaining.is_none() => 0,
            r => r?,
        };
        if let Some(r) = &mut self.remaining {
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the payload ended early"));
            }
            *r -= n as u64;
        }
        Ok(n)
    }
}
