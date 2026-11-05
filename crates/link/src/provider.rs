//! The LAN link provider: listens for announcements and connections and makes [`Link`]s (android and kde
//! `LanLinkProvider`).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use kdeconnect_proto::{Identity, MAX_TCP_PORT, MIN_TCP_PORT, UDP_PORT};

use crate::cert::DeviceCert;
use crate::discovery::{self, AddressSource};
use crate::link::{Link, LinkError, Trust};

/// A second packet or connection from one address, or for one device, this soon after the last is dropped
/// (both apps' `MILLIS_DELAY_BETWEEN_CONNECTIONS_TO_SAME_DEVICE`).
const RATE_LIMIT: Duration = Duration::from_millis(500);
/// At most this many handshakes at once (both apps' `MAX_UNPAIRED_CONNECTIONS`).
const MAX_HANDSHAKES: usize = 42;
const POLL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: IpAddr,
    pub udp_port: u16,
    pub tcp_ports: RangeInclusive<u16>,
    /// The ports another device's announced `tcpPort` may be in (1716-1764 but in tests).
    pub peer_tcp_ports: RangeInclusive<u16>,
    /// Announce to 255.255.255.255 (off in tests, and on a network the person does not trust).
    pub broadcast: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            udp_port: UDP_PORT,
            tcp_ports: MIN_TCP_PORT..=MAX_TCP_PORT,
            peer_tcp_ports: MIN_TCP_PORT..=MAX_TCP_PORT,
            broadcast: true,
        }
    }
}

#[derive(Debug)]
pub enum Event {
    /// A device is linked. Its pairing state is the program's: [`Trust::pinned`] said whether it is paired.
    Linked(Box<Link>),
    /// A handshake with this address failed (for the log; nothing is shown to the person).
    Failed { addr: SocketAddr, error: LinkError },
}

struct Shared {
    me: Identity,
    cert: DeviceCert,
    trust: Arc<dyn Trust>,
    sources: Arc<dyn AddressSource>,
    stop: AtomicBool,
    handshakes: AtomicUsize,
    by_ip: Mutex<HashMap<IpAddr, Instant>>,
    by_device: Mutex<HashMap<String, Instant>>,
    events: Mutex<Sender<Event>>,
}

impl Shared {
    fn allowed(&self, ip: IpAddr) -> bool {
        discovery::is_local(ip) || self.sources.addresses().contains(&ip)
    }

    fn limited<K: std::hash::Hash + Eq>(map: &Mutex<HashMap<K, Instant>>, key: K) -> bool {
        let now = Instant::now();
        let mut m = map.lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|_, t| now.duration_since(*t) < RATE_LIMIT);
        if m.contains_key(&key) || m.len() >= 1024 {
            return true;
        }
        m.insert(key, now);
        false
    }

    fn emit(&self, e: Event) {
        let _ = self.events.lock().unwrap_or_else(|e| e.into_inner()).send(e);
    }

    /// Runs one handshake on its own thread, unless too many are running.
    fn handshake(self: &Arc<Self>, addr: SocketAddr, f: impl FnOnce(&Shared) -> Result<Link, LinkError> + Send + 'static) {
        if self.handshakes.fetch_add(1, Ordering::SeqCst) >= MAX_HANDSHAKES {
            self.handshakes.fetch_sub(1, Ordering::SeqCst);
            return;
        }
        let me = Arc::clone(self);
        std::thread::spawn(move || {
            let r = f(&me);
            me.handshakes.fetch_sub(1, Ordering::SeqCst);
            me.emit(match r {
                Ok(link) => Event::Linked(Box::new(link)),
                Err(error) => Event::Failed { addr, error },
            });
        });
    }
}

pub struct LinkProvider {
    shared: Arc<Shared>,
    config: Config,
    tcp_port: u16,
    udp_port: u16,
    events: Receiver<Event>,
    threads: Vec<JoinHandle<()>>,
}

impl LinkProvider {
    pub fn start(
        config: Config,
        me: Identity,
        cert: DeviceCert,
        trust: Arc<dyn Trust>,
        sources: Arc<dyn AddressSource>,
    ) -> std::io::Result<Self> {
        let udp = UdpSocket::bind((config.bind, config.udp_port))?;
        udp.set_read_timeout(Some(Duration::from_millis(250)))?;
        let udp_port = udp.local_addr()?.port();
        let mut tcp = None;
        let mut last = std::io::Error::new(std::io::ErrorKind::AddrInUse, "no free port in 1716-1764");
        for port in config.tcp_ports.clone() {
            match TcpListener::bind((config.bind, port)) {
                Ok(l) => {
                    tcp = Some(l);
                    break;
                }
                Err(e) => last = e,
            }
        }
        let tcp = tcp.ok_or(last)?;
        let tcp_port = tcp.local_addr()?.port();
        tcp.set_nonblocking(true)?;
        let (tx, events) = channel();
        let shared = Arc::new(Shared {
            me,
            cert,
            trust,
            sources,
            stop: AtomicBool::new(false),
            handshakes: AtomicUsize::new(0),
            by_ip: Mutex::new(HashMap::new()),
            by_device: Mutex::new(HashMap::new()),
            events: Mutex::new(tx),
        });

        let s = Arc::clone(&shared);
        let peer_ports = config.peer_tcp_ports.clone();
        let udp_thread = std::thread::spawn(move || {
            let mut buf = vec![0u8; kdeconnect_proto::MAX_IDENTITY_PACKET_SIZE];
            while !s.stop.load(Ordering::SeqCst) {
                let Ok((n, from)) = udp.recv_from(&mut buf) else { continue };
                // This device's own announcement is dropped by its device id in parse_announcement.
                if !s.allowed(from.ip()) || Shared::limited(&s.by_ip, from.ip()) {
                    continue;
                }
                let Some(heard) = discovery::parse_announcement(&buf[..n], from, &s.me.device_id, &peer_ports) else { continue };
                if Shared::limited(&s.by_device, heard.identity.device_id.clone()) {
                    continue;
                }
                s.handshake(heard.addr, move |s| Link::connect(heard.addr, &s.me, &s.cert, &heard.identity, s.trust.as_ref()));
            }
        });

        let s = Arc::clone(&shared);
        let tcp_thread = std::thread::spawn(move || {
            while !s.stop.load(Ordering::SeqCst) {
                match tcp.accept() {
                    Ok((sock, addr)) => {
                        if !s.allowed(addr.ip()) || Shared::limited(&s.by_ip, addr.ip()) {
                            continue;
                        }
                        let _ = sock.set_nonblocking(false);
                        s.handshake(addr, move |s| Link::accept(sock, &s.me, &s.cert, s.trust.as_ref()));
                    }
                    Err(_) => std::thread::sleep(POLL),
                }
            }
        });

        Ok(LinkProvider { shared, config, tcp_port, udp_port, events, threads: vec![udp_thread, tcp_thread] })
    }

    /// The port of this device's TCP listener.
    pub fn tcp_port(&self) -> u16 {
        self.tcp_port
    }

    /// The port this device hears announcements on (1716 but in tests).
    pub fn udp_port(&self) -> u16 {
        self.udp_port
    }

    /// Announces this device: on joining a network, on a network change, and when the person asks for a
    /// refresh. Goes to the broadcast address and to every address the [`AddressSource`] gives.
    pub fn announce(&self) -> std::io::Result<()> {
        let extra = self.shared.sources.addresses();
        discovery::announce(&self.shared.me, self.tcp_port, &extra, self.config.udp_port, self.config.broadcast)
    }

    /// Links made and handshakes failed, in the order they happened.
    pub fn events(&self) -> &Receiver<Event> {
        &self.events
    }

    /// Connects to a device listening at `addr` directly, without waiting for it to hear an announcement
    /// (tests, and a device whose UDP is blocked but whose TCP port is known).
    pub fn connect_direct(&self, addr: SocketAddr, peer: Identity) {
        self.shared.handshake(addr, move |s| Link::connect(addr, &s.me, &s.cert, &peer, s.trust.as_ref()));
    }
}

impl Drop for LinkProvider {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}
