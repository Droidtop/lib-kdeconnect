//! A running KDE Connect device, the one both programs embed (droidtop through droidtop-agent's JNI module,
//! Pythia through its Python module). It owns this device's identity on disk, the paired devices, the LAN
//! link provider, one thread per linked device, pairing and the plugins. The program sees it through calls
//! and a queue of [`ServiceEvent`]s, all serialisable to JSON, so a JNI or Python layer adds no types of its
//! own.
//!
//! What a plugin needs from the platform (typing into a field, the clipboard, where a file goes) is the
//! program's: the service reports what arrived as an event and the program acts on it.

pub mod ops;
pub mod plugins;
pub mod store;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::Duration;

use kdeconnect_link::{verification_key, AddressSource, Config, DeviceCert, Event, Link, LinkProvider, Trust};
use kdeconnect_proto::pairing::{PairEvent, PairFailure, PairState, Pairing};
use kdeconnect_proto::{types, DeviceType, Identity, Packet};
use serde::Serialize;

use crate::store::TrustStore;

/// What the program tells the service at start.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The name other devices show. Filtered to the protocol's rules.
    pub name: String,
    pub device_type: DeviceType,
    /// Where the identity and the paired devices are kept.
    pub state_dir: PathBuf,
    pub link: Config,
    /// The plugins switched on (each can be switched off; README, "Plugins").
    pub plugins: plugins::Enabled,
    /// Where files other devices share are stored; `None` refuses them.
    pub receive_dir: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("no device {0}")]
    UnknownDevice(String),
    #[error("the device is not reachable now")]
    NotReachable,
    #[error("the device is not paired")]
    NotPaired,
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// A device as the program shows it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DeviceView {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub device_type: String,
    pub reachable: bool,
    pub paired: bool,
    /// `none`, `requested` (this device asked) or `requested_by_peer`.
    pub pairing: &'static str,
    /// The 8 characters both screens show while a request is open.
    pub verification_key: Option<String>,
    pub address: Option<String>,
    pub incoming: Vec<String>,
    pub outgoing: Vec<String>,
}

/// What happened, for the program to show or act on.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ServiceEvent {
    /// A device linked (or linked again): reachable now.
    Reachable {
        device: DeviceView,
    },
    /// The link ended.
    Unreachable {
        id: String,
    },
    /// The device asks to pair. Show `key` with Accept and Refuse.
    PairRequest {
        id: String,
        name: String,
        key: String,
    },
    Paired {
        id: String,
    },
    Unpaired {
        id: String,
    },
    /// `reason`: `timed_out`, `refused` or `clocks_differ`.
    PairFailed {
        id: String,
        reason: &'static str,
    },
    /// The service was closed: no more events come.
    Stopped,
    /// Anything a plugin turned into an event (README, "Plugins").
    Plugin {
        id: String,
        plugin: plugins::PluginEvent,
    },
}

enum Cmd {
    Send(Packet),
    Close,
}

struct DeviceState {
    identity: Identity,
    addr: Option<SocketAddr>,
    peer_cert: Option<Vec<u8>>,
    link: Option<(u64, Sender<Cmd>)>,
    pairing: Pairing,
}

#[derive(Default)]
struct Addresses {
    extra: RwLock<Vec<IpAddr>>,
    remembered: RwLock<Vec<IpAddr>>,
}

impl AddressSource for Addresses {
    fn addresses(&self) -> Vec<IpAddr> {
        let mut v = self.extra.read().unwrap_or_else(|e| e.into_inner()).clone();
        for a in self.remembered.read().unwrap_or_else(|e| e.into_inner()).iter() {
            if !v.contains(a) {
                v.push(*a);
            }
        }
        v
    }
}

struct Inner {
    me: Identity,
    cert: DeviceCert,
    plugins: plugins::Enabled,
    receive_dir: Option<PathBuf>,
    clip: Mutex<plugins::clipboard::Clip>,
    /// Whether this device can take typing now (droidtop: its input method is the active one).
    keyboard_ready: std::sync::atomic::AtomicBool,
    /// This device's battery, when the program said (`None`: it has none, or has not said).
    battery: Mutex<Option<plugins::battery::Battery>>,
    /// This device's notifications as the program posted them, for a paired device that asks for all.
    posted: Mutex<std::collections::BTreeMap<String, plugins::notifications::Outgoing>>,
    trust: Mutex<TrustStore>,
    devices: Mutex<HashMap<String, DeviceState>>,
    events: Mutex<Sender<ServiceEvent>>,
    next_gen: Mutex<u64>,
    stop: std::sync::atomic::AtomicBool,
}

struct Pins(Arc<Inner>);

impl Trust for Pins {
    fn pinned(&self, id: &str) -> Option<Vec<u8>> {
        self.0.trust.lock().unwrap_or_else(|e| e.into_inner()).devices.get(id).and_then(|t| t.cert_der())
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// The running service. Dropping it stops every thread and closes every link.
pub struct Service {
    inner: Arc<Inner>,
    provider: Arc<LinkProvider>,
    addresses: Arc<Addresses>,
    events: Mutex<Receiver<ServiceEvent>>,
    threads: Vec<JoinHandle<()>>,
}

impl Inner {
    fn emit(&self, e: ServiceEvent) {
        let _ = self.events.lock().unwrap_or_else(|e| e.into_inner()).send(e);
    }

    fn view(&self, s: &DeviceState) -> DeviceView {
        let trusted = self.trust.lock().unwrap_or_else(|e| e.into_inner()).devices.contains_key(&s.identity.device_id);
        let key = match (s.pairing.timestamp(), &s.peer_cert) {
            (Some(ts), Some(c)) => verification_key(&self.cert, c, ts).ok(),
            _ => None,
        };
        DeviceView {
            id: s.identity.device_id.clone(),
            name: s.identity.device_name.clone(),
            device_type: s.identity.device_type.as_str().to_owned(),
            reachable: s.link.is_some(),
            paired: trusted,
            pairing: match s.pairing.state {
                PairState::Requested { .. } => "requested",
                PairState::RequestedByPeer { .. } => "requested_by_peer",
                _ => "none",
            },
            verification_key: key,
            address: s.addr.map(|a| a.ip().to_string()),
            incoming: s.identity.incoming_capabilities.clone(),
            outgoing: s.identity.outgoing_capabilities.clone(),
        }
    }

    fn send(&self, id: &str, np: Packet) -> Result<(), ServiceError> {
        let devices = self.devices.lock().unwrap_or_else(|e| e.into_inner());
        let d = devices.get(id).ok_or_else(|| ServiceError::UnknownDevice(id.to_owned()))?;
        let (_, tx) = d.link.as_ref().ok_or(ServiceError::NotReachable)?;
        tx.send(Cmd::Send(np)).map_err(|_| ServiceError::NotReachable)
    }

    fn pin(&self, id: &str) {
        let devices = self.devices.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(d) = devices.get(id) {
            if let Some(c) = &d.peer_cert {
                let _ = self.trust.lock().unwrap_or_else(|e| e.into_inner()).pin(
                    id,
                    &d.identity.device_name,
                    d.identity.device_type.as_str(),
                    c,
                    d.addr.map(|a| a.ip().to_string()),
                );
            }
        }
    }

    /// The clipboard as it is now, to a device that has just been paired (android sends it when the plugin starts).
    fn send_clip_connect(&self, id: &str) {
        if self.plugins.battery {
            if let Some(b) = *self.battery.lock().unwrap_or_else(|e| e.into_inner()) {
                let _ = self.send(id, b.packet());
            }
        }
        if self.plugins.notifications {
            let _ = self.send(id, plugins::notifications::request_all());
        }
        if self.plugins.input {
            let _ = self.send(id, plugins::input::keyboard_state(self.keyboard_ready.load(std::sync::atomic::Ordering::SeqCst)));
        }
        if self.plugins.clipboard {
            if let Some(np) = self.clip.lock().unwrap_or_else(|e| e.into_inner()).connect_packet() {
                let _ = self.send(id, np);
            }
        }
    }

    fn forget(&self, id: &str) {
        let _ = self.trust.lock().unwrap_or_else(|e| e.into_inner()).forget(id);
    }

    fn pair_event(&self, id: &str, e: PairEvent) {
        match e {
            PairEvent::IncomingRequest => {
                let (name, key) = {
                    let devices = self.devices.lock().unwrap_or_else(|e| e.into_inner());
                    let d = &devices[id];
                    (d.identity.device_name.clone(), self.view(d).verification_key.unwrap_or_default())
                };
                self.emit(ServiceEvent::PairRequest { id: id.to_owned(), name, key });
            }
            PairEvent::Paired => {
                self.pin(id);
                self.send_clip_connect(id);
                self.emit(ServiceEvent::Paired { id: id.to_owned() });
            }
            PairEvent::Unpaired => {
                self.forget(id);
                self.emit(ServiceEvent::Unpaired { id: id.to_owned() });
            }
            PairEvent::Failed(f) => self.emit(ServiceEvent::PairFailed {
                id: id.to_owned(),
                reason: match f {
                    PairFailure::TimedOut => "timed_out",
                    PairFailure::RefusedByPeer => "refused",
                    PairFailure::ClocksDiffer => "clocks_differ",
                },
            }),
        }
    }

    /// Takes a new link: replaces any link the device had, and runs it on its own thread.
    fn adopt(self: &Arc<Self>, link: Link) {
        let id = link.peer.device_id.clone();
        let (tx, rx) = channel();
        let tx_for_connect = tx.clone();
        let gen = {
            let mut g = self.next_gen.lock().unwrap_or_else(|e| e.into_inner());
            *g += 1;
            *g
        };
        let paired = self.trust.lock().unwrap_or_else(|e| e.into_inner()).devices.contains_key(&id);
        let view = {
            let mut devices = self.devices.lock().unwrap_or_else(|e| e.into_inner());
            let d = devices.entry(id.clone()).or_insert_with(|| DeviceState {
                identity: link.peer.clone(),
                addr: None,
                peer_cert: None,
                link: None,
                pairing: Pairing::new(paired),
            });
            if let Some((_, old)) = d.link.take() {
                let _ = old.send(Cmd::Close);
            }
            d.identity = link.peer.clone();
            d.addr = Some(link.peer_addr);
            d.peer_cert = Some(link.peer_cert.clone());
            d.link = Some((gen, tx.clone()));
            if paired && d.pairing.state == PairState::NotPaired {
                d.pairing = Pairing::new(true);
            }
            self.view(d)
        };
        if paired {
            // Keep the address it was last reached at, for the next start.
            self.pin(&id);
            if self.plugins.battery {
                if let Some(b) = *self.battery.lock().unwrap_or_else(|e| e.into_inner()) {
                    let _ = tx_for_connect.send(Cmd::Send(b.packet()));
                }
            }
            if self.plugins.notifications {
                let _ = tx_for_connect.send(Cmd::Send(plugins::notifications::request_all()));
            }
            if self.plugins.input {
                let ready = self.keyboard_ready.load(std::sync::atomic::Ordering::SeqCst);
                let _ = tx_for_connect.send(Cmd::Send(plugins::input::keyboard_state(ready)));
            }
            if self.plugins.clipboard {
                if let Some(np) = self.clip.lock().unwrap_or_else(|e| e.into_inner()).connect_packet() {
                    let _ = tx_for_connect.send(Cmd::Send(np));
                }
            }
        }
        self.emit(ServiceEvent::Reachable { device: view });
        let me = Arc::clone(self);
        std::thread::spawn(move || me.run_link(link, gen, rx));
    }

    fn run_link(self: Arc<Self>, mut link: Link, gen: u64, rx: Receiver<Cmd>) {
        let id = link.peer.device_id.clone();
        let _ = link.set_read_timeout(Some(Duration::from_millis(200)));
        let ended = loop {
            if self.stop.load(std::sync::atomic::Ordering::SeqCst) {
                break true;
            }
            let mut close = false;
            while let Ok(cmd) = rx.try_recv() {
                match cmd {
                    Cmd::Send(np) => {
                        if link.send(&np).is_err() {
                            close = true;
                        }
                    }
                    Cmd::Close => close = true,
                }
            }
            if close {
                break true;
            }
            let lapsed = {
                let mut devices = self.devices.lock().unwrap_or_else(|e| e.into_inner());
                devices.get_mut(&id).and_then(|d| d.pairing.tick(now()))
            };
            if let Some(e) = lapsed {
                self.pair_event(&id, e);
            }
            match link.recv() {
                Ok(None) => {}
                Ok(Some(np)) => self.packet(&id, np, &link),
                Err(_) => break true,
            }
        };
        link.shutdown();
        if ended {
            let gone = {
                let mut devices = self.devices.lock().unwrap_or_else(|e| e.into_inner());
                match devices.get_mut(&id) {
                    Some(d) if d.link.as_ref().is_some_and(|(g, _)| *g == gen) => {
                        d.link = None;
                        if !matches!(d.pairing.state, PairState::Paired) {
                            d.pairing = Pairing::new(false);
                        }
                        true
                    }
                    _ => false,
                }
            };
            if gone {
                self.emit(ServiceEvent::Unreachable { id });
            }
        }
    }

    fn packet(self: &Arc<Self>, id: &str, np: Packet, link: &Link) {
        if np.kind == types::PAIR {
            let e = {
                let mut devices = self.devices.lock().unwrap_or_else(|e| e.into_inner());
                devices.get_mut(id).and_then(|d| d.pairing.on_packet(&np, now()))
            };
            if let Some(e) = e {
                self.pair_event(id, e);
            }
            return;
        }
        // Both apps drop every other packet from a device that is not paired.
        let paired = self.trust.lock().unwrap_or_else(|e| e.into_inner()).devices.contains_key(id);
        if !paired {
            return;
        }
        if self.plugins.clipboard && (np.kind == plugins::clipboard::TYPE || np.kind == plugins::clipboard::CONNECT) {
            let e = self.clip.lock().unwrap_or_else(|e| e.into_inner()).receive(&np, now_ms());
            if let Some(e) = e {
                self.emit(ServiceEvent::Plugin { id: id.to_owned(), plugin: e });
            }
            return;
        }
        if matches!(np.kind.as_str(), plugins::input::REQUEST | plugins::input::ECHO | plugins::input::KEYBOARD_STATE) {
            let (e, ack) = plugins::input::receive(&np, self.plugins.input);
            if let Some(ack) = ack {
                let _ = self.send(id, ack);
            }
            if let Some(e) = e {
                self.emit(ServiceEvent::Plugin { id: id.to_owned(), plugin: e });
            }
            return;
        }
        if np.kind == plugins::notifications::REQUEST {
            if !self.plugins.notifications {
                return;
            }
            match plugins::notifications::request(&np) {
                Some(plugins::notifications::Request::All) => {
                    let all: Vec<_> = self.posted.lock().unwrap_or_else(|e| e.into_inner()).values().cloned().collect();
                    for n in all {
                        let _ = self.send(id, n.packet());
                    }
                }
                Some(plugins::notifications::Request::Dismiss(key))
                    if self.posted.lock().unwrap_or_else(|e| e.into_inner()).contains_key(&key) =>
                {
                    self.emit(ServiceEvent::Plugin { id: id.to_owned(), plugin: plugins::PluginEvent::NotificationDismissed { key } });
                }
                _ => {}
            }
            return;
        }
        if np.kind == plugins::battery::REQUEST {
            if self.plugins.battery {
                if let Some(b) = *self.battery.lock().unwrap_or_else(|e| e.into_inner()) {
                    let _ = self.send(id, b.packet());
                }
            }
            return;
        }
        let me = Arc::clone(self);
        let device = id.to_owned();
        let ctx = || plugins::share::Incoming {
            receive_dir: self.receive_dir.clone(),
            cert: self.cert.clone(),
            peer_ip: link.peer_addr.ip(),
            peer_cert: link.peer_cert.clone(),
            emit: Arc::new(move |e| me.emit(ServiceEvent::Plugin { id: device.clone(), plugin: e })),
        };
        for e in plugins::receive(&self.plugins, &np, ctx) {
            self.emit(ServiceEvent::Plugin { id: id.to_owned(), plugin: e });
        }
    }
}

impl Service {
    pub fn start(settings: Settings) -> Result<Service, ServiceError> {
        let (device_id, cert, fresh) = store::load_identity(&settings.state_dir)?;
        let trust = TrustStore::load(&settings.state_dir, fresh);
        let mut me = Identity::new(device_id, &settings.name, settings.device_type);
        me.incoming_capabilities = plugins::incoming(&settings.plugins);
        me.outgoing_capabilities = plugins::outgoing(&settings.plugins);
        let addresses = Arc::new(Addresses::default());
        *addresses.remembered.write().unwrap_or_else(|e| e.into_inner()) =
            trust.devices.values().filter_map(|t| t.last_address.as_deref()?.parse().ok()).collect();
        let (tx, rx) = channel();
        let inner = Arc::new(Inner {
            me: me.clone(),
            cert: cert.clone(),
            plugins: settings.plugins,
            receive_dir: settings.receive_dir,
            clip: Mutex::new(Default::default()),
            keyboard_ready: std::sync::atomic::AtomicBool::new(false),
            battery: Mutex::new(None),
            posted: Mutex::new(Default::default()),
            trust: Mutex::new(trust),
            devices: Mutex::new(HashMap::new()),
            events: Mutex::new(tx),
            next_gen: Mutex::new(0),
            stop: std::sync::atomic::AtomicBool::new(false),
        });
        let provider = Arc::new(LinkProvider::start(settings.link, me, cert, Arc::new(Pins(Arc::clone(&inner))), addresses.clone())?);
        let (i, p) = (Arc::clone(&inner), Arc::clone(&provider));
        let accept = std::thread::spawn(move || {
            while !i.stop.load(std::sync::atomic::Ordering::SeqCst) {
                if let Some(Event::Linked(link)) = p.next_event(Duration::from_millis(250)) {
                    i.adopt(*link);
                }
            }
        });
        let s = Service { inner, provider, addresses, events: Mutex::new(rx), threads: vec![accept] };
        let _ = s.announce();
        Ok(s)
    }

    /// This device's id and name as the others see them.
    pub fn identity(&self) -> &Identity {
        &self.inner.me
    }

    /// The port this device's link listener took (tests).
    pub fn tcp_port(&self) -> u16 {
        self.provider.tcp_port()
    }

    /// The port it hears announcements on (tests).
    pub fn udp_port(&self) -> u16 {
        self.provider.udp_port()
    }

    /// Says this device is here: on start, on a network change and when the person refreshes the list.
    pub fn announce(&self) -> std::io::Result<()> {
        self.provider.announce()
    }

    /// Addresses to announce to besides the broadcast: devices the person added by address, and a VPN
    /// plugin's peers (a tailnet's online devices). Replaces the last list.
    pub fn set_extra_addresses(&self, addrs: Vec<IpAddr>) {
        *self.addresses.extra.write().unwrap_or_else(|e| e.into_inner()) = addrs;
    }

    /// The next event; `None` when `timeout` passes first.
    pub fn next_event(&self, timeout: Duration) -> Option<ServiceEvent> {
        self.events.lock().unwrap_or_else(|e| e.into_inner()).recv_timeout(timeout).ok()
    }

    /// Every device seen this run, and every paired one, reachable or not.
    pub fn devices(&self) -> Vec<DeviceView> {
        let devices = self.inner.devices.lock().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<DeviceView> = devices.values().map(|d| self.inner.view(d)).collect();
        let trust = self.inner.trust.lock().unwrap_or_else(|e| e.into_inner());
        for (id, t) in &trust.devices {
            if !devices.contains_key(id) {
                v.push(DeviceView {
                    id: id.clone(),
                    name: t.name.clone(),
                    device_type: t.device_type.clone(),
                    reachable: false,
                    paired: true,
                    pairing: "none",
                    verification_key: None,
                    address: t.last_address.clone(),
                    incoming: Vec::new(),
                    outgoing: Vec::new(),
                });
            }
        }
        v.sort_by(|a, b| b.reachable.cmp(&a.reachable).then_with(|| a.name.cmp(&b.name)));
        v
    }

    fn with_pairing<T>(&self, id: &str, f: impl FnOnce(&mut Pairing) -> T) -> Result<T, ServiceError> {
        let mut devices = self.inner.devices.lock().unwrap_or_else(|e| e.into_inner());
        let d = devices.get_mut(id).ok_or_else(|| ServiceError::UnknownDevice(id.to_owned()))?;
        if d.link.is_none() {
            return Err(ServiceError::NotReachable);
        }
        Ok(f(&mut d.pairing))
    }

    /// Asks the device to pair. Its answer comes as [`ServiceEvent::Paired`] or [`ServiceEvent::PairFailed`].
    pub fn pair(&self, id: &str) -> Result<(), ServiceError> {
        let accepted_theirs = self.with_pairing(id, |p| matches!(p.state, PairState::RequestedByPeer { .. }))?;
        if let Some(np) = self.with_pairing(id, |p| p.request(now()))? {
            self.inner.send(id, np)?;
        }
        if accepted_theirs {
            self.inner.pin(id);
            self.inner.send_clip_connect(id);
            self.inner.emit(ServiceEvent::Paired { id: id.to_owned() });
        }
        Ok(())
    }

    /// Accepts the device's request.
    pub fn accept(&self, id: &str) -> Result<(), ServiceError> {
        let np = self.with_pairing(id, |p| p.accept())?;
        if let Some(np) = np {
            self.inner.send(id, np)?;
            self.inner.pin(id);
            self.inner.send_clip_connect(id);
            self.inner.emit(ServiceEvent::Paired { id: id.to_owned() });
        }
        Ok(())
    }

    /// Refuses the device's request, or withdraws this device's own.
    pub fn refuse(&self, id: &str) -> Result<(), ServiceError> {
        if let Some(np) = self.with_pairing(id, |p| p.cancel())? {
            self.inner.send(id, np)?;
        }
        Ok(())
    }

    /// Unpairs: tells the device when it is reachable, and forgets its certificate either way.
    pub fn unpair(&self, id: &str) -> Result<(), ServiceError> {
        let np = self.with_pairing(id, |p| p.unpair()).ok();
        if let Some(np) = np {
            let _ = self.inner.send(id, np);
        }
        self.inner.forget(id);
        self.inner.emit(ServiceEvent::Unpaired { id: id.to_owned() });
        Ok(())
    }

    /// Sends a packet to a paired, reachable device.
    pub fn send(&self, id: &str, np: Packet) -> Result<(), ServiceError> {
        if !self.inner.trust.lock().unwrap_or_else(|e| e.into_inner()).devices.contains_key(id) {
            return Err(ServiceError::NotPaired);
        }
        self.inner.send(id, np)
    }

    /// This device's clipboard changed to `text`: sent to every paired, reachable device, unless it is the text
    /// already held (the one that just arrived from one of them).
    pub fn clipboard_set(&self, text: &str) -> usize {
        if !self.inner.plugins.clipboard || !self.inner.clip.lock().unwrap_or_else(|e| e.into_inner()).set(text, now_ms()) {
            return 0;
        }
        let ids: Vec<String> = self.devices().into_iter().filter(|d| d.paired && d.reachable).map(|d| d.id).collect();
        ids.iter().filter(|id| self.send(id, plugins::clipboard::packet(text)).is_ok()).count()
    }

    /// This device's battery changed (or `None`: it has none): sent to every paired, reachable device.
    pub fn set_battery(&self, battery: Option<plugins::battery::Battery>) {
        let old = std::mem::replace(&mut *self.inner.battery.lock().unwrap_or_else(|e| e.into_inner()), battery);
        if !self.inner.plugins.battery || old == battery {
            return;
        }
        if let Some(b) = battery {
            for d in self.devices().into_iter().filter(|d| d.paired && d.reachable) {
                let _ = self.send(&d.id, b.packet());
            }
        }
    }

    /// Rings the paired device `id` (find my device).
    pub fn ring(&self, id: &str) -> Result<(), ServiceError> {
        self.send(id, plugins::findmyphone::packet())
    }

    /// This device posted or updated notification `n`: sent to every paired, reachable device, and kept for any that
    /// asks for all. Returns how many it went to.
    pub fn post_notification(&self, n: plugins::notifications::Outgoing) -> usize {
        if !self.inner.plugins.notifications {
            return 0;
        }
        let np = n.packet();
        self.inner.posted.lock().unwrap_or_else(|e| e.into_inner()).insert(n.key.clone(), n);
        let ids: Vec<String> = self.devices().into_iter().filter(|d| d.paired && d.reachable).map(|d| d.id).collect();
        ids.iter().filter(|id| self.send(id, np.clone()).is_ok()).count()
    }

    /// This device's notification `key` is gone: taken away on every paired, reachable device.
    pub fn cancel_notification(&self, key: &str) {
        if self.inner.posted.lock().unwrap_or_else(|e| e.into_inner()).remove(key).is_none() {
            return;
        }
        for d in self.devices().into_iter().filter(|d| d.paired && d.reachable) {
            let _ = self.send(&d.id, plugins::notifications::cancel(key));
        }
    }

    /// Dismisses the other device's notification `key` there.
    pub fn dismiss_notification(&self, id: &str, key: &str) -> Result<(), ServiceError> {
        self.send(id, plugins::notifications::dismiss(key))
    }

    /// Moves the pointer of, or types into, the paired device `id`.
    pub fn input_send(&self, id: &str, input: &plugins::input::InputEvent) -> Result<(), ServiceError> {
        self.send(id, input.to_packet())
    }

    /// Whether this device can take typing now; told to every paired, reachable device when it changes.
    pub fn set_keyboard_ready(&self, ready: bool) {
        if !self.inner.plugins.input || self.inner.keyboard_ready.swap(ready, std::sync::atomic::Ordering::SeqCst) == ready {
            return;
        }
        for d in self.devices().into_iter().filter(|d| d.paired && d.reachable) {
            let _ = self.send(&d.id, plugins::input::keyboard_state(ready));
        }
    }

    /// Shares a text (`kdeconnect.share.request` with `text`).
    pub fn share_text(&self, id: &str, text: &str) -> Result<(), ServiceError> {
        self.send(id, plugins::share::text_packet(text))
    }

    /// Shares a link the other device opens.
    pub fn share_url(&self, id: &str, url: &str) -> Result<(), ServiceError> {
        self.send(id, plugins::share::url_packet(url))
    }

    /// Sends a file. The packet goes now; the bytes go when the other device connects for them (within 10 s), on a
    /// thread of their own. The outcome comes as [`plugins::PluginEvent::FileSent`] or `FileSendFailed`.
    pub fn share_file(&self, id: &str, file: plugins::share::Outgoing) -> Result<(), ServiceError> {
        let pin = {
            let devices = self.inner.devices.lock().unwrap_or_else(|e| e.into_inner());
            let d = devices.get(id).ok_or_else(|| ServiceError::UnknownDevice(id.to_owned()))?;
            d.peer_cert.clone().ok_or(ServiceError::NotReachable)?
        };
        let (np, offer) = plugins::share::file_packet(&file, IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))?;
        self.send(id, np)?;
        let (inner, id, cert) = (Arc::clone(&self.inner), id.to_owned(), self.inner.cert.clone());
        std::thread::spawn(move || {
            let plugins::share::Outgoing { name, size, mut data, .. } = file;
            let e = match offer.serve(&cert, pin, &mut data, size, &mut |_| {}) {
                Ok(n) => plugins::PluginEvent::FileSent { name, size: n },
                Err(e) => plugins::PluginEvent::FileSendFailed { name, why: e.to_string() },
            };
            inner.emit(ServiceEvent::Plugin { id, plugin: e });
        });
        Ok(())
    }

    /// `kdeconnect.ping`, with an optional message the other device shows.
    pub fn ping(&self, id: &str, message: Option<&str>) -> Result<(), ServiceError> {
        self.send(id, plugins::ping::packet(message))
    }
}

impl Service {
    /// Closes every link and wakes a caller waiting in [`Service::next_event`] with [`ServiceEvent::Stopped`].
    /// The listeners close when the service is dropped.
    pub fn close(&self) {
        if self.inner.stop.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        for d in self.inner.devices.lock().unwrap_or_else(|e| e.into_inner()).values() {
            if let Some((_, tx)) = &d.link {
                let _ = tx.send(Cmd::Close);
            }
        }
        self.inner.emit(ServiceEvent::Stopped);
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.close();
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}
