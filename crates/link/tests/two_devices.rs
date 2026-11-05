//! Two devices in one process, over loopback: discovery, the TLS link both ways round, pairing, a packet,
//! a payload, and the pin refusing a changed certificate. Plus the verification-key vectors from
//! kdeconnect-android's `PairingHandlerTest`.

use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use kdeconnect_link::discovery::{self, AddressSource};
use kdeconnect_link::{cert, verification_key, Config, DeviceCert, Event, Link, LinkProvider, PayloadOffer, PayloadReader, Trust};
use kdeconnect_proto::identity::new_device_id;
use kdeconnect_proto::pairing::{PairEvent, Pairing};
use kdeconnect_proto::{types, DeviceType, Identity, Packet};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

#[derive(Default)]
struct Pins(Mutex<HashMap<String, Vec<u8>>>);

impl Trust for Pins {
    fn pinned(&self, id: &str) -> Option<Vec<u8>> {
        self.0.lock().unwrap().get(id).cloned()
    }
}

impl Pins {
    fn pin(&self, id: &str, der: Vec<u8>) {
        self.0.lock().unwrap().insert(id.to_owned(), der);
    }
}

struct Loopback;
impl AddressSource for Loopback {
    fn addresses(&self) -> Vec<IpAddr> {
        vec![LOOPBACK]
    }
}

struct Device {
    id: Identity,
    cert: DeviceCert,
    pins: Arc<Pins>,
    provider: LinkProvider,
}

fn device(name: &str, kind: DeviceType) -> Device {
    let mut id = Identity::new(new_device_id(), name, kind);
    id.incoming_capabilities = vec![types::PING.into()];
    id.outgoing_capabilities = vec![types::PING.into()];
    let cert = DeviceCert::generate(&id.device_id).unwrap();
    let pins = Arc::new(Pins::default());
    let config = Config {
        bind: LOOPBACK,
        udp_port: 0,
        tcp_ports: 0..=0,
        peer_tcp_ports: 1..=u16::MAX,
        peer_udp_port: 0,
        mdns: false,
        broadcast: false,
    };
    let provider = LinkProvider::start(config, id.clone(), cert.clone(), pins.clone(), Arc::new(Loopback)).unwrap();
    Device { id, cert, pins, provider }
}

fn next_link(d: &Device) -> Link {
    match d.provider.next_event(Duration::from_secs(20)).expect("an event") {
        Event::Linked(l) => *l,
        Event::Failed { addr, error } => panic!("handshake with {addr} failed: {error}"),
    }
}

fn recv(l: &mut Link) -> Packet {
    l.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    l.recv().unwrap().expect("a packet in time")
}

#[test]
fn certificate_is_made_like_the_official_apps() {
    let id = new_device_id();
    let c = DeviceCert::generate(&id).unwrap();
    assert_eq!(c.device_id().unwrap(), id);
    assert!(!cert::has_san(&c.cert_der).unwrap(), "a SAN would replace the CN kde checks");
    assert!(!cert::spki(&c.cert_der).unwrap().is_empty());
}

// kdeconnect-android src/test/.../PairingHandlerTest.kt, getVerificationKey.
#[test]
fn verification_key_matches_android() {
    let b64 = base64::engine::general_purpose::STANDARD;
    let a = b64.decode(concat!(
        "MIIBkzCCATmgAwIBAgIBATAKBggqhkjOPQQDBDBTMS0wKwYDVQQDDCRlZTA2MWE3NV9lNDAzXzRlY2NfOTI2",
        "MV81ZmZlMjcyMmY2OTgxFDASBgNVBAsMC0tERSBDb25uZWN0MQwwCgYDVQQKDANLREUwHhcNMjMwOTE1MjIw",
        "MDAwWhcNMzQwOTE1MjIwMDAwWjBTMS0wKwYDVQQDDCRlZTA2MWE3NV9lNDAzXzRlY2NfOTI2MV81ZmZlMjcy",
        "MmY2OTgxFDASBgNVBAsMC0tERSBDb25uZWN0MQwwCgYDVQQKDANLREUwWTATBgcqhkjOPQIBBggqhkjOPQMB",
        "BwNCAASqOIKTm5j6x8DKgYSkItLmjCgIXP0gkOW6bmVvloDGsYnvqYLMFGe7YW8g8lT/qPBTEfDOM4UpQ8X6",
        "jidE+XrnMAoGCCqGSM49BAMEA0gAMEUCIEpk6VNpbt3tfbWDf0TmoJftRq3wAs3Dke7d5vMZlivyAiEA/ZXt",
        "SRqPjs/2RN9SynKhSUA9/z0PNq6LYoAaC6TdomM="
    ));
    let b = b64.decode(concat!(
        "MIIBkzCCATmgAwIBAgIBATAKBggqhkjOPQQDBDBTMS0wKwYDVQQDDCQxNTdiYmMyOF82ZjJiXzRiMTZfYmQw",
        "Ml8xMzM0NWMwMjU0M2MxFDASBgNVBAsMC0tERSBDb25uZWN0MQwwCgYDVQQKDANLREUwHhcNMjQwMTE3MjMw",
        "MDAwWhcNMzUwMTE3MjMwMDAwWjBTMS0wKwYDVQQDDCQxNTdiYmMyOF82ZjJiXzRiMTZfYmQwMl8xMzM0NWMw",
        "MjU0M2MxFDASBgNVBAsMC0tERSBDb25uZWN0MQwwCgYDVQQKDANLREUwWTATBgcqhkjOPQIBBggqhkjOPQMB",
        "BwNCAAQ5W53rrDJps9v/sszQf0eLtvoGiRbfsY+snO6IJJfi1pFeHDQj2nAE+aTyUYelrcx1eIuqxFHnJTFt",
        "/HqXwuAvMAoGCCqGSM49BAMEA0gAMEUCIBIk3zKPz/M0c82nvCGFDXGGmfdojHsx3G5DbYNNKqFVAiEAzhBG",
        "e960/4NDiaVcOplBaeg5xNJKs3Kq+22J6JOii4Y="
    ));
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(cert::common_name(&a).unwrap(), "ee061a75_e403_4ecc_9261_5ffe2722f698");
    let (sa, sb) = (cert::spki(&a).unwrap(), cert::spki(&b).unwrap());
    use kdeconnect_proto::pairing::verification_key as key;
    assert_eq!(key(&sa, &sb, 1737228658), "54DC916E");
    assert_eq!(key(&sb, &sa, 1737228658), "54DC916E");
    assert_eq!(key(&sa, &sb, 2737228658), "8C07153A");
}

/// The handheld announces; the PC hears it, connects and is the TLS server; the handheld accepts and is the
/// TLS client. Then they pair, verify the same key, ping, and send a payload.
#[test]
fn discover_link_pair_ping_and_payload() {
    let handheld = device("Retroid Pocket 5", DeviceType::Phone);
    let pc = device("Desktop", DeviceType::Desktop);

    discovery::announce(&handheld.id, handheld.provider.tcp_port(), &[LOOPBACK], pc.provider.udp_port(), false).unwrap();
    let mut on_pc = next_link(&pc);
    let mut on_handheld = next_link(&handheld);
    assert_eq!(on_pc.peer.device_id, handheld.id.device_id);
    assert_eq!(on_pc.peer.device_name, "Retroid Pocket 5");
    assert_eq!(on_handheld.peer.device_id, pc.id.device_id);
    assert_eq!(on_handheld.peer.incoming_capabilities, vec![types::PING.to_string()]);
    assert_eq!(on_pc.peer_cert, handheld.cert.cert_der);
    assert_eq!(on_handheld.peer_cert, pc.cert.cert_der);

    // Pairing: the PC asks, both show the same key, the handheld accepts.
    let now = 1_800_000_000;
    let mut pc_pairing = Pairing::new(false);
    let mut hh_pairing = Pairing::new(false);
    on_pc.send(&pc_pairing.request(now).unwrap()).unwrap();
    let req = recv(&mut on_handheld);
    assert_eq!(req.kind, types::PAIR);
    assert_eq!(hh_pairing.on_packet(&req, now + 1), Some(PairEvent::IncomingRequest));
    let key_pc = verification_key(&pc.cert, &on_pc.peer_cert, pc_pairing.timestamp().unwrap()).unwrap();
    let key_hh = verification_key(&handheld.cert, &on_handheld.peer_cert, hh_pairing.timestamp().unwrap()).unwrap();
    assert_eq!(key_pc, key_hh);
    on_handheld.send(&hh_pairing.accept().unwrap()).unwrap();
    handheld.pins.pin(&pc.id.device_id, on_handheld.peer_cert.clone());
    assert_eq!(pc_pairing.on_packet(&recv(&mut on_pc), now + 2), Some(PairEvent::Paired));
    pc.pins.pin(&handheld.id.device_id, on_pc.peer_cert.clone());

    // A packet each way.
    on_handheld.send(&Packet::new(types::PING).with("message", "hello")).unwrap();
    assert_eq!(recv(&mut on_pc).str("message").as_deref(), Some("hello"));
    on_pc.send(&Packet::new(types::PING)).unwrap();
    assert_eq!(recv(&mut on_handheld).kind, types::PING);

    // A payload, handheld to PC: 1 MiB and a little, so it spans many TLS records and buffers.
    let data: Vec<u8> = (0..(1 << 20) + 12345).map(|i| (i * 7 % 251) as u8).collect();
    let offer = PayloadOffer::open_in(LOOPBACK, 0..=0).unwrap();
    let mut np = Packet::new("kdeconnect.share.request").with("filename", "save.srm");
    offer.attach(&mut np, data.len() as i64);
    on_handheld.send(&np).unwrap();
    let hh_cert = handheld.cert.clone();
    let pin_pc = on_handheld.peer_cert.clone();
    let to_send = data.clone();
    let sender = std::thread::spawn(move || offer.serve(&hh_cert, pin_pc, &mut to_send.as_slice(), to_send.len() as i64, &mut |_| {}));
    let got = recv(&mut on_pc);
    let mut reader = PayloadReader::connect(&got, on_pc.peer_addr.ip(), &pc.cert, on_pc.peer_cert.clone()).unwrap().unwrap();
    let mut received = Vec::new();
    reader.read_to_end(&mut received).unwrap();
    assert_eq!(sender.join().unwrap().unwrap(), data.len() as u64);
    assert_eq!(received, data);
}

/// A paired device that comes back with another certificate is refused by the pin.
#[test]
fn a_changed_certificate_is_refused() {
    let a = device("A", DeviceType::Desktop);
    let b = device("B", DeviceType::Phone);
    let other = DeviceCert::generate(&b.id.device_id).unwrap();
    a.pins.pin(&b.id.device_id, other.cert_der);
    a.provider.connect_direct(SocketAddr::new(LOOPBACK, b.provider.tcp_port()), b.id.clone());
    match a.provider.next_event(Duration::from_secs(20)).unwrap() {
        Event::Failed { .. } => {}
        Event::Linked(_) => panic!("linked to a device whose certificate is not the pinned one"),
    }
}

/// A connection packet naming another device is refused before TLS.
#[test]
fn a_connection_for_another_device_is_refused() {
    let a = device("A", DeviceType::Desktop);
    let b = device("B", DeviceType::Phone);
    let mut wrong = b.id.clone();
    wrong.device_id = new_device_id();
    a.provider.connect_direct(SocketAddr::new(LOOPBACK, b.provider.tcp_port()), wrong);
    match b.provider.next_event(Duration::from_secs(20)).unwrap() {
        Event::Failed { .. } => {}
        Event::Linked(_) => panic!("accepted a connection meant for another device"),
    }
}
