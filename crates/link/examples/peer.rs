//! A KDE Connect device on the command line, for checking the library against the official apps.
//!
//! ```text
//! cargo run -p kdeconnect-link --example peer -- [--name NAME] [--announce IP]... [--pair] [--accept]
//!     [--ping TEXT] [--receive-dir DIR]
//! ```
//!
//! It announces itself (broadcast and to each `--announce` address), prints every device that links, and:
//! `--pair` asks each linked device to pair; `--accept` accepts every pairing request; `--ping` sends a ping
//! once paired; `--receive-dir` stores files shared to it (`kdeconnect.share.request` with a payload).
//! Pairing is kept for the run only.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kdeconnect_link::{verification_key, Config, DeviceCert, Event, Link, LinkProvider, PayloadReader, Trust};
use kdeconnect_proto::identity::new_device_id;
use kdeconnect_proto::pairing::{PairEvent, Pairing};
use kdeconnect_proto::{types, DeviceType, Identity, Packet};

#[derive(Default)]
struct Pins(Mutex<HashMap<String, Vec<u8>>>);
impl Trust for Pins {
    fn pinned(&self, id: &str) -> Option<Vec<u8>> {
        self.0.lock().unwrap().get(id).cloned()
    }
}

struct Extra(Vec<IpAddr>);
impl kdeconnect_link::AddressSource for Extra {
    fn addresses(&self) -> Vec<IpAddr> {
        self.0.clone()
    }
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut name, mut extra, mut pair, mut accept, mut ping, mut dir) = ("droidtop peer".to_string(), vec![], false, false, None, None);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--name" => name = args.next().expect("a name"),
            "--announce" => extra.push(args.next().expect("an address").parse::<IpAddr>().expect("an IP address")),
            "--pair" => pair = true,
            "--accept" => accept = true,
            "--ping" => ping = args.next(),
            "--receive-dir" => dir = args.next(),
            other => panic!("unknown argument {other}"),
        }
    }
    let mut me = Identity::new(new_device_id(), &name, DeviceType::Desktop);
    me.incoming_capabilities = vec![types::PING.into(), "kdeconnect.share.request".into()];
    me.outgoing_capabilities = vec![types::PING.into()];
    let cert = DeviceCert::generate(&me.device_id).expect("a certificate");
    let pins = Arc::new(Pins::default());
    // UDP port 0 when 1716 is taken (an official app on the same machine): it can still be announced to.
    let mut config = Config::default();
    if std::net::UdpSocket::bind(("0.0.0.0", config.udp_port)).is_err() {
        config.udp_port = 0;
    }
    let dest = kdeconnect_proto::UDP_PORT;
    let provider = LinkProvider::start(config, me.clone(), cert.clone(), pins.clone(), Arc::new(Extra(extra.clone()))).expect("listeners");
    println!("me: {} {} tcp {} udp {}", me.device_id, me.device_name, provider.tcp_port(), provider.udp_port());
    kdeconnect_link::discovery::announce(&me, provider.tcp_port(), &extra, dest, true).expect("announce");

    loop {
        let link = match provider.events().recv_timeout(Duration::from_secs(5)) {
            Ok(Event::Linked(l)) => *l,
            Ok(Event::Failed { addr, error }) => {
                println!("handshake with {addr} failed: {error}");
                continue;
            }
            Err(_) => {
                kdeconnect_link::discovery::announce(&me, provider.tcp_port(), &extra, dest, true).ok();
                continue;
            }
        };
        println!(
            "linked: {} {:?} {} at {} (paired: {})",
            link.peer.device_id,
            link.peer.device_type,
            link.peer.device_name,
            link.peer_addr,
            pins.pinned(&link.peer.device_id).is_some()
        );
        let (cert, pins, ping, dir) = (cert.clone(), pins.clone(), ping.clone(), dir.clone());
        std::thread::spawn(move || serve(link, cert, pins, pair, accept, ping, dir));
    }
}

fn serve(mut link: Link, cert: DeviceCert, pins: Arc<Pins>, pair: bool, accept: bool, ping: Option<String>, dir: Option<String>) {
    let id = link.peer.device_id.clone();
    let mut pairing = Pairing::new(pins.pinned(&id).is_some());
    let paired = |pins: &Pins, link: &mut Link| {
        pins.0.lock().unwrap().insert(id.clone(), link.peer_cert.clone());
        println!("paired with {id}");
        if let Some(p) = &ping {
            link.send(&Packet::new(types::PING).with("message", p.clone())).unwrap();
            println!("sent ping {p:?}");
        }
    };
    if pair {
        if let Some(np) = pairing.request(now()) {
            link.send(&np).unwrap();
            println!("asked to pair; key {}", verification_key(&cert, &link.peer_cert, pairing.timestamp().unwrap()).unwrap());
        }
    }
    link.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    loop {
        if let Some(e) = pairing.tick(now()) {
            println!("pairing: {e:?}");
        }
        let np = match link.recv() {
            Ok(Some(np)) => np,
            Ok(None) => continue,
            Err(e) => {
                println!("link to {} ended: {e}", link.peer.device_id);
                return;
            }
        };
        println!("packet: {} {}", np.kind, serde_json::Value::Object(np.body.clone()));
        match np.kind.as_str() {
            types::PAIR => match pairing.on_packet(&np, now()) {
                Some(PairEvent::IncomingRequest) => {
                    println!("pair request; key {}", verification_key(&cert, &link.peer_cert, pairing.timestamp().unwrap()).unwrap());
                    if accept {
                        link.send(&pairing.accept().unwrap()).unwrap();
                        paired(&pins, &mut link);
                    }
                }
                Some(PairEvent::Paired) => paired(&pins, &mut link),
                Some(PairEvent::Unpaired) => {
                    pins.0.lock().unwrap().remove(&link.peer.device_id);
                    println!("unpaired");
                }
                e => println!("pairing: {e:?}"),
            },
            "kdeconnect.share.request" if np.payload_port().is_some() => {
                let Some(dir) = &dir else { continue };
                let Some(pin) = pins.pinned(&link.peer.device_id) else { continue };
                let name = np.str("filename").unwrap_or_else(|| "file".into());
                let name = std::path::Path::new(&name).file_name().map(|n| n.to_owned()).unwrap_or_else(|| "file".into());
                let path = std::path::Path::new(dir).join(name);
                match PayloadReader::connect(&np, link.peer_addr.ip(), &cert, pin) {
                    Ok(Some(mut r)) => {
                        let mut f = std::fs::File::create(&path).unwrap();
                        let n = std::io::copy(&mut r, &mut f);
                        println!("received {} : {n:?}", path.display());
                    }
                    other => println!("payload failed: {:?}", other.err()),
                }
            }
            _ => {}
        }
    }
}
