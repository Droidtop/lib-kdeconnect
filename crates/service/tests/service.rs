//! Two services over loopback: found by an extra address, paired from one side, ping each way, the pairing
//! kept on disk across a restart, and unpairing.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use kdeconnect_link::Config;
use kdeconnect_proto::DeviceType;
use kdeconnect_service::plugins::{Enabled, PluginEvent};
use kdeconnect_service::{Service, ServiceEvent, Settings};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kdc-svc-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn start(name: &str, state: PathBuf, peer_udp_port: u16) -> Service {
    let link = Config { bind: LOOPBACK, udp_port: 0, tcp_ports: 0..=0, peer_tcp_ports: 1..=u16::MAX, peer_udp_port, broadcast: false };
    let s = Service::start(Settings {
        name: name.into(),
        device_type: DeviceType::Desktop,
        state_dir: state,
        link,
        plugins: Enabled::default(),
    })
    .unwrap();
    s.set_extra_addresses(vec![LOOPBACK]);
    s
}

fn wait(s: &Service, what: &str, f: impl Fn(&ServiceEvent) -> bool) -> ServiceEvent {
    let end = Instant::now() + Duration::from_secs(20);
    while Instant::now() < end {
        if let Some(e) = s.next_event(Duration::from_millis(200)) {
            if f(&e) {
                return e;
            }
        }
    }
    panic!("no {what} event");
}

#[test]
fn pair_ping_restart_unpair() {
    let (da, db) = (dir("a"), dir("b"));
    let b = start("Handheld", db.clone(), 0);
    let a = start("Desktop", da.clone(), b.udp_port());
    a.announce().unwrap();
    let a_id = a.identity().device_id.clone();
    let b_id = b.identity().device_id.clone();
    wait(&a, "reachable", |e| matches!(e, ServiceEvent::Reachable { device } if device.id == b_id));
    wait(&b, "reachable", |e| matches!(e, ServiceEvent::Reachable { device } if device.id == a_id));

    // Pinging before pairing reaches nothing.
    assert!(a.ping(&b_id, Some("early")).is_err());

    a.pair(&b_id).unwrap();
    let ServiceEvent::PairRequest { key, .. } = wait(&b, "pair request", |e| matches!(e, ServiceEvent::PairRequest { .. })) else {
        unreachable!()
    };
    let shown_on_a = a.devices().into_iter().find(|d| d.id == b_id).unwrap().verification_key.unwrap();
    assert_eq!(key, shown_on_a);
    b.accept(&a_id).unwrap();
    wait(&b, "paired", |e| matches!(e, ServiceEvent::Paired { .. }));
    wait(&a, "paired", |e| matches!(e, ServiceEvent::Paired { .. }));

    b.ping(&a_id, Some("hello")).unwrap();
    let e = wait(&a, "ping", |e| matches!(e, ServiceEvent::Plugin { .. }));
    assert_eq!(e, ServiceEvent::Plugin { id: b_id.clone(), plugin: PluginEvent::Ping { message: Some("hello".into()) } });
    let json = serde_json::to_value(&e).unwrap();
    assert_eq!(json["event"], "plugin");
    assert_eq!(json["plugin"]["plugin"], "ping");

    // Restart A: it still knows B as paired, with B's address remembered, and links again.
    drop(a);
    let a = start("Desktop", da.clone(), b.udp_port());
    assert_eq!(a.identity().device_id, a_id);
    let known = a.devices();
    assert!(known.iter().any(|d| d.id == b_id && d.paired && !d.reachable));
    a.announce().unwrap();
    wait(&a, "reachable again", |e| matches!(e, ServiceEvent::Reachable { device } if device.id == b_id && device.paired));
    a.ping(&b_id, None).unwrap();
    wait(&b, "ping after restart", |e| matches!(e, ServiceEvent::Plugin { .. }));

    a.unpair(&b_id).unwrap();
    wait(&b, "unpaired", |e| matches!(e, ServiceEvent::Unpaired { .. }));
    assert!(!a.devices().iter().any(|d| d.id == b_id && d.paired));
    let _ = std::fs::remove_dir_all(&da);
    let _ = std::fs::remove_dir_all(&db);
}

/// The JSON operations the JNI and Python layers pass through.
#[test]
fn json_operations() {
    use kdeconnect_service::ops::call_with;
    use serde_json::json;
    let d = dir("ops");
    let cfg = || Config { bind: LOOPBACK, udp_port: 0, tcp_ports: 0..=0, peer_tcp_ports: 1..=u16::MAX, peer_udp_port: 0, broadcast: false };
    assert!(call_with("devices", &json!({}), cfg())["error"].is_string());
    let started = call_with("start", &json!({"state_dir": d, "name": "Pocket: 5", "type": "phone"}), cfg());
    assert_eq!(started["name"], "Pocket 5");
    assert_eq!(call_with("start", &json!({"state_dir": d}), cfg())["id"], started["id"]);
    assert_eq!(call_with("devices", &json!({}), cfg())["devices"], json!([]));
    assert_eq!(call_with("event", &json!({"timeout_ms": 10}), cfg())["event"], "none");
    assert_eq!(call_with("addresses", &json!({"addresses": ["100.101.102.103", "not an ip"]}), cfg()), json!({}));
    assert!(call_with("pair", &json!({"id": "nobody"}), cfg())["error"].is_string());
    assert!(call_with("nope", &json!({}), cfg())["error"].is_string());
    assert_eq!(call_with("stop", &json!({}), cfg()), json!({}));
    let _ = std::fs::remove_dir_all(&d);
}
