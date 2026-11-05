//! Two devices find each other by mDNS alone. Multicast needs a network interface that carries it: where none
//! does (some containers), the test says so and passes, as the broadcast still finds devices there.

use std::sync::mpsc::channel;
use std::time::Duration;

use kdeconnect_link::mdns::Mdns;
use kdeconnect_proto::identity::new_device_id;
use kdeconnect_proto::{DeviceType, Identity};

#[test]
fn two_devices_find_each_other() {
    let a = Identity::new(new_device_id(), "Handheld", DeviceType::Tablet);
    let b = Identity::new(new_device_id(), "Desktop", DeviceType::Desktop);
    let (tx, rx) = channel();
    let Ok(_a) = Mdns::start(&a, 1739, |_| {}) else {
        eprintln!("no mDNS here: skipped");
        return;
    };
    let _b = Mdns::start(&b, 1740, move |h| {
        let _ = tx.send(h);
    })
    .unwrap();
    let end = std::time::Instant::now() + Duration::from_secs(10);
    while let Ok(h) = rx.recv_timeout(end.saturating_duration_since(std::time::Instant::now())) {
        if h.identity.device_id == a.device_id {
            assert_eq!(h.addr.port(), 1739);
            assert_eq!(h.identity.device_name, "Handheld");
            assert_eq!(h.identity.device_type, DeviceType::Tablet);
            assert_eq!(h.identity.protocol_version, 8);
            return;
        }
    }
    if std::env::var_os("CI").is_some() {
        panic!("not found by mDNS within 10 s");
    }
    eprintln!("not found by mDNS here (no multicast?): skipped");
}
