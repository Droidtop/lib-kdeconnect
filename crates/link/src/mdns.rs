//! Discovery by mDNS / DNS-SD, beside the UDP broadcast, as both official apps do (kdeconnect-kde
//! `core/backends/lan/mdnshdiscovery.cpp` and `avahidiscovery.cpp`, kdeconnect-android `backends/lan/MdnsDiscovery.kt`):
//! a network that drops broadcasts often still carries multicast DNS.
//!
//! - This device is published as `<device id>._kdeconnect._udp.local.` on its TCP port, with the TXT records
//!   `id`, `name`, `type` and `protocol` (avahidiscovery.cpp `txtRecords`).
//! - A device found is connected to at its address and port, as a heard UDP announcement is (kde
//!   `LanLinkProvider::deviceDiscovered`).
//! - The protocol work is the `mdns-sd` crate's (owner, 2026-11-05: "No need to reinvent wheels").
//!
//! On Android the program holds a Wi-Fi multicast lock while this runs (`WifiManager.MulticastLock`), or the
//! radio drops multicast.

use std::net::{IpAddr, SocketAddr};

use kdeconnect_proto::{DeviceType, Identity, PROTOCOL_VERSION};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::discovery::Heard;

pub const SERVICE_TYPE: &str = "_kdeconnect._udp.local.";

/// The running publisher and browser. Dropping it withdraws this device and stops browsing.
pub struct Mdns {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Mdns {
    /// Publishes `me` on `tcp_port` and calls `found` for every other KDE Connect device that appears, from the
    /// browser's own thread.
    pub fn start(me: &Identity, tcp_port: u16, found: impl Fn(Heard) + Send + 'static) -> Result<Mdns, mdns_sd::Error> {
        let daemon = ServiceDaemon::new()?;
        let props =
            [("id", me.device_id.as_str()), ("name", me.device_name.as_str()), ("type", me.device_type.as_str()), ("protocol", "8")];
        let host = format!("{}.local.", me.device_id);
        let info = ServiceInfo::new(SERVICE_TYPE, &me.device_id, &host, "", tcp_port, &props[..])?.enable_addr_auto();
        let fullname = info.get_fullname().to_owned();
        daemon.register(info)?;
        let events = daemon.browse(SERVICE_TYPE)?;
        let my_id = me.device_id.clone();
        std::thread::Builder::new()
            .name("kdeconnect-mdns".into())
            .spawn(move || {
                while let Ok(event) = events.recv() {
                    let ServiceEvent::ServiceResolved(s) = event else { continue };
                    let id = s
                        .get_property_val_str("id")
                        .map(str::to_owned)
                        .unwrap_or_else(|| s.get_fullname().split('.').next().unwrap_or("").to_owned());
                    if id == my_id || !kdeconnect_proto::identity::is_valid_device_id(&id) {
                        continue;
                    }
                    let protocol = s.get_property_val_str("protocol").and_then(|p| p.parse().ok()).unwrap_or(0);
                    if protocol < PROTOCOL_VERSION {
                        continue;
                    }
                    // IPv4 first, as kde's resolvers hand the address they reached.
                    let mut addrs: Vec<IpAddr> = s.get_addresses().iter().map(|a| a.to_ip_addr()).collect();
                    addrs.sort_by_key(|a| a.is_ipv6());
                    let Some(ip) = addrs.into_iter().next() else { continue };
                    let mut identity = Identity::new(
                        id,
                        s.get_property_val_str("name").unwrap_or("KDE Connect"),
                        DeviceType::parse(s.get_property_val_str("type").unwrap_or("desktop")),
                    );
                    identity.protocol_version = protocol;
                    identity.tcp_port = Some(s.get_port());
                    found(Heard { identity, addr: SocketAddr::new(ip, s.get_port()) });
                }
            })
            .map_err(|e| mdns_sd::Error::Msg(e.to_string()))?;
        Ok(Mdns { daemon, fullname })
    }
}

impl Drop for Mdns {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}
