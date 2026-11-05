//! `kdeconnect.ping` (android `plugins/ping/PingPlugin.kt`): a packet with an optional `message`.

use kdeconnect_proto::Packet;

use super::PluginEvent;

pub const TYPE: &str = kdeconnect_proto::types::PING;
pub const INCOMING: &[&str] = &[TYPE];
pub const OUTGOING: &[&str] = &[TYPE];

pub fn packet(message: Option<&str>) -> Packet {
    let np = Packet::new(TYPE);
    match message {
        Some(m) => np.with("message", m),
        None => np,
    }
}

pub fn receive(np: &Packet) -> PluginEvent {
    PluginEvent::Ping { message: np.str("message") }
}
