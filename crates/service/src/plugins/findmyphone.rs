//! `kdeconnect.findmyphone.request` (kdeconnect-kde `plugins/findmyphone`, kdeconnect-android
//! `plugins/findmyphone`): "ring": the receiver plays a loud sound until the person stops it. An empty body.

use kdeconnect_proto::Packet;

pub const TYPE: &str = "kdeconnect.findmyphone.request";
pub const INCOMING: &[&str] = &[TYPE];
pub const OUTGOING: &[&str] = &[TYPE];

pub fn packet() -> Packet {
    Packet::new(TYPE)
}
