//! The plugins: what each one sends and what an arriving packet becomes. Each can be switched off; a
//! plugin that is off is neither advertised in the identity's capabilities nor answered.

pub mod ping;

use kdeconnect_link::{DeviceCert, Link};
use kdeconnect_proto::Packet;
use serde::Serialize;

/// Which plugins are on. All are on by default; the program offers a switch for each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enabled {
    pub ping: bool,
}

impl Default for Enabled {
    fn default() -> Self {
        Enabled { ping: true }
    }
}

/// What a packet from a paired device became.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "plugin", rename_all = "snake_case")]
pub enum PluginEvent {
    /// `kdeconnect.ping`: show it (a notification with the message, or "Ping!").
    Ping { message: Option<String> },
}

/// The packet types this device takes.
pub fn incoming(on: &Enabled) -> Vec<String> {
    let mut v = Vec::new();
    if on.ping {
        v.extend(ping::INCOMING.iter().map(|s| s.to_string()));
    }
    v
}

/// The packet types this device sends.
pub fn outgoing(on: &Enabled) -> Vec<String> {
    let mut v = Vec::new();
    if on.ping {
        v.extend(ping::OUTGOING.iter().map(|s| s.to_string()));
    }
    v
}

/// A packet from a paired device. Unknown types and plugins that are off give nothing.
pub fn receive(on: &Enabled, np: &Packet, _link: &Link, _cert: &DeviceCert) -> Vec<PluginEvent> {
    match np.kind.as_str() {
        ping::TYPE if on.ping => vec![ping::receive(np)],
        _ => Vec::new(),
    }
}
