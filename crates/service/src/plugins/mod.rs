//! The plugins: what each one sends and what an arriving packet becomes. Each can be switched off; a
//! plugin that is off is neither advertised in the identity's capabilities nor answered.

pub mod battery;
pub mod clipboard;
pub mod findmyphone;
pub mod input;
pub mod notifications;
pub mod ping;
pub mod share;

use kdeconnect_proto::Packet;
use serde::Serialize;

/// Which plugins are on. All are on by default; the program offers a switch for each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enabled {
    pub ping: bool,
    pub share: bool,
    pub clipboard: bool,
    /// Paired devices may move this device's pointer and type into it.
    pub input: bool,
    pub battery: bool,
    pub findmyphone: bool,
    pub notifications: bool,
}

impl Enabled {
    /// Switches one plugin by its name; unknown names are ignored.
    pub fn set(&mut self, name: &str, on: bool) {
        match name {
            "ping" => self.ping = on,
            "share" => self.share = on,
            "clipboard" => self.clipboard = on,
            "input" => self.input = on,
            "battery" => self.battery = on,
            "findmyphone" => self.findmyphone = on,
            "notifications" => self.notifications = on,
            _ => {}
        }
    }
}

impl Default for Enabled {
    fn default() -> Self {
        Enabled { ping: true, share: true, clipboard: true, input: true, battery: true, findmyphone: true, notifications: true }
    }
}

/// What a packet from a paired device became.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "plugin", rename_all = "snake_case")]
pub enum PluginEvent {
    /// `kdeconnect.ping`: show it (a notification with the message, or "Ping!").
    Ping { message: Option<String> },
    /// A link to open.
    ShareUrl { url: String },
    /// A text to show, with Copy.
    ShareText { text: String },
    /// A file started arriving; `size` in bytes when the sender said.
    FileReceiving { name: String, size: Option<i64> },
    /// It arrived whole at `path`. `open`: the sender asked to open it.
    FileReceived { name: String, path: String, size: u64, open: bool },
    /// It did not arrive; nothing of it is kept.
    FileFailed { name: String, why: String },
    /// A file this device sent arrived at the other.
    FileSent { name: String, size: u64 },
    /// The other device's clipboard: put it on this one's.
    Clipboard { text: String },
    /// A paired device moves the pointer or types: do it.
    Input { input: input::InputEvent },
    /// The device this one controls can take typing now, or not.
    KeyboardState { state: bool },
    /// The other device's battery.
    Battery { charge: i64, charging: bool, low: bool },
    /// Ring: play a loud sound until the person stops it.
    Ring,
    /// Show (or update) the other device's notification `key`.
    Notification { key: String, app: String, title: String, text: String, dismissable: bool, silent: bool },
    /// The other device's notification `key` is gone.
    NotificationGone { key: String },
    /// A file this device sent did not get there.
    FileSendFailed { name: String, why: String },
}

/// The packet types this device takes.
pub fn incoming(on: &Enabled) -> Vec<String> {
    let mut v = Vec::new();
    if on.ping {
        v.extend(ping::INCOMING.iter().map(|s| s.to_string()));
    }
    if on.share {
        v.extend(share::INCOMING.iter().map(|s| s.to_string()));
    }
    if on.clipboard {
        v.extend(clipboard::INCOMING.iter().map(|s| s.to_string()));
    }
    if on.battery {
        v.extend(battery::INCOMING.iter().map(|s| s.to_string()));
    }
    if on.findmyphone {
        v.extend(findmyphone::INCOMING.iter().map(|s| s.to_string()));
    }
    if on.notifications {
        v.extend(notifications::INCOMING.iter().map(|s| s.to_string()));
    }
    if on.input {
        v.extend(input::INCOMING.iter().map(|s| s.to_string()));
    } else {
        // Controlling others still needs their echo and keyboard state.
        v.extend([input::ECHO, input::KEYBOARD_STATE].iter().map(|s| s.to_string()));
    }
    v
}

/// The packet types this device sends.
pub fn outgoing(on: &Enabled) -> Vec<String> {
    let mut v = Vec::new();
    if on.ping {
        v.extend(ping::OUTGOING.iter().map(|s| s.to_string()));
    }
    if on.share {
        v.extend(share::OUTGOING.iter().map(|s| s.to_string()));
    }
    if on.clipboard {
        v.extend(clipboard::OUTGOING.iter().map(|s| s.to_string()));
    }
    if on.battery {
        v.extend(battery::OUTGOING.iter().map(|s| s.to_string()));
    }
    if on.findmyphone {
        v.extend(findmyphone::OUTGOING.iter().map(|s| s.to_string()));
    }
    if on.notifications {
        v.extend(notifications::OUTGOING.iter().map(|s| s.to_string()));
    }
    v.extend(input::OUTGOING.iter().map(|s| s.to_string()));
    v
}

/// A packet from a paired device. Unknown types and plugins that are off give nothing.
pub fn receive(on: &Enabled, np: &Packet, share_ctx: impl FnOnce() -> share::Incoming) -> Vec<PluginEvent> {
    match np.kind.as_str() {
        ping::TYPE if on.ping => vec![ping::receive(np)],
        share::REQUEST | share::UPDATE if on.share => share::receive(np, share_ctx()),
        battery::TYPE if on.battery => battery::receive(np).into_iter().collect(),
        findmyphone::TYPE if on.findmyphone => vec![PluginEvent::Ring],
        notifications::TYPE if on.notifications => notifications::receive(np).into_iter().collect(),
        _ => Vec::new(),
    }
}
