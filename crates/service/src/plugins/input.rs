//! Remote input (kdeconnect-kde `plugins/mousepad`, `plugins/remotekeyboard`; kdeconnect-android
//! `plugins/mousepad`, `plugins/remotekeyboard`, `plugins/mousereceiver`): a pointer and a keyboard, each way.
//!
//! - `kdeconnect.mousepad.request` moves the pointer (`dx`, `dy`, or absolute `x`, `y`), scrolls (`scroll` with
//!   `dy`), clicks (`singleclick`, `doubleclick`, `middleclick`, `rightclick`, `singlehold`, `singlerelease`) or types
//!   (`key`: text; `specialKey`: one of [`SPECIAL_KEYS`]; `shift`, `ctrl`, `alt`, `super`). With `sendAck` the
//!   receiver answers `kdeconnect.mousepad.echo`: the key fields again and `isAck: true`.
//! - `kdeconnect.mousepad.keyboardstate {state}` says whether the sender can take typing now (android: its input
//!   method is the active one; kde: its platform supports it). It is sent on connecting and when it changes.
//! - The service turns a request into [`InputEvent`] for the program, which moves its pointer or types into its
//!   focused field; it builds requests from the program's [`InputEvent`] the other way.

use kdeconnect_proto::Packet;
use serde::{Deserialize, Serialize};

use super::PluginEvent;

pub const REQUEST: &str = "kdeconnect.mousepad.request";
pub const ECHO: &str = "kdeconnect.mousepad.echo";
pub const KEYBOARD_STATE: &str = "kdeconnect.mousepad.keyboardstate";
/// Taken when this device can be controlled; the echo and the keyboard state come back from the device it controls.
pub const INCOMING: &[&str] = &[REQUEST, ECHO, KEYBOARD_STATE];
pub const OUTGOING: &[&str] = &[REQUEST, ECHO, KEYBOARD_STATE];

/// `specialKey` 1..=32, in the order of kde's `SpecialKeysMap` (x11remoteinput.cpp); 0 is none.
pub const SPECIAL_KEYS: [&str; 32] = [
    "backspace",
    "tab",
    "linefeed",
    "left",
    "up",
    "right",
    "down",
    "page_up",
    "page_down",
    "home",
    "end",
    "enter",
    "delete",
    "escape",
    "sysreq",
    "scroll_lock",
    "control",
    "alt",
    "shift",
    "super",
    "f1",
    "f2",
    "f3",
    "f4",
    "f5",
    "f6",
    "f7",
    "f8",
    "f9",
    "f10",
    "f11",
    "f12",
];

pub fn special_key_name(n: i64) -> Option<&'static str> {
    usize::try_from(n).ok().filter(|n| *n >= 1).and_then(|n| SPECIAL_KEYS.get(n - 1).copied())
}

pub fn special_key_number(name: &str) -> Option<i64> {
    SPECIAL_KEYS.iter().position(|k| *k == name).map(|i| i as i64 + 1)
}

/// One pointer or keyboard action, as the program sees it and as it asks for one.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct InputEvent {
    #[serde(default, skip_serializing_if = "is_zero")]
    pub dx: f64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub dy: f64,
    /// Absolute position, when the sender gives one (a presenter's pointer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<f64>,
    /// `dy` is a scroll, not a move.
    #[serde(default, skip_serializing_if = "is_false")]
    pub scroll: bool,
    /// `single`, `double`, `middle`, `right`, `hold` (press and keep) or `release`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub click: Option<String>,
    /// Text to type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// One of [`SPECIAL_KEYS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub special_key: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub shift: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ctrl: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub alt: bool,
    #[serde(default, rename = "super", skip_serializing_if = "is_false")]
    pub super_: bool,
}

fn is_zero(v: &f64) -> bool {
    *v == 0.0
}
fn is_false(v: &bool) -> bool {
    !*v
}

const CLICKS: [(&str, &str); 6] = [
    ("single", "singleclick"),
    ("double", "doubleclick"),
    ("middle", "middleclick"),
    ("right", "rightclick"),
    ("hold", "singlehold"),
    ("release", "singlerelease"),
];

impl InputEvent {
    pub fn from_packet(np: &Packet) -> InputEvent {
        let f = |k: &str| np.body.get(k).and_then(serde_json::Value::as_f64);
        let b = |k: &str| np.bool(k).unwrap_or(false);
        InputEvent {
            dx: f("dx").unwrap_or(0.0),
            dy: f("dy").unwrap_or(0.0),
            x: f("x"),
            y: f("y"),
            scroll: b("scroll"),
            click: CLICKS.iter().find(|(_, field)| b(field)).map(|(name, _)| name.to_string()),
            key: np.str("key").filter(|k| !k.is_empty()),
            special_key: np.int("specialKey").and_then(special_key_name).map(str::to_owned),
            shift: b("shift"),
            ctrl: b("ctrl"),
            alt: b("alt"),
            super_: b("super"),
        }
    }

    pub fn to_packet(&self) -> Packet {
        let mut np = Packet::new(REQUEST);
        if self.dx != 0.0 || self.dy != 0.0 {
            np.set("dx", self.dx);
            np.set("dy", self.dy);
        }
        if let (Some(x), Some(y)) = (self.x, self.y) {
            np.set("x", x);
            np.set("y", y);
        }
        if self.scroll {
            np.set("scroll", true);
        }
        if let Some(field) = self.click.as_deref().and_then(|c| CLICKS.iter().find(|(name, _)| *name == c)).map(|(_, f)| *f) {
            np.set(field, true);
        }
        if let Some(k) = &self.key {
            np.set("key", k.clone());
        }
        if let Some(n) = self.special_key.as_deref().and_then(special_key_number) {
            np.set("specialKey", n);
        }
        for (field, on) in [("shift", self.shift), ("ctrl", self.ctrl), ("alt", self.alt), ("super", self.super_)] {
            if on {
                np.set(field, true);
            }
        }
        np
    }

    /// Whether it does anything (kde ignores a request with no field it knows).
    pub fn is_empty(&self) -> bool {
        *self == InputEvent::default()
    }
}

/// The answer to a request with `sendAck` (android `RemoteKeyboardPlugin.sendAck`).
pub fn echo(np: &Packet) -> Packet {
    let mut reply = Packet::new(ECHO).with("key", np.str("key").unwrap_or_default());
    for field in ["specialKey", "shift", "ctrl", "alt", "super"] {
        if let Some(v) = np.body.get(field) {
            reply.set(field, v.clone());
        }
    }
    reply.with("isAck", true)
}

pub fn keyboard_state(state: bool) -> Packet {
    Packet::new(KEYBOARD_STATE).with("state", state)
}

/// What arrived, and the echo to send back when one was asked for.
pub fn receive(np: &Packet, controlled: bool) -> (Option<PluginEvent>, Option<Packet>) {
    match np.kind.as_str() {
        REQUEST if controlled => {
            let e = InputEvent::from_packet(np);
            if e.is_empty() {
                return (None, None);
            }
            let ack = (np.bool("sendAck") == Some(true)).then(|| echo(np));
            (Some(PluginEvent::Input { input: e }), ack)
        }
        KEYBOARD_STATE => (Some(PluginEvent::KeyboardState { state: np.bool("state").unwrap_or(false) }), None),
        // An echo only says the key arrived; a sender that types blind does not need it.
        _ => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_keys_match_kde() {
        assert_eq!(special_key_name(1), Some("backspace"));
        assert_eq!(special_key_name(12), Some("enter"));
        assert_eq!(special_key_name(32), Some("f12"));
        assert_eq!(special_key_name(0), None);
        assert_eq!(special_key_name(33), None);
        assert_eq!(special_key_number("escape"), Some(14));
    }

    #[test]
    fn packets_round_trip() {
        let e = InputEvent { dx: 3.5, dy: -2.0, click: Some("right".into()), ..Default::default() };
        let np = e.to_packet();
        assert_eq!(np.bool("rightclick"), Some(true));
        assert_eq!(InputEvent::from_packet(&np), e);
        let k = InputEvent { key: Some("a".into()), ctrl: true, ..Default::default() };
        assert_eq!(InputEvent::from_packet(&k.to_packet()), k);
        let s = InputEvent { special_key: Some("enter".into()), ..Default::default() };
        assert_eq!(s.to_packet().int("specialKey"), Some(12));
        let json = serde_json::to_value(&k).unwrap();
        assert_eq!(json, serde_json::json!({"key": "a", "ctrl": true}));
    }

    #[test]
    fn requests_and_echoes() {
        // android's mousepad sends doubles as dx/dy and asks for an ack on typed keys.
        let np = Packet::new(REQUEST).with("key", "x").with("shift", true).with("sendAck", true);
        let (e, ack) = receive(&np, true);
        assert_eq!(e, Some(PluginEvent::Input { input: InputEvent { key: Some("x".into()), shift: true, ..Default::default() } }));
        let ack = ack.unwrap();
        assert_eq!(ack.kind, ECHO);
        assert_eq!(ack.bool("isAck"), Some(true));
        assert_eq!(ack.bool("shift"), Some(true));
        // Not controlled: nothing.
        assert_eq!(receive(&np, false), (None, None));
        assert_eq!(receive(&Packet::new(REQUEST), true), (None, None));
        assert_eq!(receive(&keyboard_state(true), false).0, Some(PluginEvent::KeyboardState { state: true }));
    }
}
