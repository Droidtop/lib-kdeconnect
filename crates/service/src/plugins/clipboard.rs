//! `kdeconnect.clipboard` and `kdeconnect.clipboard.connect` (android `plugins/clipboard/ClipboardPlugin.kt`):
//! a device's clipboard text, sent when it changes, and once more with the time it changed when a paired device
//! links.
//!
//! - `kdeconnect.clipboard {content}`: the other device's clipboard changed; take it.
//! - `kdeconnect.clipboard.connect {content, timestamp}`: sent on connecting. A `timestamp` of 0 means "not known"
//!   and is ignored, as is one older than this device's own clip (android: `packetTime < updateTimestamp`).
//! - What the program puts here (`clipboard_set`) goes to every paired, reachable device, unless it is the text
//!   already held: so text that just arrived and was written to the platform's clipboard is not sent back.
//! - What may leave the device (a clip marked sensitive, a size limit, Android's background-read rule) is the
//!   program's to decide before it calls `clipboard_set`.

use kdeconnect_proto::Packet;

use super::PluginEvent;

pub const TYPE: &str = "kdeconnect.clipboard";
pub const CONNECT: &str = "kdeconnect.clipboard.connect";
pub const INCOMING: &[&str] = &[TYPE, CONNECT];
pub const OUTGOING: &[&str] = &[TYPE, CONNECT];

/// This device's clipboard as the service knows it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Clip {
    pub text: Option<String>,
    /// Milliseconds since 1970 when it last changed; 0 when not known.
    pub changed_ms: i64,
}

impl Clip {
    /// The program's new clip. `false` when it is the text already held (nothing to send).
    pub fn set(&mut self, text: &str, now_ms: i64) -> bool {
        if self.text.as_deref() == Some(text) {
            return false;
        }
        self.text = Some(text.to_owned());
        self.changed_ms = now_ms;
        true
    }

    /// The packet sent on connecting, when there is a clip.
    pub fn connect_packet(&self) -> Option<Packet> {
        let text = self.text.as_ref()?;
        Some(Packet::new(CONNECT).with("content", text.clone()).with("timestamp", self.changed_ms))
    }

    /// A clipboard packet arrived: the event for the program, when it is to be taken.
    pub fn receive(&mut self, np: &Packet, now_ms: i64) -> Option<PluginEvent> {
        let text = np.str("content")?;
        if np.kind == CONNECT {
            let ts = np.int("timestamp").unwrap_or(0);
            if ts == 0 || ts < self.changed_ms {
                return None;
            }
            if self.text.as_deref() == Some(text.as_str()) {
                return None;
            }
            self.text = Some(text.clone());
            self.changed_ms = ts;
        } else {
            if self.text.as_deref() == Some(text.as_str()) {
                return None;
            }
            self.text = Some(text.clone());
            self.changed_ms = now_ms;
        }
        Some(PluginEvent::Clipboard { text })
    }
}

pub fn packet(text: &str) -> Packet {
    Packet::new(TYPE).with("content", text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        let mut c = Clip::default();
        assert!(c.connect_packet().is_none());
        assert!(c.set("a", 100));
        assert!(!c.set("a", 200), "the same text is not sent again");
        assert_eq!(c.connect_packet().unwrap().int("timestamp"), Some(100));

        // An older or unknown connect clip is ignored; a newer one is taken.
        assert_eq!(c.receive(&Packet::new(CONNECT).with("content", "old").with("timestamp", 50), 300), None);
        assert_eq!(c.receive(&Packet::new(CONNECT).with("content", "x").with("timestamp", 0), 300), None);
        assert_eq!(
            c.receive(&Packet::new(CONNECT).with("content", "new").with("timestamp", 150), 300),
            Some(PluginEvent::Clipboard { text: "new".into() })
        );
        // A change is taken, and writing it back to the platform does not send it again.
        assert_eq!(c.receive(&packet("b"), 400), Some(PluginEvent::Clipboard { text: "b".into() }));
        assert!(!c.set("b", 401));
        assert_eq!(c.receive(&packet("b"), 402), None);
    }
}
