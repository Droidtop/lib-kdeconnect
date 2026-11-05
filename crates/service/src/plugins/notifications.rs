//! `kdeconnect.notification` (kdeconnect-kde `plugins/notifications/notification.cpp`,
//! `notificationsplugin.cpp`; kdeconnect-android `plugins/notifications`): another device's notifications, shown
//! here. `{id, appName, title, text, ticker, isClearable, silent, ...}` posts or updates one; `{id, isCancel: true}`
//! takes it away. This device dismisses one with `kdeconnect.notification.request {cancel: id}` and asks for all
//! with `{request: true}`. Icons (a payload with `payloadHash`) are not fetched.
//!
//! The other way, this device's own notifications ([`Outgoing`]) go out in the same packet, as kdeconnect-android's
//! `NotificationsPlugin.sendNotification` sends them (`id`, `appName`, `title`, `text`, `ticker`, `isClearable`,
//! `time`, `silent`), and a paired device's `request` asks for all of them or dismisses one here.

use kdeconnect_proto::Packet;

use super::PluginEvent;

pub const TYPE: &str = "kdeconnect.notification";
pub const REQUEST: &str = "kdeconnect.notification.request";
pub const INCOMING: &[&str] = &[TYPE, REQUEST];
pub const OUTGOING: &[&str] = &[REQUEST, TYPE];

/// One of this device's notifications, as the program gives it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Outgoing {
    /// Stable while the notification lives: an update and its cancel use the same key.
    pub key: String,
    pub app: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub text: String,
    /// The person may dismiss it from the other device.
    #[serde(default)]
    pub dismissable: bool,
    /// An update the other device shows without sound.
    #[serde(default)]
    pub silent: bool,
    /// When it was posted, in milliseconds since 1970.
    #[serde(default)]
    pub time: i64,
}

impl Outgoing {
    pub fn packet(&self) -> Packet {
        let ticker = match (self.title.is_empty(), self.text.is_empty()) {
            (false, false) => format!("{}: {}", self.title, self.text),
            (false, true) => self.title.clone(),
            _ => self.text.clone(),
        };
        Packet::new(TYPE)
            .with("id", self.key.as_str())
            .with("appName", self.app.as_str())
            .with("title", self.title.as_str())
            .with("text", self.text.as_str())
            .with("ticker", ticker)
            .with("isClearable", self.dismissable)
            .with("time", self.time.to_string())
            .with("silent", self.silent)
    }
}

/// This device's notification `key` is gone.
pub fn cancel(key: &str) -> Packet {
    Packet::new(TYPE).with("id", key).with("isCancel", true)
}

/// What a paired device's `kdeconnect.notification.request` asks of this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Send every notification this device shows.
    All,
    /// The person dismissed this device's notification `key` there.
    Dismiss(String),
}

pub fn request(np: &Packet) -> Option<Request> {
    if np.bool("request") == Some(true) {
        return Some(Request::All);
    }
    np.str("cancel").map(Request::Dismiss)
}

pub fn receive(np: &Packet) -> Option<PluginEvent> {
    let id = np.str("id")?;
    if np.bool("isCancel") == Some(true) {
        return Some(PluginEvent::NotificationGone { key: id });
    }
    Some(PluginEvent::Notification {
        key: id,
        app: np.str("appName").unwrap_or_default(),
        title: np.str("title").unwrap_or_default(),
        text: np.str("text").or_else(|| np.str("ticker")).unwrap_or_default(),
        dismissable: np.bool("isClearable").unwrap_or(false),
        silent: np.bool("silent").unwrap_or(false),
    })
}

pub fn request_all() -> Packet {
    Packet::new(REQUEST).with("request", true)
}

pub fn dismiss(key: &str) -> Packet {
    Packet::new(REQUEST).with("cancel", key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_and_cancel() {
        let np = Packet::new(TYPE)
            .with("id", "0|com.x|1")
            .with("appName", "Messages")
            .with("title", "Ana")
            .with("ticker", "hi")
            .with("isClearable", true);
        assert_eq!(
            receive(&np),
            Some(PluginEvent::Notification {
                key: "0|com.x|1".into(),
                app: "Messages".into(),
                title: "Ana".into(),
                text: "hi".into(),
                dismissable: true,
                silent: false
            })
        );
        let gone = Packet::new(TYPE).with("id", "0|com.x|1").with("isCancel", true);
        assert_eq!(receive(&gone), Some(PluginEvent::NotificationGone { key: "0|com.x|1".into() }));
        assert_eq!(dismiss("k").str("cancel").as_deref(), Some("k"));
    }

    #[test]
    fn outgoing_as_android_sends_it() {
        let n = Outgoing {
            key: "0|org.app|7|null|10123".into(),
            app: "Messages".into(),
            title: "Ana".into(),
            text: "On my way".into(),
            dismissable: true,
            silent: false,
            time: 1_700_000_000_000,
        };
        let np = n.packet();
        assert_eq!(np.kind, TYPE);
        assert_eq!(np.str("id").as_deref(), Some("0|org.app|7|null|10123"));
        assert_eq!(np.str("ticker").as_deref(), Some("Ana: On my way"));
        assert_eq!(np.str("time").as_deref(), Some("1700000000000"));
        assert_eq!(np.bool("isClearable"), Some(true));
        // What this device sends, it reads back the same way.
        assert_eq!(
            receive(&np),
            Some(PluginEvent::Notification {
                key: n.key.clone(),
                app: "Messages".into(),
                title: "Ana".into(),
                text: "On my way".into(),
                dismissable: true,
                silent: false
            })
        );
        assert_eq!(receive(&cancel(&n.key)), Some(PluginEvent::NotificationGone { key: n.key }));
    }

    #[test]
    fn requests() {
        assert_eq!(request(&request_all()), Some(Request::All));
        assert_eq!(request(&dismiss("k")), Some(Request::Dismiss("k".into())));
        assert_eq!(request(&Packet::new(REQUEST)), None);
    }
}
