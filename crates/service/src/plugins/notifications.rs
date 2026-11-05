//! `kdeconnect.notification` (kdeconnect-kde `plugins/notifications/notification.cpp`,
//! `notificationsplugin.cpp`; kdeconnect-android `plugins/notifications`): another device's notifications, shown
//! here. `{id, appName, title, text, ticker, isClearable, silent, ...}` posts or updates one; `{id, isCancel: true}`
//! takes it away. This device dismisses one with `kdeconnect.notification.request {cancel: id}` and asks for all
//! with `{request: true}`. Icons (a payload with `payloadHash`) are not fetched.

use kdeconnect_proto::Packet;

use super::PluginEvent;

pub const TYPE: &str = "kdeconnect.notification";
pub const REQUEST: &str = "kdeconnect.notification.request";
pub const INCOMING: &[&str] = &[TYPE];
pub const OUTGOING: &[&str] = &[REQUEST];

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
}
