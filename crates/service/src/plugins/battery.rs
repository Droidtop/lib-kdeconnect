//! `kdeconnect.battery` (kdeconnect-kde `plugins/battery/batteryplugin.cpp`, kdeconnect-android
//! `plugins/battery`): a device's charge and whether it charges, sent on connecting and when it changes.
//! `{currentCharge: 0..100, isCharging, thresholdEvent: 0 none | 1 low}`; kde also sends `batteryQuantity`.
//! A charge of -1 means no battery.

use kdeconnect_proto::Packet;
use serde::Serialize;

use super::PluginEvent;

pub const TYPE: &str = "kdeconnect.battery";
pub const REQUEST: &str = "kdeconnect.battery.request";
pub const INCOMING: &[&str] = &[TYPE, REQUEST];
pub const OUTGOING: &[&str] = &[TYPE, REQUEST];

/// Below this the battery counts as low (kde and android: 15 %, `thresholdEvent` 1).
pub const LOW: i64 = 15;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct Battery {
    pub charge: i64,
    pub charging: bool,
}

impl Battery {
    pub fn packet(&self) -> Packet {
        let low = !self.charging && self.charge >= 0 && self.charge <= LOW;
        Packet::new(TYPE)
            .with("currentCharge", self.charge)
            .with("isCharging", self.charging)
            .with("thresholdEvent", i64::from(low))
            .with("batteryQuantity", i64::from(self.charge >= 0))
    }
}

pub fn receive(np: &Packet) -> Option<PluginEvent> {
    if np.kind != TYPE {
        return None; // a request is answered by the service with this device's state
    }
    Some(PluginEvent::Battery {
        charge: np.int("currentCharge").unwrap_or(-1),
        charging: np.bool("isCharging").unwrap_or(false),
        low: np.int("thresholdEvent") == Some(1),
    })
}
