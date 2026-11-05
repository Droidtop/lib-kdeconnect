//! Who a device is: the identity packet and its rules (android `DeviceInfo.kt`, kde `core/deviceinfo.h`).

use crate::packet::Packet;
use crate::{types, PROTOCOL_VERSION};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Desktop,
    Laptop,
    Phone,
    Tablet,
    Tv,
}

impl DeviceType {
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceType::Desktop => "desktop",
            DeviceType::Laptop => "laptop",
            DeviceType::Phone => "phone",
            DeviceType::Tablet => "tablet",
            DeviceType::Tv => "tv",
        }
    }

    /// Unknown names read as desktop, as android does (`getString("deviceType", "desktop")`). kde also
    /// accepts the older "smartphone".
    pub fn parse(s: &str) -> Self {
        match s {
            "laptop" => DeviceType::Laptop,
            "phone" | "smartphone" => DeviceType::Phone,
            "tablet" => DeviceType::Tablet,
            "tv" => DeviceType::Tv,
            _ => DeviceType::Desktop,
        }
    }
}

/// An identity packet's contents. The same packet is used, with different optional fields, for the UDP
/// announcement (`tcp_port`), the plain-text connection packet (`target_*`) and the identity sent again
/// over TLS (neither).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub device_id: String,
    pub device_name: String,
    pub device_type: DeviceType,
    pub protocol_version: i64,
    pub incoming_capabilities: Vec<String>,
    pub outgoing_capabilities: Vec<String>,
    pub tcp_port: Option<u16>,
    pub target_device_id: Option<String>,
    pub target_protocol_version: Option<i64>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("not an identity packet")]
    NotIdentity,
    #[error("device id is not 32 to 38 of [A-Za-z0-9_-]")]
    BadDeviceId,
    #[error("device name is empty once filtered")]
    NoName,
}

impl Identity {
    /// This device's identity: protocol version 8, the capabilities it handles.
    pub fn new(device_id: String, device_name: &str, device_type: DeviceType) -> Self {
        Identity {
            device_id,
            device_name: filter_name(device_name),
            device_type,
            protocol_version: PROTOCOL_VERSION,
            incoming_capabilities: Vec::new(),
            outgoing_capabilities: Vec::new(),
            tcp_port: None,
            target_device_id: None,
            target_protocol_version: None,
        }
    }

    /// The full identity packet. android sends the full identity even over UDP, and kde's minimal UDP packet
    /// is a subset of it, so the one packet satisfies both (README, "Discovery").
    pub fn to_packet(&self) -> Packet {
        let mut np = Packet::new(types::IDENTITY)
            .with("deviceId", self.device_id.clone())
            .with("deviceName", self.device_name.clone())
            .with("deviceType", self.device_type.as_str())
            .with("protocolVersion", self.protocol_version)
            .with("incomingCapabilities", self.incoming_capabilities.clone())
            .with("outgoingCapabilities", self.outgoing_capabilities.clone());
        if let Some(p) = self.tcp_port {
            np.set("tcpPort", p);
        }
        if let Some(t) = &self.target_device_id {
            np.set("targetDeviceId", t.clone());
        }
        if let Some(v) = self.target_protocol_version {
            np.set("targetProtocolVersion", v);
        }
        np
    }

    /// The UDP announcement: the identity and the port of this device's TCP listener.
    pub fn announcement(&self, tcp_port: u16) -> Packet {
        Identity { tcp_port: Some(tcp_port), target_device_id: None, target_protocol_version: None, ..self.clone() }.to_packet()
    }

    /// The plain-text packet sent on a TCP connection this device opened after hearing `peer`'s announcement:
    /// it names the device and version it expects to reach (kde `toConnectionPacket`).
    pub fn connection_packet(&self, peer: &Identity) -> Packet {
        Identity {
            tcp_port: None,
            target_device_id: Some(peer.device_id.clone()),
            target_protocol_version: Some(peer.protocol_version),
            ..self.clone()
        }
        .to_packet()
    }

    /// The identity sent over TLS once the handshake is done.
    pub fn secure_packet(&self) -> Packet {
        Identity { tcp_port: None, target_device_id: None, target_protocol_version: None, ..self.clone() }.to_packet()
    }

    /// Reads an identity packet, with android's `isValidIdentityPacket` rules: the type, a valid device id
    /// and a name that is not empty once filtered. A packet without a name (kde's minimal UDP packet has
    /// one only "to pass validation on older implementations") is read with `require_name = false`.
    pub fn from_packet(np: &Packet, require_name: bool) -> Result<Self, IdentityError> {
        if np.kind != types::IDENTITY {
            return Err(IdentityError::NotIdentity);
        }
        let device_id = np.str("deviceId").unwrap_or_default();
        if !is_valid_device_id(&device_id) {
            return Err(IdentityError::BadDeviceId);
        }
        let device_name = filter_name(&np.str("deviceName").unwrap_or_default());
        if require_name && device_name.trim().is_empty() {
            return Err(IdentityError::NoName);
        }
        Ok(Identity {
            device_id,
            device_name,
            device_type: DeviceType::parse(&np.str("deviceType").unwrap_or_default()),
            protocol_version: np.int("protocolVersion").unwrap_or(0),
            incoming_capabilities: np.strings("incomingCapabilities"),
            outgoing_capabilities: np.strings("outgoingCapabilities"),
            tcp_port: np.int("tcpPort").and_then(|p| u16::try_from(p).ok()),
            target_device_id: np.str("targetDeviceId"),
            target_protocol_version: np.int("targetProtocolVersion"),
        })
    }
}

/// A new device id: a random UUID without dashes, 32 lower-case hex digits (android
/// `DeviceHelper.initializeDeviceId`; kde also uses a bare 128-bit UUID).
pub fn new_device_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// `^[a-zA-Z0-9_-]{32,38}$` (both apps' `isValidDeviceId`). Older devices used UUIDs with underscores.
pub fn is_valid_device_id(id: &str) -> bool {
    (32..=38).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Drops `"',;:.!?()[]<>` and keeps at most 32 characters (both apps' `filterName`).
pub fn filter_name(name: &str) -> String {
    name.chars().filter(|c| !"\"',;:.!?()[]<>".contains(*c)).take(32).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> Identity {
        let mut i = Identity::new(new_device_id(), "Retroid: Pocket 5!", DeviceType::Phone);
        i.incoming_capabilities = vec!["kdeconnect.ping".into()];
        i
    }

    #[test]
    fn device_ids() {
        let id = new_device_id();
        assert_eq!(id.len(), 32);
        assert!(is_valid_device_id(&id));
        assert!(is_valid_device_id("ee061a75_e403_4ecc_9261_5ffe2722f698")); // android's test certificate CN
        assert!(!is_valid_device_id("short"));
        assert!(!is_valid_device_id("ee061a75/e403/4ecc/9261/5ffe2722f698"));
    }

    #[test]
    fn names_are_filtered() {
        assert_eq!(filter_name("Retroid: Pocket 5!"), "Retroid Pocket 5");
        assert_eq!(filter_name(&"x".repeat(40)).len(), 32);
    }

    #[test]
    fn announcement_and_connection_packets() {
        let a = me();
        let ann = Identity::from_packet(&Packet::parse(a.announcement(1716).to_line().as_bytes()).unwrap(), true).unwrap();
        assert_eq!(ann.tcp_port, Some(1716));
        assert_eq!(ann.target_device_id, None);

        let b = Identity::new(new_device_id(), "PC", DeviceType::Desktop);
        let conn = Identity::from_packet(&b.connection_packet(&a), true).unwrap();
        assert_eq!(conn.target_device_id.as_deref(), Some(a.device_id.as_str()));
        assert_eq!(conn.target_protocol_version, Some(8));
        assert_eq!(conn.tcp_port, None);
    }

    // android sends targetProtocolVersion as a string (LanLinkProvider.udpPacketReceived).
    #[test]
    fn reads_android_connection_packet() {
        let line = r#"{"id":1,"type":"kdeconnect.identity","body":{"deviceId":"0123456789abcdef0123456789abcdef","deviceName":"Phone","deviceType":"phone","protocolVersion":8,"incomingCapabilities":[],"outgoingCapabilities":[],"targetDeviceId":"fedcba9876543210fedcba9876543210","targetProtocolVersion":"8"}}"#;
        let i = Identity::from_packet(&Packet::parse(line.as_bytes()).unwrap(), true).unwrap();
        assert_eq!(i.target_protocol_version, Some(8));
        assert_eq!(i.device_type, DeviceType::Phone);
    }

    // kde's minimal UDP packet (toUdpDiscoveryPacket).
    #[test]
    fn reads_kde_udp_packet() {
        let line = r#"{"id":1,"type":"kdeconnect.identity","body":{"deviceId":"0123456789abcdef0123456789abcdef","deviceName":"pc","protocolVersion":8,"tcpPort":1716}}"#;
        let i = Identity::from_packet(&Packet::parse(line.as_bytes()).unwrap(), false).unwrap();
        assert_eq!(i.tcp_port, Some(1716));
        assert_eq!(i.device_type, DeviceType::Desktop);
    }

    #[test]
    fn refuses_bad_identities() {
        let np = Packet::new("kdeconnect.ping");
        assert_eq!(Identity::from_packet(&np, true), Err(IdentityError::NotIdentity));
        let np = Packet::new(types::IDENTITY).with("deviceId", "0123456789abcdef0123456789abcdef").with("deviceName", "..!");
        assert_eq!(Identity::from_packet(&np, true), Err(IdentityError::NoName));
    }
}
