//! KDE Connect protocol version 8, the parts that need no I/O.
//!
//! Ported from kdeconnect-android (`NetworkPacket.kt`, `DeviceInfo.kt`, `PairingHandler.kt`,
//! `backends/lan/LanLinkProvider.kt`) and checked against kdeconnect-kde (`core/networkpacket.cpp`,
//! `core/deviceinfo.h`, `core/backends/lan/lanlinkprovider.cpp`). Both are
//! `GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL`; this port is GPL-3.0-only. See NOTICE.md.

pub mod identity;
pub mod packet;
pub mod pairing;

pub use identity::{DeviceType, Identity};
pub use packet::{Packet, PacketError};

/// The only protocol version both official apps still accept (kde `NetworkPacket::s_protocolVersion`,
/// android `DeviceHelper.PROTOCOL_VERSION`). Both refuse anything lower.
pub const PROTOCOL_VERSION: i64 = 8;

/// UDP discovery port (android `LanLinkProvider.UDP_PORT`).
pub const UDP_PORT: u16 = 1716;
/// The range a link's TCP listener is taken from (android `MIN_PORT`..`MAX_PORT`). A UDP identity whose
/// `tcpPort` is outside it is ignored by both apps.
pub const MIN_TCP_PORT: u16 = 1716;
pub const MAX_TCP_PORT: u16 = 1764;
/// Payload listeners start here (android `PAYLOAD_TRANSFER_MIN_PORT`) and end at [`MAX_TCP_PORT`].
pub const MIN_PAYLOAD_PORT: u16 = 1739;

/// The longest identity or connection packet read before TLS, and the encrypted identity after it
/// (both apps' `MAX_IDENTITY_PACKET_SIZE`).
pub const MAX_IDENTITY_PACKET_SIZE: usize = 8192;
/// The longest packet read on an established link (android `LanLink.MAX_PACKET_SIZE`).
pub const MAX_PACKET_SIZE: usize = 32 * 1024 * 1024;

/// Packet types used by the core (kde `core/networkpackettypes.h`).
pub mod types {
    pub const IDENTITY: &str = "kdeconnect.identity";
    pub const PAIR: &str = "kdeconnect.pair";
    pub const PING: &str = "kdeconnect.ping";
}
