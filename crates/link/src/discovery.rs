//! Finding devices: the UDP announcement, and which addresses may be talked to (README, "Discovery").

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::ops::RangeInclusive;

use kdeconnect_proto::{Identity, Packet, MAX_TCP_PORT, MIN_TCP_PORT, PROTOCOL_VERSION};

/// Addresses to announce to besides the broadcast: devices a person added by address, and the peers a VPN
/// plugin knows (a Tailscale tailnet's online devices, say). The link layer knows nothing about where they
/// come from. Addresses from a source are also allowed to connect even when they are not local ones.
pub trait AddressSource: Send + Sync {
    fn addresses(&self) -> Vec<IpAddr>;
}

/// No extra addresses.
pub struct NoAddresses;

impl AddressSource for NoAddresses {
    fn addresses(&self) -> Vec<IpAddr> {
        Vec::new()
    }
}

/// The ports both apps' TCP listeners are taken from.
pub const KDE_TCP_PORTS: RangeInclusive<u16> = MIN_TCP_PORT..=MAX_TCP_PORT;

/// Whether both apps would talk to this address without it being added by hand (android `isPrivateAddress`):
/// loopback, private, link-local, carrier-grade NAT (100.64.0.0/10, which is Tailscale's) and IPv6
/// unique-local (fc00::/7, which holds Tailscale's fd7a:115c:a1e0::/48).
pub fn is_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => {
            let o = a.octets();
            a.is_loopback() || a.is_private() || a.is_link_local() || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_local(IpAddr::V4(v4));
            }
            let s = a.segments();
            a.is_loopback() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// An announcement heard from another device.
#[derive(Debug, Clone)]
pub struct Heard {
    pub identity: Identity,
    /// Where to connect: the sender's address and the `tcpPort` it announced.
    pub addr: SocketAddr,
}

/// Reads a datagram as an announcement, with both apps' rules: a valid identity (a name is not required:
/// kde's minimal UDP packet), not this device's own, version 8 or later, and a `tcpPort` in `ports`
/// (1716-1764, [`KDE_TCP_PORTS`], everywhere but tests).
pub fn parse_announcement(datagram: &[u8], from: SocketAddr, my_device_id: &str, ports: &RangeInclusive<u16>) -> Option<Heard> {
    let np = Packet::parse(datagram).ok()?;
    let identity = Identity::from_packet(&np, false).ok()?;
    if identity.device_id == my_device_id || identity.protocol_version < PROTOCOL_VERSION {
        return None;
    }
    let port = identity.tcp_port?;
    if !ports.contains(&port) {
        return None;
    }
    let ip = match from.ip() {
        IpAddr::V6(a) => a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(a)),
        a => a,
    };
    Some(Heard { identity, addr: SocketAddr::new(ip, port) })
}

/// Sends this device's announcement to the broadcast address and to each extra address, on `udp_port`
/// (1716 everywhere but tests).
pub fn announce(me: &Identity, tcp_port: u16, extra: &[IpAddr], udp_port: u16, broadcast: bool) -> std::io::Result<()> {
    let line = me.announcement(tcp_port).to_line();
    let v4 = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    v4.set_broadcast(true)?;
    if broadcast {
        // A failed broadcast (no network) is not an error for the addresses after it.
        let _ = v4.send_to(line.as_bytes(), (Ipv4Addr::BROADCAST, udp_port));
    }
    for ip in extra {
        let _ = match ip {
            IpAddr::V4(_) => v4.send_to(line.as_bytes(), (*ip, udp_port)),
            IpAddr::V6(_) => UdpSocket::bind("[::]:0").and_then(|s| s.send_to(line.as_bytes(), (*ip, udp_port))),
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdeconnect_proto::identity::new_device_id;
    use kdeconnect_proto::DeviceType;

    #[test]
    fn local_addresses() {
        for a in [
            "127.0.0.1",
            "192.168.1.5",
            "10.0.0.1",
            "172.16.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "::1",
            "fd7a:115c:a1e0::1",
            "fe80::1",
            "::ffff:192.168.0.1",
        ] {
            assert!(is_local(a.parse().unwrap()), "{a}");
        }
        for a in ["8.8.8.8", "100.128.0.1", "2001:db8::1", "::ffff:8.8.8.8"] {
            assert!(!is_local(a.parse().unwrap()), "{a}");
        }
    }

    #[test]
    fn announcements() {
        let me = new_device_id();
        let peer = Identity::new(new_device_id(), "Phone", DeviceType::Phone);
        let from: SocketAddr = "[::ffff:192.168.1.9]:1716".parse().unwrap();
        let h = parse_announcement(peer.announcement(1720).to_line().as_bytes(), from, &me, &KDE_TCP_PORTS).unwrap();
        assert_eq!(h.addr, "192.168.1.9:1720".parse().unwrap());
        assert!(parse_announcement(peer.announcement(1765).to_line().as_bytes(), from, &me, &KDE_TCP_PORTS).is_none());
        assert!(parse_announcement(peer.announcement(1720).to_line().as_bytes(), from, &peer.device_id, &KDE_TCP_PORTS).is_none());
        let mut old = peer.clone();
        old.protocol_version = 7;
        assert!(parse_announcement(old.announcement(1720).to_line().as_bytes(), from, &me, &KDE_TCP_PORTS).is_none());
    }
}
