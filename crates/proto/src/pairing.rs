//! Pairing: the `kdeconnect.pair` packets, their state machine and the verification key both screens show
//! (android `PairingHandler.kt`).

use sha2::{Digest, Sha256};

use crate::packet::Packet;
use crate::types;

/// How far a peer's pairing timestamp may be from this clock (android `allowedTimestampDifferenceSeconds`).
pub const ALLOWED_CLOCK_SKEW_SECS: i64 = 1800;
/// How long this device waits for the other to accept (android: 30 s after `requestPairing`).
pub const REQUEST_TIMEOUT_SECS: i64 = 30;
/// How long a request from the other device stays open here (android: 25 s, so it lapses before the
/// requester's own 30 s do).
pub const INCOMING_TIMEOUT_SECS: i64 = 25;

/// The key both devices show while pairing: SHA-256 over the two certificates' SubjectPublicKeyInfo (DER),
/// the larger one first, then the request's timestamp in decimal; the first 8 hex digits, upper case
/// (android `getVerificationKey`, `sortedConcat`, `humanReadableHash`).
pub fn verification_key(spki_a: &[u8], spki_b: &[u8], timestamp: i64) -> String {
    let (first, second) = if spki_a < spki_b { (spki_b, spki_a) } else { (spki_a, spki_b) };
    let mut h = Sha256::new();
    h.update(first);
    h.update(second);
    h.update(timestamp.to_string().as_bytes());
    let digest = h.finalize();
    digest[..4].iter().map(|b| format!("{b:02X}")).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairState {
    NotPaired,
    /// This device asked; `timestamp` is the one it sent.
    Requested {
        timestamp: i64,
        since: i64,
    },
    /// The other device asked; `timestamp` is the one it sent.
    RequestedByPeer {
        timestamp: i64,
        since: i64,
    },
    Paired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairEvent {
    /// The other device asks to pair: show the verification key, and Accept / Refuse.
    IncomingRequest,
    /// Both sides agree: pin the peer's certificate now.
    Paired,
    /// The other device unpaired: forget its certificate.
    Unpaired,
    /// Pairing did not happen.
    Failed(PairFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairFailure {
    TimedOut,
    RefusedByPeer,
    /// The request's timestamp is more than 30 minutes from this clock, or missing.
    ClocksDiffer,
}

/// One peer's pairing. Time is unix seconds, given by the caller, so the machine is testable and has no
/// timers of its own: call [`Pairing::tick`] about once a second while a request is open.
#[derive(Debug, Clone)]
pub struct Pairing {
    pub state: PairState,
}

fn pair_packet(pair: bool) -> Packet {
    Packet::new(types::PAIR).with("pair", pair)
}

impl Pairing {
    pub fn new(paired: bool) -> Self {
        Pairing { state: if paired { PairState::Paired } else { PairState::NotPaired } }
    }

    /// The timestamp the verification key is made from, while a request is open.
    pub fn timestamp(&self) -> Option<i64> {
        match self.state {
            PairState::Requested { timestamp, .. } | PairState::RequestedByPeer { timestamp, .. } => Some(timestamp),
            _ => None,
        }
    }

    /// Ask to pair. Returns the packet to send; a request the other device already made is accepted instead.
    pub fn request(&mut self, now: i64) -> Option<Packet> {
        match self.state {
            PairState::Paired => None,
            PairState::RequestedByPeer { .. } => self.accept(),
            _ => {
                self.state = PairState::Requested { timestamp: now, since: now };
                Some(pair_packet(true).with("timestamp", now))
            }
        }
    }

    /// Accept the other device's request. The caller pins the certificate once the packet is sent.
    pub fn accept(&mut self) -> Option<Packet> {
        if let PairState::RequestedByPeer { .. } = self.state {
            self.state = PairState::Paired;
            Some(pair_packet(true))
        } else {
            None
        }
    }

    /// Refuse the other device's request, or withdraw this device's own.
    pub fn cancel(&mut self) -> Option<Packet> {
        match self.state {
            PairState::Requested { .. } | PairState::RequestedByPeer { .. } => {
                self.state = PairState::NotPaired;
                Some(pair_packet(false))
            }
            _ => None,
        }
    }

    /// Unpair. The packet is sent if the device is reachable; the caller forgets the certificate either way.
    pub fn unpair(&mut self) -> Packet {
        self.state = PairState::NotPaired;
        pair_packet(false)
    }

    /// A `kdeconnect.pair` packet arrived.
    pub fn on_packet(&mut self, np: &Packet, now: i64) -> Option<PairEvent> {
        if np.bool("pair") == Some(true) {
            match self.state {
                PairState::Requested { .. } => {
                    self.state = PairState::Paired;
                    Some(PairEvent::Paired)
                }
                // A second request before the first lapsed is ignored, as android does.
                PairState::RequestedByPeer { .. } => None,
                PairState::Paired | PairState::NotPaired => {
                    // A request from a device already trusted: android unpairs and treats it as new, because
                    // a request and an acceptance are the same packet.
                    let was_paired = self.state == PairState::Paired;
                    self.state = PairState::NotPaired;
                    let Some(ts) = np.int("timestamp") else {
                        return Some(if was_paired { PairEvent::Unpaired } else { PairEvent::Failed(PairFailure::ClocksDiffer) });
                    };
                    if (ts - now).abs() > ALLOWED_CLOCK_SKEW_SECS {
                        return Some(PairEvent::Failed(PairFailure::ClocksDiffer));
                    }
                    self.state = PairState::RequestedByPeer { timestamp: ts, since: now };
                    Some(PairEvent::IncomingRequest)
                }
            }
        } else {
            match self.state {
                PairState::NotPaired => None,
                PairState::Requested { .. } | PairState::RequestedByPeer { .. } => {
                    self.state = PairState::NotPaired;
                    Some(PairEvent::Failed(PairFailure::RefusedByPeer))
                }
                PairState::Paired => {
                    self.state = PairState::NotPaired;
                    Some(PairEvent::Unpaired)
                }
            }
        }
    }

    /// Lapses an open request whose time is up.
    pub fn tick(&mut self, now: i64) -> Option<PairEvent> {
        let lapsed = match self.state {
            PairState::Requested { since, .. } => now - since >= REQUEST_TIMEOUT_SECS,
            PairState::RequestedByPeer { since, .. } => now - since >= INCOMING_TIMEOUT_SECS,
            _ => false,
        };
        if lapsed {
            self.state = PairState::NotPaired;
            Some(PairEvent::Failed(PairFailure::TimedOut))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_does_not_depend_on_order() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 4];
        assert_eq!(verification_key(&a, &b, 5), verification_key(&b, &a, 5));
        assert_ne!(verification_key(&a, &b, 5), verification_key(&a, &b, 6));
        assert_eq!(verification_key(&a, &b, 5).len(), 8);
    }

    #[test]
    fn request_then_accepted() {
        let mut me = Pairing::new(false);
        let mut peer = Pairing::new(false);
        let req = me.request(1000).unwrap();
        assert_eq!(req.int("timestamp"), Some(1000));
        assert_eq!(peer.on_packet(&req, 1003), Some(PairEvent::IncomingRequest));
        assert_eq!(peer.timestamp(), me.timestamp());
        let acc = peer.accept().unwrap();
        assert_eq!(peer.state, PairState::Paired);
        assert_eq!(me.on_packet(&acc, 1005), Some(PairEvent::Paired));
    }

    #[test]
    fn refused_and_timed_out() {
        let mut me = Pairing::new(false);
        let mut peer = Pairing::new(false);
        peer.on_packet(&me.request(0).unwrap(), 0);
        let refusal = peer.cancel().unwrap();
        assert_eq!(me.on_packet(&refusal, 1), Some(PairEvent::Failed(PairFailure::RefusedByPeer)));

        me.request(100);
        assert_eq!(me.tick(129), None);
        assert_eq!(me.tick(130), Some(PairEvent::Failed(PairFailure::TimedOut)));
    }

    #[test]
    fn clocks_must_agree() {
        let mut me = Pairing::new(false);
        let req = Packet::new(types::PAIR).with("pair", true).with("timestamp", 0);
        assert_eq!(me.on_packet(&req, 1801), Some(PairEvent::Failed(PairFailure::ClocksDiffer)));
        let no_ts = Packet::new(types::PAIR).with("pair", true);
        assert_eq!(me.on_packet(&no_ts, 0), Some(PairEvent::Failed(PairFailure::ClocksDiffer)));
    }

    #[test]
    fn unpair_from_peer() {
        let mut me = Pairing::new(true);
        assert_eq!(me.on_packet(&Packet::new(types::PAIR).with("pair", false), 0), Some(PairEvent::Unpaired));
        assert_eq!(me.state, PairState::NotPaired);
    }
}
