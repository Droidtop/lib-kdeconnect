//! A network packet: one JSON object on one line (android `NetworkPacket.serialize`).

use serde_json::{Map, Value};

#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("packet is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("packet has no {0}")]
    Missing(&'static str),
    #[error("packet is longer than {0} bytes")]
    TooLong(usize),
}

/// `{id, type, body, payloadSize?, payloadTransferInfo?}`. Fields other than these are ignored on read, as
/// both apps do.
#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    /// Milliseconds since the epoch when it was made. Nothing reads it; both apps send it.
    pub id: i64,
    pub kind: String,
    pub body: Map<String, Value>,
    /// Size of the payload that follows on a separate connection, or -1 when unknown (a stream).
    pub payload_size: Option<i64>,
    /// `{"port": n}` where the payload can be fetched (README, "Payloads").
    pub payload_transfer_info: Option<Map<String, Value>>,
}

impl Packet {
    pub fn new(kind: impl Into<String>) -> Self {
        Packet { id: now_ms(), kind: kind.into(), body: Map::new(), payload_size: None, payload_transfer_info: None }
    }

    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.set(key, value);
        self
    }

    pub fn set(&mut self, key: &str, value: impl Into<Value>) {
        self.body.insert(key.to_owned(), value.into());
    }

    /// The packet as it goes on the wire: compact JSON and `\n`. `payloadSize` and `payloadTransferInfo`
    /// are left out when there is no payload (android `NetworkPacketTest`).
    pub fn to_line(&self) -> String {
        let mut o = Map::new();
        o.insert("id".into(), self.id.into());
        o.insert("type".into(), self.kind.clone().into());
        o.insert("body".into(), Value::Object(self.body.clone()));
        if let Some(size) = self.payload_size {
            o.insert("payloadSize".into(), size.into());
            if let Some(info) = &self.payload_transfer_info {
                o.insert("payloadTransferInfo".into(), Value::Object(info.clone()));
            }
        }
        let mut s = Value::Object(o).to_string();
        s.push('\n');
        s
    }

    /// Reads one packet. A trailing newline (or `\r\n`) is allowed.
    pub fn parse(line: &[u8]) -> Result<Self, PacketError> {
        let v: Value = serde_json::from_slice(line)?;
        let Value::Object(mut o) = v else { return Err(PacketError::Missing("object")) };
        let kind = match o.remove("type") {
            Some(Value::String(s)) => s,
            _ => return Err(PacketError::Missing("type")),
        };
        let body = match o.remove("body") {
            Some(Value::Object(b)) => b,
            None | Some(Value::Null) => Map::new(),
            _ => return Err(PacketError::Missing("body")),
        };
        let id = o.get("id").and_then(as_i64).unwrap_or(0);
        let payload_size = o.get("payloadSize").and_then(as_i64);
        let payload_transfer_info = match o.remove("payloadTransferInfo") {
            Some(Value::Object(m)) if !m.is_empty() => Some(m),
            _ => None,
        };
        Ok(Packet { id, kind, body, payload_size, payload_transfer_info })
    }

    /// A string field. A number or boolean is given as its text, as android `getString` does.
    pub fn str(&self, key: &str) -> Option<String> {
        match self.body.get(key)? {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    /// An integer field, from a number or from a string holding one: android sends `targetProtocolVersion`
    /// as a string (`LanLinkProvider.udpPacketReceived`), kde as a number.
    pub fn int(&self, key: &str) -> Option<i64> {
        as_i64(self.body.get(key)?)
    }

    /// A boolean field, from `true`/`false` or the strings `"true"`/`"false"`.
    pub fn bool(&self, key: &str) -> Option<bool> {
        match self.body.get(key)? {
            Value::Bool(b) => Some(*b),
            Value::String(s) => s.parse().ok(),
            _ => None,
        }
    }

    /// A list of strings; anything in it that is not a string is skipped.
    pub fn strings(&self, key: &str) -> Vec<String> {
        match self.body.get(key) {
            Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect(),
            _ => Vec::new(),
        }
    }

    /// The payload port the sender offers, if any.
    pub fn payload_port(&self) -> Option<u16> {
        self.payload_transfer_info.as_ref()?.get("port").and_then(as_i64).and_then(|p| u16::try_from(p).ok())
    }
}

fn as_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // android NetworkPacketTest: the line ends in a newline, the payload fields only appear with a payload.
    #[test]
    fn round_trip_and_payload_fields() {
        let mut np = Packet::new("com.test").with("path", "/a/b");
        np.payload_size = Some(42);
        let mut info = Map::new();
        info.insert("port".into(), 1739.into());
        np.payload_transfer_info = Some(info);
        let line = np.to_line();
        assert!(line.ends_with('\n'));
        assert!(line.contains("\"path\":\"/a/b\""));
        let back = Packet::parse(line.as_bytes()).unwrap();
        assert_eq!(back.kind, "com.test");
        assert_eq!(back.str("path").as_deref(), Some("/a/b"));
        assert_eq!(back.payload_size, Some(42));
        assert_eq!(back.payload_port(), Some(1739));

        let plain = Packet::new("com.test").to_line();
        assert!(!plain.contains("payloadSize"));
        assert!(!plain.contains("payloadTransferInfo"));
    }

    // android NetworkPacketTest: lenient types, unknown top-level fields ignored.
    #[test]
    fn lenient_fields() {
        let np = Packet::parse(br#"{"id":1,"type":"test","body":{"int":8,"str":"12","bool":"true","nil":null},"extra":0}"#).unwrap();
        assert_eq!(np.str("int").as_deref(), Some("8"));
        assert_eq!(np.int("str"), Some(12));
        assert_eq!(np.bool("bool"), Some(true));
        assert_eq!(np.str("nil"), None);
    }

    #[test]
    fn refuses_what_is_not_a_packet() {
        assert!(Packet::parse(b"[]").is_err());
        assert!(Packet::parse(br#"{"id":1,"body":{}}"#).is_err());
        assert!(Packet::parse(b"not json").is_err());
    }
}
