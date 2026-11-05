//! The service behind JSON operations: one table that droidtop's JNI module (`kdeconnect_<op>`) and Pythia's
//! Python module both pass through, so neither has a binding of its own to keep in step.
//!
//! | Op | Arguments | Reply |
//! |---|---|---|
//! | `start` | `state_dir, name, type?` (`phone`, `tablet`, `desktop`, `laptop`, `tv`), `plugins?` (`{name: bool}`) | `{id, name}` |
//! | `stop` | | `{}` |
//! | `identity` | | `{id, name}` |
//! | `devices` | | `{devices: [DeviceView]}` |
//! | `event` | `timeout_ms?` (default 1000, at most 60000) | an event, or `{"event": "none"}` |
//! | `announce` | | `{}` |
//! | `addresses` | `addresses: [ip]` | `{}`: the extra addresses (added by hand, a VPN plugin's peers) |
//! | `pair`, `accept`, `refuse`, `unpair` | `id` | `{}` |
//! | `ping` | `id, message?` | `{}` |
//!
//! A failure is `{"error": "..."}` in words a screen can show. A call before `start` is an error, and
//! `start` while running returns the running device.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kdeconnect_link::Config;
use kdeconnect_proto::DeviceType;
use serde_json::{json, Value};

use crate::plugins::Enabled;
use crate::{Service, ServiceError, Settings};

static RUNNING: Mutex<Option<Arc<Service>>> = Mutex::new(None);

fn running() -> Result<Arc<Service>, String> {
    RUNNING.lock().unwrap_or_else(|e| e.into_inner()).clone().ok_or_else(|| "KDE Connect is not on".to_string())
}

fn id(args: &Value) -> Result<&str, String> {
    args.get("id").and_then(Value::as_str).ok_or_else(|| "no device id".to_string())
}

fn words(e: ServiceError) -> String {
    match e {
        ServiceError::UnknownDevice(_) => "That device is not known here".into(),
        ServiceError::NotReachable => "That device is not reachable now".into(),
        ServiceError::NotPaired => "That device is not paired".into(),
        ServiceError::Io(e) => format!("KDE Connect could not use the network: {e}"),
    }
}

/// Reads `plugins: {"ping": false, ...}` over the defaults (all on).
pub fn plugins_of(args: &Value) -> Enabled {
    let mut on = Enabled::default();
    if let Some(m) = args.get("plugins").and_then(Value::as_object) {
        for (k, v) in m {
            let v = v.as_bool().unwrap_or(true);
            on.set(k, v);
        }
    }
    on
}

fn start(args: &Value, link: Config) -> Result<Value, String> {
    let mut slot = RUNNING.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = slot.as_ref() {
        return Ok(json!({ "id": s.identity().device_id, "name": s.identity().device_name }));
    }
    let state_dir = args.get("state_dir").and_then(Value::as_str).ok_or("no state_dir")?;
    let name = args.get("name").and_then(Value::as_str).unwrap_or("droidtop");
    let device_type = DeviceType::parse(args.get("type").and_then(Value::as_str).unwrap_or("desktop"));
    let settings = Settings { name: name.into(), device_type, state_dir: PathBuf::from(state_dir), link, plugins: plugins_of(args) };
    let s = Service::start(settings).map_err(|e| match e {
        ServiceError::Io(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            "Another KDE Connect is running on this device (the KDE Connect app, or another program). Close it and try again.".to_string()
        }
        e => words(e),
    })?;
    let reply = json!({ "id": s.identity().device_id, "name": s.identity().device_name });
    *slot = Some(Arc::new(s));
    Ok(reply)
}

/// Runs one operation. `link` is used by `start` only (programs pass `Config::default()`).
pub fn call_with(op: &str, args: &Value, link: Config) -> Value {
    let r: Result<Value, String> = (|| match op {
        "start" => start(args, link),
        "stop" => {
            RUNNING.lock().unwrap_or_else(|e| e.into_inner()).take();
            Ok(json!({}))
        }
        "identity" => {
            let s = running()?;
            Ok(json!({ "id": s.identity().device_id, "name": s.identity().device_name }))
        }
        "devices" => Ok(json!({ "devices": running()?.devices() })),
        "event" => {
            let s = running()?;
            let ms = args.get("timeout_ms").and_then(Value::as_u64).unwrap_or(1000).min(60_000);
            Ok(match s.next_event(Duration::from_millis(ms)) {
                Some(e) => serde_json::to_value(e).map_err(|e| e.to_string())?,
                None => json!({ "event": "none" }),
            })
        }
        "announce" => {
            running()?.announce().map_err(|e| format!("KDE Connect could not announce this device: {e}"))?;
            Ok(json!({}))
        }
        "addresses" => {
            let list: Vec<IpAddr> = args
                .get("addresses")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str()?.trim().parse().ok()).collect())
                .unwrap_or_default();
            running()?.set_extra_addresses(list);
            Ok(json!({}))
        }
        "pair" => running()?.pair(id(args)?).map(|_| json!({})).map_err(words),
        "accept" => running()?.accept(id(args)?).map(|_| json!({})).map_err(words),
        "refuse" => running()?.refuse(id(args)?).map(|_| json!({})).map_err(words),
        "unpair" => running()?.unpair(id(args)?).map(|_| json!({})).map_err(words),
        "ping" => {
            let message = args.get("message").and_then(Value::as_str);
            running()?.ping(id(args)?, message).map(|_| json!({})).map_err(words)
        }
        other => Err(format!("unknown KDE Connect operation {other}")),
    })();
    r.unwrap_or_else(|e| json!({ "error": e }))
}

/// Runs one operation with the default link settings.
pub fn call(op: &str, args: &Value) -> Value {
    call_with(op, args, Config::default())
}
