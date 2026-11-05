//! The service behind JSON operations: one table that droidtop's JNI module (`kdeconnect_<op>`) and Pythia's
//! Python module both pass through, so neither has a binding of its own to keep in step.
//!
//! | Op | Arguments | Reply |
//! |---|---|---|
//! | `start` | `state_dir, name, receive_dir?, type?` (`phone`, `tablet`, `desktop`, `laptop`, `tv`), `plugins?` (`{name: bool}`) | `{id, name}` |
//! | `stop` | | `{}`: once it returns the ports are free; a waiting `event` returns `{"event": "stopped"}` |
//! | `identity` | | `{id, name}` |
//! | `devices` | | `{devices: [DeviceView]}` |
//! | `event` | `timeout_ms?` (default 1000, at most 60000) | an event, or `{"event": "none"}` |
//! | `announce` | | `{}` |
//! | `addresses` | `addresses: [ip]` | `{}`: the extra addresses (added by hand, a VPN plugin's peers) |
//! | `pair`, `accept`, `refuse`, `unpair` | `id` | `{}` |
//! | `ping` | `id, message?` | `{}` |
//! | `input_send` | `id, input: {dx?, dy?, x?, y?, scroll?, click?, key?, special_key?, shift?, ctrl?, alt?, super?}` | `{}` |
//! | `keyboard_ready` | `ready` | `{}`: whether this device can take typing now |
//! | `battery_set` | `charge?` (0-100; none: no battery), `charging?` | `{}` |
//! | `ring` | `id` | `{}`: the other device rings |
//! | `notification_dismiss` | `id, key` | `{}` |
//! | `clipboard_set` | `text` | `{sent_to}`: this device's clipboard changed; sent to paired, reachable devices |
//! | `share_text` | `id, text` | `{}` |
//! | `share_url` | `id, url` | `{}` |
//! | `share_file` | `id, path` or `fd` (Unix: handed over), `name?`, `size?`, `open?` | `{}`; the outcome comes as an event |
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
    let receive_dir = args.get("receive_dir").and_then(Value::as_str).map(PathBuf::from);
    let settings =
        Settings { name: name.into(), device_type, state_dir: PathBuf::from(state_dir), link, plugins: plugins_of(args), receive_dir };
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
            if let Some(s) = RUNNING.lock().unwrap_or_else(|e| e.into_inner()).take() {
                // Wake an `event` call waiting on it, and wait (at most 2 s) for it to let go, so the ports are
                // free when `stop` returns and a `start` straight after can take them.
                s.close();
                let end = std::time::Instant::now() + Duration::from_secs(2);
                while Arc::strong_count(&s) > 1 && std::time::Instant::now() < end {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
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
        "input_send" => {
            let input: crate::plugins::input::InputEvent =
                serde_json::from_value(args.get("input").cloned().unwrap_or(Value::Null)).map_err(|e| format!("not an input: {e}"))?;
            running()?.input_send(id(args)?, &input).map(|_| json!({})).map_err(words)
        }
        "keyboard_ready" => {
            running()?.set_keyboard_ready(args.get("ready").and_then(Value::as_bool).unwrap_or(false));
            Ok(json!({}))
        }
        "battery_set" => {
            let charge = args.get("charge").and_then(Value::as_i64);
            let charging = args.get("charging").and_then(Value::as_bool).unwrap_or(false);
            running()?.set_battery(charge.map(|charge| crate::plugins::battery::Battery { charge, charging }));
            Ok(json!({}))
        }
        "ring" => running()?.ring(id(args)?).map(|_| json!({})).map_err(words),
        "notification_dismiss" => {
            let key = args.get("key").and_then(Value::as_str).ok_or("no key")?;
            running()?.dismiss_notification(id(args)?, key).map(|_| json!({})).map_err(words)
        }
        "clipboard_set" => {
            let text = args.get("text").and_then(Value::as_str).ok_or("no text")?;
            Ok(json!({ "sent_to": running()?.clipboard_set(text) }))
        }
        "share_text" => {
            let text = args.get("text").and_then(Value::as_str).ok_or("no text")?;
            running()?.share_text(id(args)?, text).map(|_| json!({})).map_err(words)
        }
        "share_url" => {
            let url = args.get("url").and_then(Value::as_str).ok_or("no url")?;
            running()?.share_url(id(args)?, url).map(|_| json!({})).map_err(words)
        }
        "share_file" => {
            let file = outgoing_file(args)?;
            running()?.share_file(id(args)?, file).map(|_| json!({})).map_err(words)
        }
        other => Err(format!("unknown KDE Connect operation {other}")),
    })();
    r.unwrap_or_else(|e| json!({ "error": e }))
}

/// The file `share_file` names: `path`, or on Unix an open file descriptor `fd` the caller hands over (droidtop
/// passes a document's descriptor, so nothing is copied). `name` overrides the file's own name; `size` is read
/// from the file when it is a regular one, else taken from `size`, else unknown (-1).
fn outgoing_file(args: &Value) -> Result<crate::plugins::share::Outgoing, String> {
    let (file, own_name) = if let Some(p) = args.get("path").and_then(Value::as_str) {
        let f = std::fs::File::open(p).map_err(|e| format!("Could not open the file: {e}"))?;
        (f, std::path::Path::new(p).file_name().map(|n| n.to_string_lossy().into_owned()))
    } else if let Some(fd) = args.get("fd").and_then(Value::as_i64) {
        (from_fd(fd)?, None)
    } else {
        return Err("no path or fd".into());
    };
    let name = args.get("name").and_then(Value::as_str).map(str::to_owned).or(own_name).unwrap_or_else(|| "file".into());
    let meta = file.metadata().ok().filter(|m| m.is_file());
    let size = meta.as_ref().map(|m| m.len() as i64).or_else(|| args.get("size").and_then(Value::as_i64)).unwrap_or(-1);
    let last_modified_ms =
        meta.and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as i64);
    let open = args.get("open").and_then(Value::as_bool).unwrap_or(false);
    Ok(crate::plugins::share::Outgoing { name, size, last_modified_ms, data: Box::new(file), open })
}

#[cfg(unix)]
fn from_fd(fd: i64) -> Result<std::fs::File, String> {
    use std::os::fd::FromRawFd;
    let fd = i32::try_from(fd).map_err(|_| "not a file descriptor".to_string())?;
    if fd < 0 {
        return Err("not a file descriptor".into());
    }
    // The caller hands the descriptor over (droidtop: ParcelFileDescriptor.detachFd); it is closed when sent.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(not(unix))]
fn from_fd(_: i64) -> Result<std::fs::File, String> {
    Err("a file descriptor is only taken on Unix; pass a path".into())
}

/// Runs one operation with the default link settings.
pub fn call(op: &str, args: &Value) -> Value {
    call_with(op, args, Config::default())
}
