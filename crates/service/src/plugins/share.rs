//! `kdeconnect.share.request` (android `plugins/share/SharePlugin.kt`, `CompositeReceiveFileJob.kt`,
//! `CompositeUploadFileJob.kt`): a URL, a text, or a file with its payload, each way.
//!
//! - A request with `url` is a link to open, with `text` a text to show or copy, with `filename` and a payload a
//!   file. `numberOfFiles` and `totalPayloadSize` describe the whole batch; `kdeconnect.share.request.update`
//!   corrects them while a batch is sent. `open: true` asks the receiver to open the file once it arrives.
//! - A received file is fetched at once on its own thread (the sender waits only 10 s for the payload
//!   connection), into the folder the program named, as `<name>.part` until all of it arrived, then renamed. A
//!   file that does not arrive whole is deleted. Without a folder, files are not fetched and the program is told.
//! - Names follow droidtop's rules for a received file (docs/SPEC.md "File transfer", `FileNames`): only what
//!   follows the last `/` or `\`, control characters and `: * ? " < > |` as `_`, no leading dots, no trailing
//!   dots or spaces, at most 120 bytes keeping the extension, `file` when nothing is left, and never over another
//!   file ("Name (2)").

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kdeconnect_link::{DeviceCert, PayloadOffer, PayloadReader};
use kdeconnect_proto::Packet;

use super::PluginEvent;

pub const REQUEST: &str = "kdeconnect.share.request";
pub const UPDATE: &str = "kdeconnect.share.request.update";
pub const INCOMING: &[&str] = &[REQUEST, UPDATE];
pub const OUTGOING: &[&str] = &[REQUEST];

const MAX_NAME_BYTES: usize = 120;

/// What a share packet needs from the link it came on.
pub struct Incoming {
    pub receive_dir: Option<PathBuf>,
    pub cert: DeviceCert,
    pub peer_ip: IpAddr,
    pub peer_cert: Vec<u8>,
    /// Reports what happened later, from the download's thread.
    pub emit: Arc<dyn Fn(PluginEvent) + Send + Sync>,
}

pub fn receive(np: &Packet, ctx: Incoming) -> Vec<PluginEvent> {
    if np.kind == UPDATE {
        return Vec::new();
    }
    if let Some(url) = np.str("url") {
        return vec![PluginEvent::ShareUrl { url }];
    }
    if let Some(text) = np.str("text") {
        return vec![PluginEvent::ShareText { text }];
    }
    let Some(name) = np.str("filename") else { return Vec::new() };
    let name = sanitise(&name);
    let size = np.payload_size.filter(|s| *s >= 0);
    let open = np.bool("open").unwrap_or(false);
    if np.payload_port().is_none() {
        return vec![PluginEvent::FileFailed { name, why: "the device sent no file with it".into() }];
    }
    let Some(dir) = ctx.receive_dir else {
        return vec![PluginEvent::FileFailed { name, why: "receiving files is not set up here".into() }];
    };
    let np = np.clone();
    let (cert, peer_ip, peer_cert, emit) = (ctx.cert, ctx.peer_ip, ctx.peer_cert, ctx.emit);
    let started = PluginEvent::FileReceiving { name: name.clone(), size };
    std::thread::spawn(move || {
        let e = match fetch(&np, &dir, &name, &cert, peer_ip, peer_cert) {
            Ok((path, bytes)) => PluginEvent::FileReceived {
                name: path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or(name),
                path: path.to_string_lossy().into_owned(),
                size: bytes,
                open,
            },
            Err(e) => PluginEvent::FileFailed { name, why: e.to_string() },
        };
        emit(e);
    });
    vec![started]
}

fn fetch(np: &Packet, dir: &Path, name: &str, cert: &DeviceCert, peer: IpAddr, pin: Vec<u8>) -> io::Result<(PathBuf, u64)> {
    std::fs::create_dir_all(dir)?;
    let target = unique(dir, name);
    let part = target.with_file_name(format!("{}.part", target.file_name().unwrap_or_default().to_string_lossy()));
    let mut reader = PayloadReader::connect(np, peer, cert, pin)
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("the device sent no file with it"))?;
    let result = (|| {
        let mut f = File::create(&part)?;
        let n = io::copy(&mut reader, &mut f)?;
        f.flush()?;
        f.sync_all()?;
        Ok::<u64, io::Error>(n)
    })();
    match result {
        Ok(n) => {
            // A name taken while it arrived is not replaced: the next free one is used.
            let target = if target.exists() { unique(dir, name) } else { target };
            std::fs::rename(&part, &target)?;
            Ok((target, n))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&part);
            Err(e)
        }
    }
}

/// droidtop's `FileNames.sanitise`, for a name another device sent.
pub fn sanitise(name: &str) -> String {
    let last = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = last.chars().map(|c| if c.is_control() || ":*?\"<>|".contains(c) { '_' } else { c }).collect();
    let cleaned = cleaned.trim_start_matches('.').trim_end_matches(['.', ' ']).to_string();
    let cleaned = if cleaned.len() > MAX_NAME_BYTES {
        let (stem, ext) = split_ext(&cleaned);
        let room = MAX_NAME_BYTES.saturating_sub(ext.len());
        let mut cut = stem.len().min(room);
        while !stem.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}{}", &stem[..cut], ext)
    } else {
        cleaned
    };
    if cleaned.is_empty() {
        "file".into()
    } else {
        cleaned
    }
}

/// `stem` and `.ext`, where ".tar.gz" counts as one extension as droidtop's `FileNames.unique` does.
fn split_ext(name: &str) -> (&str, &str) {
    let lower = name.to_ascii_lowercase();
    for two in [".tar.gz", ".tar.xz", ".tar.bz2", ".tar.zst"] {
        if lower.ends_with(two) && name.len() > two.len() {
            return name.split_at(name.len() - two.len());
        }
    }
    match name.rfind('.') {
        Some(i) if i > 0 => name.split_at(i),
        _ => (name, ""),
    }
}

/// The first of "name", "name (2)", "name (3)"... not taken in `dir`.
pub fn unique(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() && !dir.join(format!("{name}.part")).exists() {
        return first;
    }
    let (stem, ext) = split_ext(name);
    (2..)
        .map(|n| dir.join(format!("{stem} ({n}){ext}")))
        .find(|p| !p.exists() && !p.with_file_name(format!("{}.part", p.file_name().unwrap().to_string_lossy())).exists())
        .unwrap()
}

pub fn text_packet(text: &str) -> Packet {
    Packet::new(REQUEST).with("text", text)
}

pub fn url_packet(url: &str) -> Packet {
    Packet::new(REQUEST).with("url", url)
}

/// A file to send: its name, its size (-1 when not known) and its bytes.
pub struct Outgoing {
    pub name: String,
    pub size: i64,
    pub last_modified_ms: Option<i64>,
    pub data: Box<dyn Read + Send>,
    pub open: bool,
}

/// The packet announcing `file` and the listener its payload is served from.
pub fn file_packet(file: &Outgoing, bind: IpAddr) -> io::Result<(Packet, PayloadOffer)> {
    let offer = PayloadOffer::open(bind)?;
    let mut np = Packet::new(REQUEST)
        .with("filename", file.name.clone())
        .with("numberOfFiles", 1)
        .with("totalPayloadSize", file.size.max(0))
        .with("open", file.open);
    if let Some(ms) = file.last_modified_ms {
        np.set("lastModified", ms);
    }
    offer.attach(&mut np, file.size);
    Ok((np, offer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(sanitise("../../etc/passwd"), "passwd");
        assert_eq!(sanitise("C:\\Users\\x\\save.srm"), "save.srm");
        assert_eq!(sanitise("a:b*c?.txt"), "a_b_c_.txt");
        assert_eq!(sanitise("...hidden"), "hidden");
        assert_eq!(sanitise("name. . "), "name");
        assert_eq!(sanitise(""), "file");
        assert_eq!(sanitise("..."), "file");
        let long = format!("{}.zip", "é".repeat(100));
        let s = sanitise(&long);
        assert!(s.len() <= 120 && s.ends_with(".zip"), "{s}");
    }

    #[test]
    fn unique_names() {
        let dir = std::env::temp_dir().join(format!("kdc-share-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(unique(&dir, "x.tar.gz"), dir.join("x.tar.gz"));
        std::fs::write(dir.join("x.tar.gz"), b"").unwrap();
        assert_eq!(unique(&dir, "x.tar.gz"), dir.join("x (2).tar.gz"));
        std::fs::write(dir.join("x (2).tar.gz"), b"").unwrap();
        assert_eq!(unique(&dir, "x.tar.gz"), dir.join("x (3).tar.gz"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
