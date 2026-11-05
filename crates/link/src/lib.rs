//! KDE Connect over the network: the device certificate, UDP discovery, the TCP+TLS link and payload
//! streams. Ported from kdeconnect-android (`backends/lan/`, `helpers/security/SslHelper.kt`) and checked
//! against kdeconnect-kde (`core/backends/lan/`, `core/sslhelper.cpp`). See the README for the protocol
//! as built, and NOTICE.md.
//!
//! Blocking std I/O and threads: no async runtime, so the library links into droidtop's JNI module and
//! Pythia's Python module as it is.

pub mod cert;
pub mod discovery;
pub mod link;
pub mod payload;
pub mod provider;
pub mod tls;

pub use cert::DeviceCert;
pub use discovery::AddressSource;
pub use link::{verification_key, Link, LinkError, Trust};
pub use payload::{PayloadOffer, PayloadReader};
pub use provider::{Config, Event, LinkProvider};
