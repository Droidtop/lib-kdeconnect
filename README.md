# lib-kdeconnect

KDE Connect, implemented as a library: droidtop and Pythia speak the real protocol, so they work with the
official KDE Connect apps (Android, Plasma, Windows, macOS) and with each other, as both the device that is
controlled and the one that controls. One of the shared library families of Droidtop/tracker#867: it
belongs to no program, and each program pins a tagged release. The plan and its slices are on
Droidtop/tracker#645.

Owner, 2026-11-05: "lib-kdeconnect implements explicitly kde-connect as a programmatic module." It knows
nothing about Android, Python or any VPN (#867 D3). Each program implements the traits.

| Crate | Where | Holds |
|---|---|---|
| `kdeconnect-proto` | [`crates/proto`](crates/proto) | packets, identity, device id and name rules, pairing and the verification key. No I/O. |
| `kdeconnect-link` | [`crates/link`](crates/link) | the device certificate, UDP discovery, the TCP+TLS link, payload streams, the LAN link provider |
| `kdeconnect-service` | [`crates/service`](crates/service) | the running device both programs embed: identity and paired devices on disk, one thread per link, pairing, the plugins, and a queue of events |

The plan on #645 named a third crate `kdeconnect-plugins`. The plugins live in `kdeconnect-service` (`src/plugins/`)
instead, because each one is a few packet rules that need the service's links and nothing else.

## The service

`Service::start(Settings)` takes the name, the device type, a folder for its state, the link settings and
which plugins are on. In that folder it keeps two JSON files:
- `kdeconnect-identity.json`: the device id, certificate and key, made on first start. A certificate that no
  longer names the device id is replaced, and every pairing is forgotten with it, as android does.
- `kdeconnect-trusted.json`: the paired devices, each with its pinned certificate and the last address it was
  reached at. Those addresses are announced to at start, so paired devices reconnect off the broadcast.

The program calls `devices`, `pair`, `accept`, `refuse`, `unpair`, `ping`, `send`, `announce`, and
`set_extra_addresses` (devices added by address and a VPN plugin's peers). It reads `next_event`. Every
view and event serialises to JSON (`{"event": "pair_request", "id", "name", "key"}`, `{"event": "plugin",
"id", "plugin": {"plugin": "ping", "message"}}`, ...), so droidtop's JNI layer and Pythia's Python layer
pass them through. Packets other than pairing from a device that is not paired are dropped, as both apps do.

## Plugins

| Plugin | Packets | State |
|---|---|---|
| ping | `kdeconnect.ping` both ways | built |
| share | `kdeconnect.share.request`, `.update`: text, links and files each way | built |
| clipboard | `kdeconnect.clipboard`, `.connect`: each way, and on connecting | built |
| remote input | `kdeconnect.mousepad.request`, `.keyboardstate`, `.echo`: pointer and keyboard, controlled and controlling | built |
| battery | `kdeconnect.battery`, `.request`: this device's on connecting and on change; the other's as an event | built |
| find my device | `kdeconnect.findmyphone.request`: ring each way | built |
| notifications | `kdeconnect.notification` received (post, update, cancel); `.request` to dismiss and to ask for all | built |

**Share.** A received text or link is an event (`share_text`, `share_url`). A received file is fetched at once on
its own thread (the sender waits only 10 s) into the `receive_dir` the program named at start, as `<name>.part`
until all of it arrived, then renamed; a file that does not arrive whole is deleted, and without a folder files are
refused. The name is cleaned as droidtop cleans a received file's (only the last path part, no control characters
or `: * ? " < > |`, no leading dots, at most 120 bytes, never over another file: "Name (2)"). A file is sent from a
path, or on Unix from a file descriptor the program hands over (droidtop passes a document's), so nothing is copied.

A plugin that is off is not in the identity's capabilities and its packets are dropped. What a plugin needs
from the platform is the program's: the service reports what arrived as an event.

Used by: droidtop-agent, and through it droidtop's `libdroidtop_agent.so` and Pythia (from slice 1's wiring).

Licence: GPL-3.0-only. It is a port of kdeconnect-android's protocol core, checked against
kdeconnect-kde; see `NOTICE.md`.

## The protocol as built

Protocol version 8 only. Both official apps refuse anything lower (kde `lanlinkprovider.cpp`, "using too old
protocol version"; Ubuntu 24.04's kdeconnect 23.08 still speaks 7 and is refused here the same way).

**Packets.** One JSON object, then `\n`: `{"id": <ms>, "type": "...", "body": {...}}`, plus `payloadSize` and
`payloadTransferInfo` when a payload follows. On read, numbers may come as strings and the reverse (android
sends `targetProtocolVersion` as a string; kde 23.08 sent `id` as one). An identity is read in at most
8 KiB; any other packet in at most 32 MiB.

**Identity.** `deviceId` (32-38 of `[A-Za-z0-9_-]`; new ones are a bare UUID), `deviceName` (with
`"',;:.!?()[]<>` dropped, at most 32 characters, not empty), `deviceType` (`desktop`, `laptop`, `phone`,
`tablet`, `tv`), `protocolVersion`, `incomingCapabilities`, `outgoingCapabilities`.

**Discovery.** By mDNS (`_kdeconnect._udp`, published as the device id on its TCP port with TXT `id`, `name`,
`type`, `protocol`, through the `mdns-sd` crate; on Android the program holds a Wi-Fi multicast lock), and by UDP.
The full identity plus `tcpPort` (the device's listener, from 1716-1764) goes by UDP to
255.255.255.255:1716 and to each extra address (devices added by address, and a VPN plugin's peers, through
the `AddressSource` trait). kde sends a smaller UDP packet; the full one is a superset that both apps accept.
An announcement is ignored when it is this device's own, older than version 8, or names a port outside
1716-1764. Only local addresses are talked to (loopback, private, link-local, 100.64.0.0/10 and fc00::/7, as
android's `isPrivateAddress`), and any address the `AddressSource` gives. A second packet from one address
or for one device within 500 ms is dropped, and at most 42 handshakes run at once.

**Connection.**
1. The device that heard the announcement connects to its `tcpPort` and sends its identity in plain text,
   with `targetDeviceId` and `targetProtocolVersion`. The other refuses a connection for another device or
   another version.
2. **The TCP client is the TLS server**; the TCP server is the TLS client.
3. Both send their identity again over TLS. Only that one is believed; its device id and version must equal
   the plain one's, and the certificate's CN must equal the device id.

**TLS.** TLS 1.2 and 1.3 (android offers 1.2 only). Both sides present a certificate; the TLS server
requires the client's. A device that is not paired may present any certificate; once paired, the program
pins it and only that exact certificate is accepted. Handshake signatures are always verified.

**The certificate.** Self-signed, EC P-256, subject and issuer `CN=<device id>, OU=KDE Connect, O=KDE`, valid
from a year ago for ten years, and **no subjectAltName** (kde checks the peer name against the CN, which a SAN
would replace). The program keeps it and its key with the device id.

**Pairing.** `kdeconnect.pair {"pair": true, "timestamp": <unix seconds>}` asks, `{"pair": true}` accepts,
`{"pair": false}` refuses, withdraws or unpairs. A request from a clock more than 30 minutes off is refused.
The asker gives up after 30 s, the asked after 25 s. Both screens show the verification key: SHA-256 of the
two certificates' SubjectPublicKeyInfo (the larger first) and the timestamp in decimal, its first 8 hex digits
in upper case. android's test vectors are in `crates/link/tests/two_devices.rs`. The official apps have no QR
pairing; a device discovery does not find is added by its address.

**Payloads.** The sender listens on a port from 1739-1764 and puts `payloadSize` (-1 when unknown) and
`payloadTransferInfo: {"port": n}` on the packet. The receiver connects to it at the sender's address; here
the TCP client is the TLS client, and both require the other's pinned certificate. The sender waits 10 s for
the connection. Exactly `payloadSize` bytes follow; fewer is an error.

## Checking against other implementations

`scripts/interop-kcd.sh <kcd binary>` runs the `peer` example against kcd (https://github.com/bethropolis/kcd, an
independent protocol 8 implementation in Go, MIT), pinned by commit in CI's `interop-kcd` job. Both must link,
pair with the same verification key, ping each way, and pass a file each way intact. First run 2026-11-05
against kcd `9cf876b`: all of it passed.

## Checking against the official apps

`cargo run -p kdeconnect-link --example peer -- --announce <phone IP> --accept --ping hi --receive-dir /tmp/in`
is a device on the command line. It shows up in the KDE Connect app on that network, prints the verification
key, accepts pairing, pings, and stores files shared to it.

## Build and test

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI (`.github/workflows/ci.yml`) runs those on Linux, Windows and macOS, and builds the crates for droidtop's
two Android ABIs. Work lands on `main` from `ci/*` branches once CI is green.

## Versions

A release is a tag `vX.Y.Z`, created by CI on a green `main` whose root `Cargo.toml` names a version not yet
tagged. Programs depend on a tag:

```toml
kdeconnect-link = { git = "https://github.com/Droidtop/lib-kdeconnect", tag = "v0.1.0" }
```
