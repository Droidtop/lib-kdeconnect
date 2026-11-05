# Changelog

All notable changes to lib-kdeconnect. Versions follow [Semantic Versioning](https://semver.org/)
(0.x releases may change anything).

## [0.1.0]

### Added
- `kdeconnect-proto`: KDE Connect protocol version 8 without I/O. Packets (one JSON object a line, read as
  leniently as the official apps), the identity, announcement and connection packets, device id and name
  rules, the pairing state machine and the verification key both devices show (Droidtop/tracker#645).
- `kdeconnect-link`: the device certificate, UDP discovery, the TCP+TLS link with the official apps' role
  swap and identity re-exchange, certificate pinning, payload streams and the LAN link provider. The
  `peer` example is a command-line device for checking against the official apps.
- `kdeconnect-service`: the running device both programs embed. Identity and paired devices on disk,
  remembered addresses, pairing, the ping plugin, and JSON-serialisable views and events.
- Share: texts, links and files each way (`kdeconnect.share.request`), files stored whole into the program's
  folder under a cleaned, unique name, and sent from a path or a handed-over file descriptor.
- Clipboard: text each way (`kdeconnect.clipboard`), and on connecting with the time it changed
  (`.connect`, taken only when newer); a clip that just arrived is not sent back.
- Remote input: pointer moves, scrolls, clicks, typed text and kde's 32 special keys with modifiers
  (`kdeconnect.mousepad.request`), the echo a sender asks for, and the keyboard state, both as the
  controlled device and as the controller.
