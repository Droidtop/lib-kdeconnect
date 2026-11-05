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
