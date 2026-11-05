# Notice

lib-kdeconnect is GPL-3.0-only (see `LICENSE`).

It is a Rust port of the KDE Connect protocol core. The protocol rules, constants and checks come from:

- **kdeconnect-android** (https://invent.kde.org/network/kdeconnect-android, read at `60524fc`, 2026-11-04):
  `NetworkPacket.kt`, `DeviceInfo.kt`, `PairingHandler.kt`, `helpers/DeviceHelper.kt`,
  `helpers/NetworkHelper.kt`, `helpers/security/SslHelper.kt`, `backends/lan/LanLinkProvider.kt`,
  `backends/lan/LanLink.kt`, and the test vectors in `src/test/.../PairingHandlerTest.kt` and
  `NetworkPacketTest.kt`.
  SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL.
  Copyright the KDE Connect authors (Albert Vaca Cintora, Vineet Garg and others).
- **kdeconnect-kde** (https://invent.kde.org/network/kdeconnect-kde, read at `aee1439`, 2026-11-04):
  `core/networkpacket.cpp`, `core/deviceinfo.h`, `core/sslhelper.cpp`,
  `core/backends/lan/lanlinkprovider.cpp`.
  SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL.
  Copyright the KDE Connect authors.

Both are offered under GPL-3.0-only among their options; this port takes that option.
"KDE" and "KDE Connect" are names of the KDE community; this library is not a KDE project.
