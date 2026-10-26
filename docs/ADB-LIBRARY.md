# ADB library, identity and permissions

## Library

GoGo Gadget talks to Wireless Debugging with **libadb-android** by Muntashir Al-Islam
(<https://github.com/MuntashirAkon/libadb-android>), version **3.1.1**. It implements the ADB protocol, the
Android 11 pairing protocol (TLS + SPAKE2) and the TLS connect, with no PC and no root.

| Component | Version | Licence | Use |
|-----------|---------|---------|-----|
| libadb-android | 3.1.1 | GPL-3.0-or-later **or** Apache-2.0 (per-file `SPDX-License-Identifier`; the README says "use whatever licence you need") | ADB client |
| spake2-android (spake2-java) | 2.2.1 | LGPL-3.0 | SPAKE2 for pairing (ships a small native `libspake2.so`) |
| BouncyCastle `bcprov-jdk15to18` | 1.81 | Bouncy Castle licence (MIT-style) | SPAKE2 helpers, AES-GCM, and the self-signed certificate |

All three are compatible with this project's GPL-3.0-or-later: libadb-android is used under its GPL-3.0-or-later
option, LGPL-3.0 code may be combined into a GPL-3.0 work, and the BouncyCastle licence is permissive. The
JitPack POM lists libadb-android's licence as "Other"; the dual licence above comes from the repository itself
(`README.md`, `LICENSES/`, SPDX headers).

The upstream project states that the library has never been security-audited. This is also true of spake2-java.
Both are small and open; review them before a public release.

### Fetching

Gradle fetches the library from JitPack (`https://jitpack.io`). `settings.gradle` restricts that repository to
`com.github.MuntashirAkon*`, so nothing else can be resolved from it. Verified on the build VPS: the dependency
resolves and the project compiles. SHA-256 of the artifacts that were resolved:

```
e6fcb495a20a507ca4a125afc9c554e838a84b3a15fbcc29f7deafd0f88bbb58  libadb-android-3.1.1.aar
8798fb6c04b5d53a6307ed9481e9afe563227abd4e8b9e917c8514fa850071bb  spake2-android-2.2.1.aar
0ef9c4d9536719aaa1c92a7c694d87981fa9d4d64dd9479cc322a08aebbc651e  bcprov-jdk15to18-1.81.jar
```

Upstream's custom Conscrypt is **not** used: with minSdk 30 the platform's TLS 1.3 is enough, which also avoids a
large native dependency.

## Identity (key pair)

* Generated once on first use: RSA-2048 plus a self-signed certificate (`AdbKeys.kt`).
* The library signs the ADB auth token with raw RSA, which Android Keystore RSA keys do not support, so the
  private key cannot live inside the Keystore. Instead it is stored **encrypted with an AES-256-GCM key that is
  held in the Android Keystore** (`gogo_adb_wrap`, never exportable) in the app's private storage
  (`adb_key.enc`; the certificate is public and kept in `adb_cert.der`). `allowBackup` is off.
* If the Keystore key disappears, a new identity is generated and devices must be paired again.
* Pairing codes and tokens are never logged or stored. The private key is never logged; it is stored only
  encrypted (see above).

## Permissions

| Permission | Why | Added |
|------------|-----|-------|
| `android.permission.INTERNET` | Android requires it for any socket, including the loopback socket to this phone's own `adbd` and sockets to a device on the local network. The app opens sockets only to the address the user picks, and manual entry only accepts private/link-local addresses. It has no other network code. | Phase 2 |
| `android.permission.CHANGE_WIFI_MULTICAST_STATE` | Network devices are found by mDNS (`NsdManager`). Android drops multicast packets unless the app holds a `MulticastLock`, which needs this normal (install-time) permission. The lock is held only while the device list or a pairing is open. | 0.4.1 |
| `android.permission.FOREGROUND_SERVICE` | "This device" pairing runs a short foreground service (`foregroundServiceType="shortService"`, not exported) that looks for this phone's own pairing dialog and keeps the "Enter pairing code" notification alive while the dialog is on screen. `shortService` needs no further permission; the system stops it after about three minutes. | 0.4.1 |
| `android.permission.POST_NOTIFICATIONS` | Android 13+: shows that notification (searching / enter code / result). Asked at runtime, once, when pairing this phone starts. Optional: the in-app code field and the Paste button always work. The notification never contains the code. | 0.4.1 |
| `app.gogogadget.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` | Added by AndroidX; protects internal receivers. Not requested from the user. | Phase 1 |

Not needed and **not** requested: `NEARBY_WIFI_DEVICES` (only for Wi-Fi Aware/P2P, not NSD service discovery),
`ACCESS_WIFI_STATE` / `ACCESS_NETWORK_STATE`. If a device or a later Android version (for example a "local
network" permission) requires one of them for mDNS, it will show up on-device as "no devices found" and the
permission should be added then; this is **untested** (see `SPIKE-phase2.md`).

This is a deliberate change from "0 permissions": `INTERNET` is unavoidable for any ADB client; the other three exist only for discovery and the pairing notification.

## Two pairing methods (0.4.1)

* **This device**: the Shizuku design. A short foreground service searches `_adb-tls-pairing._tcp` and accepts a service only if its host is one of this phone's own interface addresses *and* its port is bound locally (binding 127.0.0.1:port fails). The notification's reply `PendingIntent` carries the port, so the service may be killed before the code is typed. The code is paired to `127.0.0.1:<port>`, then the app connects (port by mDNS). Before that, if a connect port is already visible, the app tries to connect directly (see `SPIKE-phase2.md`).
* **Other devices**: the ClaimTV design. The app connects straight away (mDNS connect port, else 5555); the other device shows its own "Allow debugging?" prompt and the user taps Allow (ideally Always allow) there. A 45 s watchdog gives up (adbd waits for the tap with no timeout). Only if that device answers "pairing required" does the app ask for its pairing code, typed in the app (no notification).

## Install path

The chosen file is streamed over the ADB connection, so nothing is copied to disk and no path has to be readable
on the target device (this is what makes installing on a network device work). The app opens `exec:cmd package
install -S <size> -r -d --bypass-low-target-sdk-block` (retried without the bypass flag if the device rejects
it), writes exactly `<size>` bytes read from the picked file, and parses the `Success`/`Failure` line. `exec:`
is used rather than `shell:` because it has no pty and keeps stdin binary-safe. Calls to the library are
serialised with a mutex, and only one install runs at a time. **Untested on a device.**
