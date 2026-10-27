# GoGo Gadget

A free and open-source APK installer for Android. It installs directly on the device through local Wireless Debugging: no PC, no mandatory Shizuku, no dependency on Google.

> Status: **pre-alpha**. Initial project structure only. See the [v1.0 specification](docs/SPEC-v1.0.md).

## Features (v1.0)

- Standalone local ADB (Wireless Debugging)
- Zero-Trust: only the permissions it needs, each documented in [docs/ADB-LIBRARY.md](docs/ADB-LIBRARY.md) (INTERNET, CHANGE_WIFI_MULTICAST_STATE for mDNS, FOREGROUND_SERVICE and POST_NOTIFICATIONS for the pairing notification)
- Two ways to connect: this phone (pair once, type the code in a notification) and other devices on the Wi-Fi (connect and tap Allow on that device)
- 3-Color Security Tier Architecture (Green, Yellow, Red):
  * **Green (Clean)**: Proven clean by VirusTotal and local Deep Scan, or trusted update signed with the same certificate. Installs automatically and silently.
  * **Yellow (Caution / Mod Risk / Interactive Override)**: Suspends the install flow on mod or unverified conditions (`DropperDetected` dynamic class loaders, `DebugOrTestCertificate`, `NotKnownToVirusTotal`, or missing VirusTotal API key). Displays an interactive Caution Prompt on the Home screen with risk explanations and two choices: `[ Cancel (Recommended) ]` or `[ Install Anyway (I Trust This Source) ]`.
  * **Red (Critical / Hard Block)**: Hard block fail-closed with no override capability (`MalwareDetected`, aggressive adware SDKs, signature mismatch impersonating an installed app, abusive installer permissions, unsigned packages, package mismatch).
- Deep Scan (Local Static Analysis):
  * Inspects DEX bytecode string tables (`classes.dex`, `classes2.dex`, etc.) directly from header offsets.
  * Scans assets and resources for hidden droppers (`DexClassLoader`, `InMemoryDexClassLoader`, disguised `.dex`/`.apk` binaries, or executable ZIPs). Animation and data files like `.lottie` are never flagged as hidden payloads.
  * Detects aggressive adware SDKs (`com.airpush`, `com.leadbolt`, `com.kuguo`, `com.startapp.android.publish`, `com.secneo`, `com.adwhirl`, etc.) and abusive installer permissions (`REQUEST_INSTALL_PACKAGES` combined with overlay or SMS access). Configurable in Security settings (default ON).
- VirusTotal Proof:
  * APK files are looked up by SHA-256. A VirusTotal API key is required, except for updates of an installed app signed with the same certificate. Unknown files can be uploaded after user confirmation.
  * The Shield only reports what VirusTotal says about the file hash: "no engine flags it" is not a guarantee. The Shield never verifies a signature cryptographically itself; the Android installer does that when the app is installed.
- Phase 5: Auto-Backup & 1-Tap Reversion:
  * When updating an installed app, GoGo automatically queries ADB `pm path <pkg>` and backs up the existing APK(s) to private storage before installing the update. Keeps 1 previous version per package.
  * Dedicated Backups screen lists saved backups (App Name, Package Name, Version, Date saved, Size) with 1-tap **[ Revert ]** (downgrade restoration via `pm install -r -d` / session install) and **[ Delete ]**.
- No Play Store link, ever: fully independent of Google
- Delete or keep the APK with one tap
- APK, XAPK, APKM, APKS, ZIP splits

## Build

Requires **JDK 17**. Point `JAVA_HOME` at a JDK 17 before running Gradle:

```
JAVA_HOME=/path/to/jdk-17 ./gradlew assembleDebug testDebugUnitTest
```

## ADB library

ADB pairing and connection use [libadb-android](https://github.com/MuntashirAkon/libadb-android)
(GPL-3.0-or-later or Apache-2.0; used here under GPL-3.0-or-later), which depends on spake2-java (LGPL-3.0) and
BouncyCastle. Details, checksums and the permission list are in [docs/ADB-LIBRARY.md](docs/ADB-LIBRARY.md); what
could not be verified without a device is in [docs/SPIKE-phase2.md](docs/SPIKE-phase2.md).

## Support

The code is 100% free. Support options (to be decided): GitHub Sponsors, Buy Me a Coffee, or a paid convenience build on the Play Store.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
