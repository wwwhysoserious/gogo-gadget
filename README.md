# GoGo Gadget

A free and open-source APK installer for Android. It installs directly on the device through local Wireless Debugging: no PC, no mandatory Shizuku, no dependency on Google.

> Status: **pre-alpha**. Initial project structure only. See the [v1.0 specification](docs/SPEC-v1.0.md).

## Features (v1.0)

- Standalone local ADB (Wireless Debugging)
- Zero-Trust: only the permissions it needs, each documented in [docs/ADB-LIBRARY.md](docs/ADB-LIBRARY.md) (INTERNET, CHANGE_WIFI_MULTICAST_STATE for mDNS, FOREGROUND_SERVICE and POST_NOTIFICATIONS for the pairing notification)
- Two ways to connect: this phone (pair once, type the code in a notification) and other devices on the Wi-Fi (connect and tap Allow on that device)
- SHA-256 antivirus shield (VirusTotal/Koodous) with optional Deep Scan
- Automatic backup and rollback before updating
- Detached from the Play Store by default
- Delete or keep the APK with one tap
- APK, XAPK, APKM, APKS

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
