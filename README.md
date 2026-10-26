# GoGo Gadget

A free and open-source APK installer for Android. It installs directly on the device through local Wireless Debugging: no PC, no mandatory Shizuku, no dependency on Google.

> Status: **pre-alpha**. Initial project structure only. See the [v1.0 specification](docs/SPEC-v1.0.md).

## Features (v1.0)

- Standalone local ADB (Wireless Debugging)
- Zero-Trust: no permissions granted by default
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

## Support

The code is 100% free. Support options (to be decided): GitHub Sponsors, Buy Me a Coffee, or a paid convenience build on the Play Store.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
