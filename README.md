# GoGo Gadget

A free and open-source APK installer for Android. It installs directly on the device through local Wireless Debugging: no PC, no mandatory Shizuku, no dependency on Google.

## How it works

1. **Pick a file**: Select standard APK files, split APK packages (`APKS`, `APKM`, `XAPK`), or ZIP archives. Unpacking and split validation happen entirely in memory.
2. **Pre-install security scan**:
   * **Local Deep Scan**: Parses DEX bytecode header offsets and string tables across `classes.dex`, `classes2.dex`, etc. Detects dynamic class loader droppers (`DexClassLoader`, `InMemoryDexClassLoader`), disguised `.dex`/`.apk` binaries in assets, aggressive adware SDKs, and abusive permission combinations.
   * **Cloud reputation**: Queries MetaDefender / VirusTotal hash lookups for threat intelligence without requiring external libraries.
   * **3-tier security architecture**: Green (clean / trusted update), Yellow (caution / interactive override prompt), and Red (malware / signature mismatch hard block).
3. **Connect to target device**: Connects to the local device (via local wireless debugging pairing code entered through an Android notification) or any Android TV / device on the local Wi-Fi network over ADB (port 5555 / mDNS discovery).
4. **Safe install & Auto-backup**:
   * Zero-Trust installation via direct ADB streaming sessions.
   * When updating an existing app, GoGo Gadget automatically backs up the currently installed APK(s) to app-private storage before applying the update.
   * Downgrade and restore anytime with 1-tap **[ Revert ]** from the dedicated Backups screen.
5. **Clean up**: Keep or immediately delete the source installer package with one tap after installation.

## Key Features

- **Standalone local ADB**: Uses native Wireless Debugging without needing root, Shizuku, or a computer.
- **Zero-Trust architecture**: Only requests minimal required permissions (`INTERNET`, `CHANGE_WIFI_MULTICAST_STATE`, `FOREGROUND_SERVICE`, `POST_NOTIFICATIONS`). Never reads files outside the chosen package.
- **Split package support**: Full support for `.apk`, `.xapk`, `.apkm`, `.apks`, and ZIP splits.
- **Target selection**: Install locally or remotely to Android TVs and other Android devices on the network.
- **App revert & history**: 1-previous-version backup protection with single-tap rollback.
- **100% Google-independent**: No Play Services or Play Store requirements.

## Build

Requires **JDK 17** and the Android SDK:

```bash
export ANDROID_HOME=/path/to/android-sdk
./gradlew assembleDebug testDebugUnitTest
```

## ADB library

ADB pairing and connection use [libadb-android](https://github.com/MuntashirAkon/libadb-android) (GPL-3.0-or-later or Apache-2.0; used here under GPL-3.0-or-later), which depends on `spake2-java` (LGPL-3.0) and BouncyCastle.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
